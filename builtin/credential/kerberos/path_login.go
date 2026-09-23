// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"
	goidentity "github.com/go-krb5/x/identity"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-sockaddr"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/cidrutil"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
	"github.com/openbao/openbao/sdk/v2/helper/policyutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKerberos,
		},
		Fields: map[string]*framework.FieldSchema{
			"authorization": {
				Type:        framework.TypeString,
				Description: `SPNEGO Authorization header. Required unless delegation_token is set.`,
			},
			"role": {
				Type: framework.TypeString,
				Description: `Name of the role to log in with. Optional; without it
every role is matched and exactly one must match. Rejected while
"config/ldap" is set and with delegation_token, whose role was fixed
at issuance.`,
			},
			"delegation_token": {
				Type: framework.TypeString,
				Description: `A delegation token issued by "delegation/token", in its URL
string form. Logs in as the token's owner without SPNEGO.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathLoginGet,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "login2",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginUpdate,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "login",
				},
			},
		},
	}
}

func parseKeytab(b64EncodedKt string) (*keytab.Keytab, error) {
	decodedKt, err := base64.StdEncoding.DecodeString(b64EncodedKt)
	if err != nil {
		return nil, err
	}
	parsedKt := new(keytab.Keytab)
	if err := parsedKt.Unmarshal(decodedKt); err != nil {
		return nil, err
	}
	return parsedKt, nil
}

func (b *backend) pathLoginGet(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Headers: map[string][]string{
			"www-authenticate": {"Negotiate"},
		},
	}, logical.CodedError(401, "authentication required")
}

func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	kerbCfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get kerberos config: %w", err)
	}
	if kerbCfg == nil {
		return nil, errors.New("backend kerberos not configured")
	}

	ldapCfg, err := b.ConfigLdap(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("unable to get ldap config: %w", err)
	}

	roleName := d.Get("role").(string)
	if ldapCfg != nil && roleName != "" {
		return logical.ErrorResponse("role is not applicable while config/ldap is set"), logical.ErrInvalidRequest
	}
	if roleName != "" && !roleNameRegex.MatchString(roleName) {
		return logical.ErrorResponse("invalid role name %q", roleName), logical.ErrInvalidRequest
	}

	if ldapCfg != nil {
		if err := checkBoundCIDRs(b, req, ldapCfg.TokenBoundCIDRs); err != nil {
			return nil, err
		}
	}

	if delegationToken := d.Get("delegation_token").(string); delegationToken != "" {
		if roleName != "" {
			return logical.ErrorResponse("role is not applicable with delegation_token"), logical.ErrInvalidRequest
		}
		if isNegotiate(authorizationValue(req, d)) {
			return logical.ErrorResponse("a SPNEGO token and delegation_token cannot be combined"), logical.ErrInvalidRequest
		}
		return b.loginWithDelegationToken(ctx, req, delegationToken)
	}

	identity, resp, err := b.negotiate(ctx, req, d, kerbCfg)
	if err != nil || resp != nil {
		return resp, err
	}

	if ldapCfg == nil {
		return b.loginWithRoles(ctx, req, identity, roleName)
	}

	// Verify that the realm on the LDAP config (if set) is the same as the identity's
	// realm. The UPNDomain denotes the realm on the LDAP config, and the identity
	// domain likewise identifies the realm. This is a case sensitive check.
	// This covers an edge case where, potentially, there has been drift between the LDAP
	// config's realm and the Kerberos realm. In such a case, it prevents a user from
	// passing Kerberos authentication, and then extracting group membership, and
	// therefore policies, from a separate directory.
	if ldapCfg.UPNDomain != "" && identity.Domain() != ldapCfg.UPNDomain {
		resp := &logical.Response{
			Warnings: []string{fmt.Sprintf("identity domain of %q doesn't match LDAP upndomain of %q", identity.Domain(), ldapCfg.UPNDomain)},
		}
		return logical.RespondWithStatusCode(resp, req, 400)
	}

	return b.loginWithLdap(ctx, req, kerbCfg, ldapCfg, identity)
}

// negotiate verifies the SPNEGO token from the Authorization header or the
// authorization field. Without a Negotiate token it answers with the 401
// challenge; on failure the error carries the reason with the status code and
// the response and error are to be returned as is.
func (b *backend) negotiate(ctx context.Context, req *logical.Request, d *framework.FieldData, kerbCfg *kerberosConfig) (goidentity.Identity, *logical.Response, error) {
	authorizationString := authorizationValue(req, d)
	if !isNegotiate(authorizationString) {
		resp, err := b.pathLoginGet(ctx, req, d)
		return nil, resp, err
	}

	kt, err := parseKeytab(kerbCfg.Keytab)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse keytab: %w", err)
	}

	if kerbCfg.RemoveInstanceName {
		removeInstanceNameFromKeytab(kt)
	}

	identity, code, message := b.spnegoAuthenticate(req, kerbCfg, kt, authorizationString)
	if identity == nil {
		resp := &logical.Response{}
		if code == http.StatusUnauthorized {
			resp.Headers = map[string][]string{"www-authenticate": {"Negotiate"}}
		}
		return nil, resp, logical.CodedError(code, message)
	}
	return identity, nil, nil
}

// authorizationValue is the Authorization header, or the authorization
// field when the header is absent.
func authorizationValue(req *logical.Request, d *framework.FieldData) string {
	if headers := req.Headers["Authorization"]; len(headers) > 0 {
		return headers[0]
	}
	return d.Get("authorization").(string)
}

func isNegotiate(authorization string) bool {
	s := strings.SplitN(authorization, " ", 2)
	return len(s) == 2 && s[0] == "Negotiate"
}

// checkBoundCIDRs denies the request when cidrs is set and the caller's
// address is outside all of them.
func checkBoundCIDRs(b *backend, req *logical.Request, cidrs []*sockaddr.SockAddrMarshaler) error {
	if len(cidrs) == 0 {
		return nil
	}
	if req.Connection == nil {
		b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
		return logical.ErrPermissionDenied
	}
	if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, cidrs) {
		return logical.ErrPermissionDenied
	}
	return nil
}

// spnegoAuthenticate verifies the SPNEGO token in authorization against kt.
// A nil identity means failure; code and message then describe it.
func (b *backend) spnegoAuthenticate(req *logical.Request, kerbCfg *kerberosConfig, kt *keytab.Keytab, authorization string) (goidentity.Identity, int, string) {
	l := b.Logger().StandardLogger(&hclog.StandardLoggerOptions{
		InferLevels: true,
	})

	// The PAC is not consumed here: identity comes from the ticket's cname,
	// and a PAC the library cannot verify must not fail the login.
	settings := []func(*service.Settings){
		service.Logger(l),
		service.DecodePAC(false),
	}
	if kerbCfg.ServiceAccount != "" {
		settings = append(settings, service.KeytabPrincipal(kerbCfg.ServiceAccount))
	}
	// The client address is compared with the ticket's addresses when the
	// ticket carries any.
	if req.Connection != nil {
		if ip := net.ParseIP(req.Connection.RemoteAddr); ip != nil {
			settings = append(settings, service.ClientAddress(types.HostAddressFromNetIP(ip)))
		}
	}

	token, err := parseSPNEGOToken(authorization)
	if err != nil {
		return nil, http.StatusUnauthorized, err.Error()
	}

	authed, ctx, status := spnego.SPNEGOService(kt, settings...).AcceptSecContext(token)
	if status.Code == gssapi.StatusContinueNeeded {
		return nil, http.StatusUnauthorized, "multi-leg SPNEGO negotiation is not supported; Kerberos must be the first mechanism offered"
	}
	if !authed || status.Code != gssapi.StatusComplete {
		message := status.Message
		if message == "" {
			message = "SPNEGO authentication failed"
		}
		return nil, http.StatusUnauthorized, message
	}
	creds, ok := ctx.Value(spnego.CTXKey).(*credentials.Credentials)
	if !ok {
		return nil, http.StatusInternalServerError, "identity credentials are not included"
	}
	b.Logger().Debug("spnego identity", "user", creds.UserName(), "domain", creds.Domain())
	return creds, http.StatusOK, ""
}

// parseSPNEGOToken decodes a Negotiate header value. A raw KRB5 AP-REQ, which
// some clients send instead of a NegTokenInit, is wrapped as one.
func parseSPNEGOToken(authorization string) (*spnego.SPNEGOToken, error) {
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 {
		return nil, errors.New("authorization is not a Negotiate token")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("SPNEGO token is not valid base64: %w", err)
	}

	var token spnego.SPNEGOToken
	if err := token.Unmarshal(raw); err != nil {
		var krb5Token spnego.KRB5Token
		if krb5Token.Unmarshal(raw) != nil {
			return nil, fmt.Errorf("error unmarshalling SPNEGO token: %w", err)
		}
		token.Init = true
		token.NegTokenInit = spnego.NegTokenInit{
			MechTypes:      []asn1.ObjectIdentifier{krb5Token.OID},
			MechTokenBytes: raw,
		}
	}
	return &token, nil
}

func newAuth(user, domain, aliasName string) *logical.Auth {
	return &logical.Auth{
		InternalData: map[string]interface{}{},
		Metadata: map[string]string{
			"user":   user,
			"domain": domain,
		},
		DisplayName: aliasName,
		Alias:       &logical.Alias{Name: aliasName},
	}
}

// loginWithLdap resolves the identity's LDAP groups and applies the policies
// mapped to them under "groups/" together with the LDAP token parameters.
func (b *backend) loginWithLdap(ctx context.Context, req *logical.Request, kerbCfg *kerberosConfig, ldapCfg *ldapConfigEntry, identity goidentity.Identity) (*logical.Response, error) {
	username := identity.UserName()
	if kerbCfg.RemoveInstanceName {
		username, _, _ = strings.Cut(username, "/")
	}

	// Now that they've passed the Kerb authentication, begin checking if
	// they're a member of an LDAP group that should have additional policies
	// attached.
	ldapClient := ldaputil.Client{
		Logger: b.Logger(),
		LDAP:   ldaputil.NewLDAP(),
	}

	ldapConnection, err := ldapClient.DialLDAP(ldapCfg.ConfigEntry)
	if err != nil {
		return nil, fmt.Errorf("could not connect to LDAP: %w", err)
	}
	if ldapConnection == nil {
		return nil, errors.New("invalid connection returned from LDAP dial")
	}

	// Clean ldap connection
	defer ldapConnection.Close()

	if len(ldapCfg.BindPassword) > 0 {
		err = ldapConnection.Bind(ldapCfg.BindDN, ldapCfg.BindPassword)
	} else {
		err = ldapConnection.UnauthenticatedBind(ldapCfg.BindDN)
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP bind failed: %v", err)
	}

	userBindDN, err := ldapClient.GetUserBindDN(ldapCfg.ConfigEntry, ldapConnection, username)
	if err != nil {
		return nil, fmt.Errorf("unable to get user binddn: %w", err)
	}
	b.Logger().Debug("auth/ldap: User BindDN fetched", "username", identity.UserName(), "binddn", userBindDN)

	userDN, err := ldapClient.GetUserDN(ldapCfg.ConfigEntry, ldapConnection, userBindDN, username)
	if err != nil {
		return nil, fmt.Errorf("unable to get user dn: %w", err)
	}

	ldapGroups, err := ldapClient.GetLdapGroups(ldapCfg.ConfigEntry, ldapConnection, userDN, username)
	if err != nil {
		return nil, fmt.Errorf("unable to get ldap groups: %w", err)
	}
	b.Logger().Debug("auth/ldap: Groups fetched from server", "num_server_groups", len(ldapGroups), "server_groups", ldapGroups)

	var allGroups []string
	// Merge local and LDAP groups
	allGroups = append(allGroups, ldapGroups...)

	// Retrieve policies
	var policies []string
	for _, groupName := range allGroups {
		group, err := b.Group(ctx, req.Storage, groupName)
		if err != nil {
			b.Logger().Warn(fmt.Sprintf("unable to retrieve %s: %s", groupName, err.Error()))
			continue
		}
		if group == nil {
			b.Logger().Warn(fmt.Sprintf("unable to find %s, does not currently exist", groupName))
			continue
		}
		policies = append(policies, group.Policies...)
	}

	// Policies from each group may overlap
	policies = strutil.RemoveDuplicates(policies, true)

	auth := newAuth(identity.UserName(), identity.Domain(), identity.UserName())
	if err := ldapCfg.PopulateTokenAuth(auth, req); err != nil {
		return nil, fmt.Errorf("failed to populate auth information: %w", err)
	}

	// This is done after PopulateTokenAuth because it forces Renewable to be true.
	// Renewable was always false at the time of the code's introduction, and we would
	// like to keep it the same until we have a concrete reason to change its behavior.
	auth.LeaseOptions = logical.LeaseOptions{
		Renewable: false,
	}

	// Combine our policies with the ones parsed from PopulateTokenAuth.
	if len(policies) > 0 {
		auth.Policies = append(auth.Policies, policies...)
	}

	// Add the LDAP groups so the Identity system can use them
	if kerbCfg.AddGroupAliases {
		for _, groupName := range allGroups {
			if groupName == "" {
				continue
			}
			auth.GroupAliases = append(auth.GroupAliases, &logical.Alias{
				Name: groupName,
			})
		}
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

// selectRole returns the single role bound to principal, or the denial to
// return when none or several are.
func (b *backend) selectRole(ctx context.Context, s logical.Storage, principal, roleName string) (*kerberosRole, *logical.Response, error) {
	roles, err := b.matchingRoles(ctx, s, principal, roleName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to match roles: %w", err)
	}
	switch {
	case len(roles) == 0 && roleName != "":
		return nil, logical.ErrorResponse("role %q is not bound to principal %q", roleName, principal), logical.ErrPermissionDenied
	case len(roles) == 0:
		return nil, logical.ErrorResponse("no role is bound to principal %q", principal), logical.ErrPermissionDenied
	case len(roles) > 1:
		names := make([]string, 0, len(roles))
		for _, role := range roles {
			names = append(names, role.Name)
		}
		return nil, logical.ErrorResponse("principal %q is bound to roles %s; pass role to select one",
			principal, strings.Join(names, ", ")), logical.ErrPermissionDenied
	}
	return roles[0], nil, nil
}

// loginWithRoles completes the login from the single role bound to the
// identity's principal.
func (b *backend) loginWithRoles(ctx context.Context, req *logical.Request, identity goidentity.Identity, roleName string) (*logical.Response, error) {
	principal := fullPrincipal(identity)

	role, resp, err := b.selectRole(ctx, req.Storage, principal, roleName)
	if err != nil || resp != nil {
		return resp, err
	}

	if err := checkBoundCIDRs(b, req, role.TokenBoundCIDRs); err != nil {
		return nil, err
	}

	auth := newAuth(identity.UserName(), identity.Domain(), principal)
	auth.Metadata["role"] = role.Name
	auth.InternalData["role"] = role.Name
	auth.InternalData["principal"] = principal

	if err := role.PopulateTokenAuth(auth, req); err != nil {
		return nil, fmt.Errorf("failed to populate auth information: %w", err)
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

// loginWithDelegationToken logs in as the owner of a delegation token with
// the role fixed at issuance. The token's remaining renewable lifetime caps
// the issued OpenBao token.
func (b *backend) loginWithDelegationToken(ctx context.Context, req *logical.Request, urlString string) (*logical.Response, error) {
	cfg, resp, err := b.delegationEnabled(ctx, req)
	if err != nil || resp != nil {
		return resp, err
	}

	now := b.now()
	id, entry, resp, err := b.verifyDelegationToken(ctx, req.Storage, cfg, urlString, now)
	if err != nil || resp != nil {
		return resp, err
	}

	role, err := b.role(ctx, req.Storage, entry.Role)
	if err != nil {
		return nil, fmt.Errorf("unable to read role %q: %w", entry.Role, err)
	}
	if role == nil || !role.matches(id.Owner) {
		return logical.ErrorResponse("role %q of delegation token %d no longer binds principal %q", entry.Role, id.SequenceNumber, id.Owner), logical.ErrPermissionDenied
	}
	if err := checkBoundCIDRs(b, req, role.TokenBoundCIDRs); err != nil {
		return nil, err
	}

	owner, domain := types.ParseSPNString(id.Owner)
	user := owner.PrincipalNameString()
	seq := strconv.FormatInt(int64(id.SequenceNumber), 10)
	auth := newAuth(user, domain, id.Owner)
	auth.Metadata["role"] = role.Name
	auth.Metadata["delegation_token"] = seq
	auth.InternalData["role"] = role.Name
	auth.InternalData["principal"] = id.Owner
	auth.InternalData["delegation_token"] = seq
	auth.InternalData["delegation_token_identifier"] = base64.StdEncoding.EncodeToString(entry.Identifier)

	if err := role.PopulateTokenAuth(auth, req); err != nil {
		return nil, fmt.Errorf("failed to populate auth information: %w", err)
	}
	// verifyDelegationToken passed against the same now, so remaining > 0.
	if remaining := entry.Expiry.Sub(now); auth.ExplicitMaxTTL == 0 || auth.ExplicitMaxTTL > remaining {
		auth.ExplicitMaxTTL = remaining
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

// pathLoginRenew renews tokens issued from a role; LDAP-mode tokens are not
// renewable and never reach it. A token logged in with a delegation token
// also needs that delegation token to still be valid.
func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName, _ := req.Auth.InternalData["role"].(string)
	principal, _ := req.Auth.InternalData["principal"].(string)
	if roleName == "" || principal == "" {
		return nil, errors.New("token was not issued from a role")
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to validate role %q during renewal: %w", roleName, err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %q does not exist during renewal", roleName)
	}
	if !role.matches(principal) {
		return nil, fmt.Errorf("principal %q is no longer bound to role %q", principal, roleName)
	}
	if !policyutil.EquivalentPolicies(role.TokenPolicies, req.Auth.TokenPolicies) {
		return nil, errors.New("policies have changed, not renewing")
	}

	if seq, _ := req.Auth.InternalData["delegation_token"].(string); seq != "" {
		identifier, _ := req.Auth.InternalData["delegation_token_identifier"].(string)
		if err := b.checkDelegationTokenAlive(ctx, req.Storage, seq, identifier); err != nil {
			return nil, err
		}
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
	return resp, nil
}

// checkDelegationTokenAlive fails when the delegation token behind a login
// was cancelled or has expired since. The record is matched by identifier,
// not only by sequence number, which is reused after the configuration is
// deleted and recreated.
func (b *backend) checkDelegationTokenAlive(ctx context.Context, s logical.Storage, seq, identifierB64 string) error {
	n, err := strconv.ParseInt(seq, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid delegation token reference %q", seq)
	}
	identifier, err := base64.StdEncoding.DecodeString(identifierB64)
	if err != nil || len(identifier) == 0 {
		return fmt.Errorf("invalid delegation token identifier reference for token %s", seq)
	}
	entry, err := b.delegationTokenEntry(ctx, s, int32(n))
	if err != nil {
		return fmt.Errorf("failed to read delegation token %s: %w", seq, err)
	}
	if entry == nil || !hmac.Equal(entry.Identifier, identifier) {
		return fmt.Errorf("delegation token %s has been cancelled", seq)
	}
	if !b.now().Before(entry.Expiry) {
		return fmt.Errorf("delegation token %s has expired", seq)
	}
	return nil
}
