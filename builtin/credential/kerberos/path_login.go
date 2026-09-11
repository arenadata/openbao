// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-sockaddr"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/cidrutil"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
	"github.com/openbao/openbao/sdk/v2/helper/policyutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"gopkg.in/jcmturner/goidentity.v3"
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
				Description: `SPNEGO Authorization header. Required.`,
			},
			"role": {
				Type: framework.TypeString,
				Description: `Name of the role to log in with. Optional; without it
every role is matched and exactly one must match. Rejected while
"config/ldap" is set.`,
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

	authorizationString := ""
	authorizationHeaders := req.Headers["Authorization"]
	if len(authorizationHeaders) > 0 {
		authorizationString = authorizationHeaders[0]
	} else {
		authorizationString = d.Get("authorization").(string)
	}

	s := strings.SplitN(authorizationString, " ", 2)
	if len(s) != 2 || s[0] != "Negotiate" {
		return b.pathLoginGet(ctx, req, d)
	}

	kt, err := parseKeytab(kerbCfg.Keytab)
	if err != nil {
		return nil, fmt.Errorf("could not parse keytab: %w", err)
	}

	if kerbCfg.RemoveInstanceName {
		removeInstanceNameFromKeytab(kt)
	}

	identity, w := b.spnegoAuthenticate(req, kerbCfg, kt, authorizationString)
	if identity == nil {
		resp := &logical.Response{
			Warnings: []string{string(w.body)},
		}
		return logical.RespondWithStatusCode(resp, req, w.statusCode)
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
// A nil identity means failure; the writer then holds the status code and message.
func (b *backend) spnegoAuthenticate(req *logical.Request, kerbCfg *kerberosConfig, kt *keytab.Keytab, authorization string) (goidentity.Identity, *simpleResponseWriter) {
	// The SPNEGOKRB5Authenticate method only calls an inner function if it's
	// successful. Let's use it to record success, and to retrieve the caller's
	// identity.
	var identity goidentity.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Context().Value(goidentity.CTXKey)
		if raw == nil {
			w.WriteHeader(400)
			_, _ = w.Write([]byte("identity credentials are not included"))
			return
		}
		id, ok := raw.(goidentity.Identity)
		if !ok {
			w.WriteHeader(400)
			_, _ = fmt.Fprintf(w, "identity credentials are malformed: %+v", raw)
			return
		}
		b.Logger().Debug("spnego identity", "user", id.UserName(), "domain", id.Domain())
		identity = id
	})

	// Let's pass in a logger so we can get debugging information if anything
	// goes wrong.
	l := b.Logger().StandardLogger(&hclog.StandardLoggerOptions{
		InferLevels: true,
	})

	// Now let's use our inner handler to compose the overall function.
	authHTTPHandler := spnego.SPNEGOKRB5Authenticate(inner, kt, service.Logger(l), service.KeytabPrincipal(kerbCfg.ServiceAccount))

	// Because the outer application strips off the raw request, we need to
	// re-compose it to use this authentication handler. Only the request
	// remote addr and the Authorization header are used anyways. We use an
	// arbitrary port of 8080 because it's not used for anything but logging,
	// but is required by an underlying parser.
	remoteAddr := ""
	if req.Connection != nil {
		remoteAddr = req.Connection.RemoteAddr
	}
	rebuiltReq := &http.Request{
		Header:     http.Header{spnego.HTTPHeaderAuthRequest: []string{authorization}},
		RemoteAddr: remoteAddr + ":8080",
	}

	// Finally, execute the SPNEGO authentication check.
	w := &simpleResponseWriter{}
	authHTTPHandler.ServeHTTP(w, rebuiltReq)
	return identity, w
}

func newAuth(identity goidentity.Identity, aliasName string) *logical.Auth {
	return &logical.Auth{
		InternalData: map[string]interface{}{},
		Metadata: map[string]string{
			"user":   identity.UserName(),
			"domain": identity.Domain(),
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
		user := splitUsername(identity.UserName())
		if len(user) > 1 {
			username = user[0]
		}
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

	auth := newAuth(identity, identity.UserName())
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

// loginWithRoles completes the login from the single role bound to the
// identity's principal.
func (b *backend) loginWithRoles(ctx context.Context, req *logical.Request, identity goidentity.Identity, roleName string) (*logical.Response, error) {
	principal := identity.UserName() + "@" + identity.Domain()

	roles, err := b.matchingRoles(ctx, req.Storage, principal, roleName)
	if err != nil {
		return nil, fmt.Errorf("unable to match roles: %w", err)
	}
	switch {
	case len(roles) == 0 && roleName != "":
		return logical.ErrorResponse("role %q is not bound to principal %q", roleName, principal), logical.ErrPermissionDenied
	case len(roles) == 0:
		return logical.ErrorResponse("no role is bound to principal %q", principal), logical.ErrPermissionDenied
	case len(roles) > 1:
		names := make([]string, 0, len(roles))
		for _, role := range roles {
			names = append(names, role.Name)
		}
		return logical.ErrorResponse("principal %q is bound to roles %s; pass role to select one",
			principal, strings.Join(names, ", ")), logical.ErrPermissionDenied
	}
	role := roles[0]

	if err := checkBoundCIDRs(b, req, role.TokenBoundCIDRs); err != nil {
		return nil, err
	}

	auth := newAuth(identity, principal)
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

// pathLoginRenew renews tokens issued from a role; LDAP-mode tokens are not
// renewable and never reach it.
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

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
	return resp, nil
}

type simpleResponseWriter struct {
	body       []byte
	statusCode int
}

func (w *simpleResponseWriter) Header() http.Header {
	return make(http.Header)
}

func (w *simpleResponseWriter) Write(b []byte) (int, error) {
	w.body = b
	return 0, nil
}

func (w *simpleResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}
