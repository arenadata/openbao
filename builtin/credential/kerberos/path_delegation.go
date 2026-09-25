// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-krb5/krb5/types"
	goidentity "github.com/go-krb5/x/identity"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	delegationTokenPathName  = "delegation/token"
	delegationRenewPathName  = "delegation/renew"
	delegationCancelPathName = "delegation/cancel"
)

var (
	authorizationField = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `SPNEGO Authorization header. Required.`,
	}
	delegationTokenField = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `The delegation token in its URL string form. Required.`,
	}
)

func (b *backend) pathDelegationToken() *framework.Path {
	return b.delegationPath(delegationTokenPathName, "issue", pathDelegationTokenHelpSyn, b.pathDelegationTokenUpdate, map[string]*framework.FieldSchema{
		"renewer": {
			Type: framework.TypeString,
			Description: `Name allowed to renew the token, compared against the renewing
principal's full name or, within the realm of the principal requesting the
token, its primary/instance or primary. Empty makes the token
non-renewable.`,
		},
		"service": {
			Type:        framework.TypeString,
			Description: `Hadoop token service written into the token. Optional.`,
		},
		"max_lifetime": {
			Type: framework.TypeDurationSecond,
			Description: `Requested hard lifetime, capped by the configured
max_lifetime. Optional.`,
		},
		"role": {
			Type: framework.TypeString,
			Description: `Role to issue the token for. Optional; without it every role
is matched and exactly one must match the owner's principal.`,
		},
		"doas": {
			Type: framework.TypeString,
			Description: `Principal to own the token instead of the caller, who is then
recorded as its real user. A name without a realm is in the doas_realm of
config/delegation or, without one, in the caller's realm. The caller must be
bound to exactly one role, and that role must list the principal in
allowed_proxy_principals. Optional.`,
		},
	})
}

func (b *backend) pathDelegationRenew() *framework.Path {
	return b.delegationPath(delegationRenewPathName, "renew", pathDelegationRenewHelpSyn, b.pathDelegationRenewUpdate, map[string]*framework.FieldSchema{
		"token": delegationTokenField,
	})
}

func (b *backend) pathDelegationCancel() *framework.Path {
	return b.delegationPath(delegationCancelPathName, "cancel", pathDelegationCancelHelpSyn, b.pathDelegationCancelUpdate, map[string]*framework.FieldSchema{
		"token": delegationTokenField,
	})
}

func (b *backend) delegationPath(name, verb, synopsis string, callback framework.OperationFunc, fields map[string]*framework.FieldSchema) *framework.Path {
	fields["authorization"] = authorizationField
	return &framework.Path{
		Pattern: name + "$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKerberos,
			OperationVerb:   verb,
			OperationSuffix: "delegation-token",
		},
		Fields: fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: callback,
			},
		},
		HelpSynopsis:    synopsis,
		HelpDescription: pathDelegationHelpDesc,
	}
}

// delegationCaller authenticates a delegation endpoint call: the caller must
// present a SPNEGO token, then delegation tokens must be enabled with
// policies coming from roles. On failure the response and error to return
// are set.
func (b *backend) delegationCaller(ctx context.Context, req *logical.Request, d *framework.FieldData) (goidentity.Identity, *delegationConfig, *logical.Response, error) {
	kerbCfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to get kerberos config: %w", err)
	}
	if kerbCfg == nil {
		return nil, nil, nil, errors.New("backend kerberos not configured")
	}

	identity, resp, err := b.negotiate(ctx, req, d, kerbCfg)
	if err != nil || resp != nil {
		return nil, nil, resp, err
	}

	cfg, resp, err := b.delegationEnabled(ctx, req)
	if err != nil || resp != nil {
		return nil, nil, resp, err
	}
	return identity, cfg, nil, nil
}

// delegationEnabled returns the delegation configuration, or the rejection
// explaining why delegation tokens cannot be used on this mount.
func (b *backend) delegationEnabled(ctx context.Context, req *logical.Request) (*delegationConfig, *logical.Response, error) {
	ldapCfg, err := b.ConfigLdap(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get ldap config: %w", err)
	}
	if ldapCfg != nil {
		return nil, logical.ErrorResponse("delegation tokens are not available while config/ldap is set"), logical.ErrInvalidRequest
	}
	cfg, err := b.delegationConfig(ctx, req.Storage)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get delegation config: %w", err)
	}
	if cfg == nil {
		return nil, logical.ErrorResponse("delegation tokens are not enabled; write config/delegation first"), logical.ErrInvalidRequest
	}
	return cfg, nil, nil
}

func (b *backend) pathDelegationTokenUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	if roleName != "" && !roleNameRegex.MatchString(roleName) {
		return logical.ErrorResponse("invalid role name %q", roleName), logical.ErrInvalidRequest
	}
	// The field schema would turn a JSON boolean or number into a name.
	if raw, ok := req.Data["doas"]; ok && raw != nil {
		if _, ok := raw.(string); !ok {
			return logical.ErrorResponse("doas must be a string"), logical.ErrInvalidRequest
		}
	}

	identity, cfg, resp, err := b.delegationCaller(ctx, req, d)
	if err != nil || resp != nil {
		return resp, err
	}

	caller := fullPrincipal(identity)
	owner, realUser, proxyRole := caller, "", ""
	if doas := d.Get("doas").(string); doas != "" {
		realm := cfg.DoasRealm
		if realm == "" {
			realm = identity.Domain()
		}
		if owner, err = doasPrincipal(doas, realm); err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	}
	if owner != caller {
		// Checked before the owner's roles, so a caller cannot probe role
		// bindings.
		grant, resp, err := b.proxyGrant(ctx, req, caller, owner)
		if err != nil || resp != nil {
			return resp, err
		}
		realUser, proxyRole = caller, grant.Name
	}

	role, resp, err := b.selectRole(ctx, req.Storage, owner, roleName)
	if err != nil || resp != nil {
		return resp, err
	}
	if err := checkBoundCIDRs(b, req, role.TokenBoundCIDRs); err != nil {
		return nil, err
	}

	renewer := d.Get("renewer").(string)
	service := d.Get("service").(string)
	maxLifetime := time.Duration(d.Get("max_lifetime").(int)) * time.Second

	b.delegationLock.Lock()
	defer b.delegationLock.Unlock()

	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	// Re-read under the lock: a concurrent delete of the configuration must
	// not be followed by an issuance that recreates the purged records.
	cfg, resp, err = b.delegationEnabled(ctx, req)
	if err != nil || resp != nil {
		return resp, err
	}

	tok, id, entry, err := b.issueDelegationToken(ctx, req.Storage, cfg, delegationRequest{
		Owner:       owner,
		RealUser:    realUser,
		Renewer:     renewer,
		Service:     service,
		Role:        role.Name,
		ProxyRole:   proxyRole,
		MaxLifetime: maxLifetime,
	})
	if err != nil {
		return nil, err
	}
	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	b.Logger().Debug("issued delegation token", "sequence", id.SequenceNumber, "owner", id.Owner, "real_user", id.RealUser, "renewer", id.Renewer, "role", role.Name)
	return &logical.Response{
		Data: map[string]interface{}{
			"token":           tok.encodeURLString(),
			"kind":            tok.Kind,
			"service":         tok.Service,
			"owner":           id.Owner,
			"real_user":       id.RealUser,
			"renewer":         id.Renewer,
			"issue_date":      id.IssueDate,
			"max_date":        id.MaxDate,
			"expiry":          entry.Expiry.UnixMilli(),
			"sequence_number": id.SequenceNumber,
			"master_key_id":   id.MasterKeyID,
			"role":            role.Name,
		},
	}, nil
}

func (b *backend) pathDelegationRenewUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	identity, cfg, resp, err := b.delegationCaller(ctx, req, d)
	if err != nil || resp != nil {
		return resp, err
	}

	b.delegationLock.Lock()
	defer b.delegationLock.Unlock()

	now := b.now()
	id, entry, resp, err := b.verifyDelegationToken(ctx, req.Storage, cfg, d.Get("token").(string), now)
	if err != nil || resp != nil {
		return resp, err
	}
	if id.Renewer == "" {
		return logical.ErrorResponse("delegation token %d has no renewer", id.SequenceNumber), logical.ErrPermissionDenied
	}
	if !renewerMatches(identity, id) {
		return logical.ErrorResponse("principal %q is not the renewer %q of delegation token %d", fullPrincipal(identity), id.Renewer, id.SequenceNumber), logical.ErrPermissionDenied
	}
	denial, err := b.proxyGrantDenial(ctx, req.Storage, id, entry)
	if err != nil {
		return nil, err
	}
	if denial != "" {
		return logical.ErrorResponse(denial), logical.ErrPermissionDenied
	}

	entry.Expiry = delegationExpiry(now, cfg, id)
	if err := putJSON(ctx, req.Storage, delegationTokenPath(id.SequenceNumber), entry); err != nil {
		return nil, err
	}

	b.Logger().Debug("renewed delegation token", "sequence", id.SequenceNumber, "expiry", entry.Expiry)
	return &logical.Response{
		Data: map[string]interface{}{
			"expiry":          entry.Expiry.UnixMilli(),
			"max_date":        id.MaxDate,
			"sequence_number": id.SequenceNumber,
		},
	}, nil
}

func (b *backend) pathDelegationCancelUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	identity, cfg, resp, err := b.delegationCaller(ctx, req, d)
	if err != nil || resp != nil {
		return resp, err
	}

	b.delegationLock.Lock()
	defer b.delegationLock.Unlock()

	id, _, resp, err := b.verifyDelegationToken(ctx, req.Storage, cfg, d.Get("token").(string), b.now())
	if err != nil || resp != nil {
		return resp, err
	}
	caller := fullPrincipal(identity)
	if caller != id.Owner && (id.Renewer == "" || !renewerMatches(identity, id)) {
		// A principal allowed to impersonate the owner may cancel too, as in
		// Hadoop, where it cancels as the owner.
		_, resp, err := b.proxyGrant(ctx, req, caller, id.Owner)
		if err != nil && !errors.Is(err, logical.ErrPermissionDenied) {
			return nil, err
		}
		if err != nil || resp != nil {
			return logical.ErrorResponse("principal %q is neither the owner nor the renewer of delegation token %d and may not impersonate its owner", caller, id.SequenceNumber), logical.ErrPermissionDenied
		}
	}

	b.Logger().Debug("cancelling delegation token", "sequence", id.SequenceNumber, "by", caller)
	return nil, req.Storage.Delete(ctx, delegationTokenPath(id.SequenceNumber))
}

func fullPrincipal(identity goidentity.Identity) string {
	return identity.UserName() + "@" + identity.Domain()
}

// doasPrincipal is the full principal a doas value names; a name without a
// realm is in realm. As in types.ParseSPNString, the realm follows the last
// "@".
func doasPrincipal(doas, realm string) (string, error) {
	name := doas
	if i := strings.LastIndex(doas, "@"); i >= 0 {
		name, realm = doas[:i], doas[i+1:]
	}
	if len(doas) > maxDoasLength || !validPrincipalText(doas) || realm == "" || slices.Contains(strings.Split(name, "/"), "") {
		return "", fmt.Errorf("doas %q is not a principal name", doas)
	}
	return name + "@" + realm, nil
}

// maxDoasLength bounds a doas value well below the identifier's field limit.
const maxDoasLength = 1024

// validPrincipalText rejects invalid UTF-8, spaces and other non-printing
// characters, and the characters role pattern lists give a meaning to.
func validPrincipalText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return !unicode.IsPrint(r) || strings.ContainsRune(" *,", r)
	})
}

// proxyGrant returns the role that lets caller impersonate owner: the only
// role bound to caller, listing owner in allowed_proxy_principals and
// admitting the caller's address. Otherwise the response and error to
// return are set.
func (b *backend) proxyGrant(ctx context.Context, req *logical.Request, caller, owner string) (*kerberosRole, *logical.Response, error) {
	roles, err := b.matchingRoles(ctx, req.Storage, caller, "")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to match roles: %w", err)
	}
	switch {
	case len(roles) == 0:
		return nil, logical.ErrorResponse("no role is bound to principal %q", caller), logical.ErrPermissionDenied
	case len(roles) > 1:
		return nil, logical.ErrorResponse("principal %q is bound to roles %s; impersonation requires exactly one", caller, roleNames(roles)), logical.ErrPermissionDenied
	case !roles[0].allowsProxy(owner):
		return nil, logical.ErrorResponse("role %q of principal %q does not allow impersonating %q", roles[0].Name, caller, owner), logical.ErrPermissionDenied
	}
	if err := checkBoundCIDRs(b, req, roles[0].TokenBoundCIDRs); err != nil {
		return nil, nil, err
	}
	return roles[0], nil, nil
}

// proxyGrantDenial explains why a token with a real user may no longer be
// used: the role recorded at issuance as granting the impersonation is gone,
// no longer binds the real user or no longer lists the owner. It is empty
// for a token without a real user and while the grant holds.
func (b *backend) proxyGrantDenial(ctx context.Context, s logical.Storage, id *delegationTokenIdentifier, entry *delegationTokenEntry) (string, error) {
	if id.RealUser == "" {
		return "", nil
	}
	role, err := b.role(ctx, s, entry.ProxyRole)
	if err != nil {
		return "", fmt.Errorf("unable to read role %q: %w", entry.ProxyRole, err)
	}
	if role == nil || !role.matches(id.RealUser) || !role.allowsProxy(id.Owner) {
		return fmt.Sprintf("real user %q of delegation token %d may no longer impersonate %q", id.RealUser, id.SequenceNumber, id.Owner), nil
	}
	return "", nil
}

// renewerMatches reports whether the caller is the token's renewer. The
// renewer may be spelled as a full principal or, for callers from the realm
// of the principal that requested the token only, as primary/instance or the
// bare primary, which is the short name a default auth_to_local rule yields.
// That principal is the real user of a token issued through doas and the
// owner otherwise.
func renewerMatches(identity goidentity.Identity, id *delegationTokenIdentifier) bool {
	requester := id.Owner
	if id.RealUser != "" {
		requester = id.RealUser
	}
	_, realm := types.ParseSPNString(requester)
	return callerMatches(identity, id.Renewer, realm)
}

func callerMatches(identity goidentity.Identity, name, realm string) bool {
	if name == fullPrincipal(identity) {
		return true
	}
	if identity.Domain() != realm {
		return false
	}
	user := identity.UserName()
	primary, _, _ := strings.Cut(user, "/")
	return name == user || name == primary
}

const (
	pathDelegationTokenHelpSyn  = `Issue a Hadoop-style delegation token owned by the SPNEGO-authenticated principal or, with doas, by the principal it names.`
	pathDelegationRenewHelpSyn  = `Renew a delegation token; the caller must be its renewer.`
	pathDelegationCancelHelpSyn = `Cancel a delegation token; the caller must be its owner, its renewer or allowed to impersonate its owner.`
	pathDelegationHelpDesc      = `
Delegation tokens let a Kerberos-authenticated principal hand a credential to
processes without Kerberos credentials, such as YARN containers. The token is
byte-compatible with Hadoop's AbstractDelegationTokenIdentifier and Token, so
it travels through the Hadoop Credentials machinery, YARN renews it through a
TokenRenewer, and a holder logs in with it through "login" using the
"delegation_token" parameter. Every endpoint here requires a SPNEGO token;
a delegation token cannot be used to obtain another one. With "doas" a
service issues a token owned by another principal, as a Hadoop proxy user;
"allowed_proxy_principals" of the service's role decides whom it may
impersonate.
`
)
