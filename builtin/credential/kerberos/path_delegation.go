// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"gopkg.in/jcmturner/goidentity.v3"
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
principal's full name or, within the owner's realm, its primary/instance or
primary. Empty makes the token non-renewable.`,
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
is matched and exactly one must match the caller's principal.`,
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
// policies coming from roles. A nil identity comes with the response to
// return.
func (b *backend) delegationCaller(ctx context.Context, req *logical.Request, d *framework.FieldData) (goidentity.Identity, *delegationConfig, *logical.Response, error) {
	kerbCfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to get kerberos config: %w", err)
	}
	if kerbCfg == nil {
		return nil, nil, nil, errors.New("backend kerberos not configured")
	}

	identity, resp, err := b.negotiate(ctx, req, d, kerbCfg)
	if identity == nil {
		return nil, nil, resp, err
	}

	cfg, resp, err := b.delegationEnabled(ctx, req)
	if cfg == nil {
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

	identity, _, resp, err := b.delegationCaller(ctx, req, d)
	if identity == nil {
		return resp, err
	}

	principal := fullPrincipal(identity)
	role, resp, err := b.selectRole(ctx, req.Storage, principal, roleName)
	if role == nil {
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
	cfg, resp, err := b.delegationEnabled(ctx, req)
	if cfg == nil {
		return resp, err
	}

	tok, id, entry, err := b.issueDelegationToken(ctx, req.Storage, cfg, principal, renewer, service, role.Name, maxLifetime)
	if err != nil {
		return nil, err
	}
	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	b.Logger().Debug("issued delegation token", "sequence", id.SequenceNumber, "owner", id.Owner, "renewer", id.Renewer, "role", role.Name)
	return &logical.Response{
		Data: map[string]interface{}{
			"token":           tok.encodeURLString(),
			"kind":            tok.Kind,
			"service":         tok.Service,
			"owner":           id.Owner,
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
	if identity == nil {
		return resp, err
	}

	b.delegationLock.Lock()
	defer b.delegationLock.Unlock()

	now := b.now()
	id, entry, resp, err := b.verifyDelegationToken(ctx, req.Storage, cfg, d.Get("token").(string), now)
	if id == nil {
		return resp, err
	}
	if id.Renewer == "" {
		return logical.ErrorResponse("delegation token %d has no renewer", id.SequenceNumber), logical.ErrPermissionDenied
	}
	if !renewerMatches(identity, id) {
		return logical.ErrorResponse("principal %q is not the renewer %q of delegation token %d", fullPrincipal(identity), id.Renewer, id.SequenceNumber), logical.ErrPermissionDenied
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
	if identity == nil {
		return resp, err
	}

	b.delegationLock.Lock()
	defer b.delegationLock.Unlock()

	id, _, resp, err := b.verifyDelegationToken(ctx, req.Storage, cfg, d.Get("token").(string), b.now())
	if id == nil {
		return resp, err
	}
	if fullPrincipal(identity) != id.Owner && (id.Renewer == "" || !renewerMatches(identity, id)) {
		return logical.ErrorResponse("principal %q is neither the owner nor the renewer of delegation token %d", fullPrincipal(identity), id.SequenceNumber), logical.ErrPermissionDenied
	}

	b.Logger().Debug("cancelling delegation token", "sequence", id.SequenceNumber, "by", fullPrincipal(identity))
	return nil, req.Storage.Delete(ctx, delegationTokenPath(id.SequenceNumber))
}

func fullPrincipal(identity goidentity.Identity) string {
	return identity.UserName() + "@" + identity.Domain()
}

// renewerMatches reports whether the caller is the token's renewer. The
// renewer may be spelled as a full principal or, for callers from the
// owner's realm only, as primary/instance or the bare primary, which is the
// short name a default auth_to_local rule yields.
func renewerMatches(identity goidentity.Identity, id *delegationTokenIdentifier) bool {
	return callerMatches(identity, id.Renewer, principalRealm(id.Owner))
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
	pathDelegationTokenHelpSyn  = `Issue a Hadoop-style delegation token for the SPNEGO-authenticated principal.`
	pathDelegationRenewHelpSyn  = `Renew a delegation token; the caller must be its renewer.`
	pathDelegationCancelHelpSyn = `Cancel a delegation token; the caller must be its owner or renewer.`
	pathDelegationHelpDesc      = `
Delegation tokens let a Kerberos-authenticated principal hand a credential to
processes without Kerberos credentials, such as YARN containers. The token is
byte-compatible with Hadoop's AbstractDelegationTokenIdentifier and Token, so
it travels through the Hadoop Credentials machinery, YARN renews it through a
TokenRenewer, and a holder logs in with it through "login" using the
"delegation_token" parameter. Every endpoint here requires a SPNEGO token;
a delegation token cannot be used to obtain another one.
`
)
