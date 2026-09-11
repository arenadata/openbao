// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"regexp"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const rolePrefix = "role/"

var roleNameRegex = regexp.MustCompile("^" + framework.GenericNameRegex("name") + "$")

// kerberosRole maps Kerberos principals to token parameters without LDAP.
type kerberosRole struct {
	tokenutil.TokenParams

	Name string `json:"-"`

	// Glob patterns matched against the full principal name
	// (`primary/instance@REALM`); any match is sufficient.
	BoundPrincipals []string `json:"bound_principals"`
}

func (r *kerberosRole) matches(principal string) bool {
	return strutil.StrListContainsGlob(r.BoundPrincipals, principal)
}

func (b *backend) pathRolesList() *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKerberos,
			OperationVerb:   "list",
			OperationSuffix: "roles",
		},

		Fields: map[string]*framework.FieldSchema{
			"after": {
				Type:        framework.TypeString,
				Description: `Optional entry to list begin listing after, not required to exist.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Description: `Optional number of entries to return; defaults to all entries.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRoleList,
			},
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func (b *backend) pathRoles() *framework.Path {
	p := &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKerberos,
			OperationSuffix: "role",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
			"bound_principals": {
				Type: framework.TypeCommaStringSlice,
				Description: `Comma-separated list of Kerberos principals allowed to log in
with this role. Each entry is matched against the full principal name
(primary/instance@REALM) and may contain "*" globs. Required.`,
			},
		},

		ExistenceCheck: b.pathRoleExistenceCheck,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
			},
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}

	tokenutil.AddTokenFields(p.Fields)
	return p
}

func (b *backend) role(ctx context.Context, s logical.Storage, name string) (*kerberosRole, error) {
	entry, err := s.Get(ctx, rolePrefix+name)
	if err != nil || entry == nil {
		return nil, err
	}

	role := &kerberosRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	role.Name = name
	return role, nil
}

// matchingRoles returns the roles bound to principal, ordered by name. When
// roleName is set only that role is considered.
func (b *backend) matchingRoles(ctx context.Context, s logical.Storage, principal, roleName string) ([]*kerberosRole, error) {
	names := []string{roleName}
	if roleName == "" {
		var err error
		names, err = s.ListPage(ctx, rolePrefix, "", -1)
		if err != nil {
			return nil, err
		}
	}

	var matched []*kerberosRole
	for _, name := range names {
		role, err := b.role(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if role != nil && role.matches(principal) {
			matched = append(matched, role)
		}
	}
	return matched, nil
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	role, err := b.role(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	roles, err := req.Storage.ListPage(ctx, rolePrefix, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := b.role(ctx, req.Storage, d.Get("name").(string))
	if err != nil || role == nil {
		return nil, err
	}

	data := map[string]interface{}{
		"bound_principals": role.BoundPrincipals,
	}
	role.PopulateTokenData(data)

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &kerberosRole{}
	}

	if raw, ok := d.GetOk("bound_principals"); ok {
		role.BoundPrincipals = strutil.RemoveEmpty(raw.([]string))
	}
	if len(role.BoundPrincipals) == 0 {
		return logical.ErrorResponse("bound_principals must contain at least one entry"), logical.ErrInvalidRequest
	}

	if err := role.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if maxTTL := b.System().MaxLeaseTTL(); role.TokenPeriod > maxTTL {
		return logical.ErrorResponse("token_period of %q is greater than the backend's maximum lease TTL of %q",
			role.TokenPeriod.String(), maxTTL.String()), logical.ErrInvalidRequest
	}

	entry, err := logical.StorageEntryJSON(rolePrefix+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, logical.EndTxStorage(ctx, req)
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, rolePrefix+d.Get("name").(string))
}

const pathRoleHelpSyn = `
Manage roles mapping Kerberos principals to policies.
`

const pathRoleHelpDesc = `
Roles bind Kerberos principals to token parameters directly, without an
LDAP lookup. They are consulted only when "config/ldap" is not set. At login
the authenticated principal (primary/instance@REALM) is matched against
"bound_principals" of the role named in the request or, without a role name,
of every role. Exactly one role must match; the login is denied when none or
several do.
`
