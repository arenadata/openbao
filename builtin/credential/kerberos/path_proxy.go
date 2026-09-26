// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-sockaddr"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const proxyPrefix = "proxy/"

// kerberosProxy lets principals request delegation tokens owned by other
// principals, like hadoop.proxyuser.<name>.* in Hadoop.
type kerberosProxy struct {
	Name string `json:"-"`

	// Glob patterns matched against the full name of the principal that
	// requests a token.
	BoundPrincipals []string `json:"bound_principals"`

	// Glob patterns matched against the full name of the principal that
	// owns the token.
	AllowedPrincipals []string `json:"allowed_principals"`

	// When set, the address of the requesting principal must be in one of
	// these blocks.
	BoundCIDRs []*sockaddr.SockAddrMarshaler `json:"bound_cidrs,omitempty"`
}

func (p *kerberosProxy) allows(realUser, owner string) bool {
	return strutil.StrListContainsGlob(p.BoundPrincipals, realUser) &&
		strutil.StrListContainsGlob(p.AllowedPrincipals, owner)
}

func (b *backend) pathProxiesList() *framework.Path {
	return &framework.Path{
		Pattern: "proxy/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKerberos,
			OperationVerb:   "list",
			OperationSuffix: "proxies",
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
				Callback: b.pathProxyList,
			},
		},

		HelpSynopsis:    pathProxyHelpSyn,
		HelpDescription: pathProxyHelpDesc,
	}
}

func (b *backend) pathProxies() *framework.Path {
	return &framework.Path{
		Pattern: proxyPrefix + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKerberos,
			OperationSuffix: "proxy",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the proxy.",
			},
			"bound_principals": {
				Type: framework.TypeCommaStringSlice,
				Description: `Comma-separated list of principals allowed to request
delegation tokens for other principals with "doas". Each entry is matched
against the full principal name (primary/instance@REALM), may contain "*"
globs and needs a realm or a "*". Required.`,
			},
			"allowed_principals": {
				Type: framework.TypeCommaStringSlice,
				Description: `Comma-separated list of principals the bound principals may
request delegation tokens for. Each entry is matched against the full
principal name (primary@REALM or primary/instance@REALM), may contain "*"
globs and needs a realm or a "*". Required.`,
			},
			"bound_cidrs": {
				Type: framework.TypeCommaStringSlice,
				Description: `Comma-separated list of CIDR blocks or IP addresses the
bound principals must request tokens from. Empty allows any address.`,
			},
		},

		ExistenceCheck: b.pathProxyExistenceCheck,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathProxyRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathProxyWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathProxyWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathProxyDelete,
			},
		},

		HelpSynopsis:    pathProxyHelpSyn,
		HelpDescription: pathProxyHelpDesc,
	}
}

func (b *backend) proxy(ctx context.Context, s logical.Storage, name string) (*kerberosProxy, error) {
	entry, err := s.Get(ctx, proxyPrefix+name)
	if err != nil || entry == nil {
		return nil, err
	}

	proxy := &kerberosProxy{}
	if err := entry.DecodeJSON(proxy); err != nil {
		return nil, err
	}
	proxy.Name = name
	return proxy, nil
}

// matchingProxies returns the proxies letting realUser request tokens owned
// by owner, ordered by name.
func (b *backend) matchingProxies(ctx context.Context, s logical.Storage, realUser, owner string) ([]*kerberosProxy, error) {
	names, err := s.ListPage(ctx, proxyPrefix, "", -1)
	if err != nil {
		return nil, err
	}

	var matched []*kerberosProxy
	for _, name := range names {
		proxy, err := b.proxy(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if proxy != nil && proxy.allows(realUser, owner) {
			matched = append(matched, proxy)
		}
	}
	return matched, nil
}

func (b *backend) pathProxyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	proxy, err := b.proxy(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}
	return proxy != nil, nil
}

func (b *backend) pathProxyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	proxies, err := req.Storage.ListPage(ctx, proxyPrefix, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(proxies), nil
}

func (b *backend) pathProxyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	proxy, err := b.proxy(ctx, req.Storage, d.Get("name").(string))
	if err != nil || proxy == nil {
		return nil, err
	}

	cidrs := make([]string, 0, len(proxy.BoundCIDRs))
	for _, cidr := range proxy.BoundCIDRs {
		cidrs = append(cidrs, cidr.String())
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_principals":   proxy.BoundPrincipals,
			"allowed_principals": proxy.AllowedPrincipals,
			"bound_cidrs":        cidrs,
		},
	}, nil
}

func (b *backend) pathProxyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	proxy, err := b.proxy(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		proxy = &kerberosProxy{}
	}

	if raw, ok := d.GetOk("bound_principals"); ok {
		proxy.BoundPrincipals = strutil.RemoveEmpty(raw.([]string))
	}
	if raw, ok := d.GetOk("allowed_principals"); ok {
		proxy.AllowedPrincipals = strutil.RemoveEmpty(raw.([]string))
	}
	if raw, ok := d.GetOk("bound_cidrs"); ok {
		entries := strutil.RemoveEmpty(raw.([]string))
		cidrs, err := parseutil.ParseAddrs(entries)
		if err != nil {
			return logical.ErrorResponse("invalid bound_cidrs: %s", err), logical.ErrInvalidRequest
		}
		// A malformed block with a "/" parses as a UNIX socket path.
		for i, cidr := range cidrs {
			if cidr.Type()&sockaddr.TypeIP == 0 {
				return logical.ErrorResponse("bound_cidrs entry %q is not an IP address or CIDR block", entries[i]), logical.ErrInvalidRequest
			}
		}
		proxy.BoundCIDRs = cidrs
	}
	if err := checkPrincipalPatterns("bound_principals", proxy.BoundPrincipals); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if err := checkPrincipalPatterns("allowed_principals", proxy.AllowedPrincipals); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	entry, err := logical.StorageEntryJSON(proxyPrefix+name, proxy)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, logical.EndTxStorage(ctx, req)
}

// checkPrincipalPatterns rejects an empty list and entries that never match:
// a principal name always carries a realm.
func checkPrincipalPatterns(field string, patterns []string) error {
	if len(patterns) == 0 {
		return fmt.Errorf("%s must contain at least one entry", field)
	}
	for _, p := range patterns {
		if !strings.ContainsAny(p, "@*") {
			return fmt.Errorf("%s entry %q has no realm", field, p)
		}
	}
	return nil
}

func (b *backend) pathProxyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, proxyPrefix+d.Get("name").(string))
}

const pathProxyHelpSyn = `
Manage principals allowed to request delegation tokens for other principals.
`

const pathProxyHelpDesc = `
A proxy lets the principals matching "bound_principals" request delegation
tokens owned by the principals matching "allowed_principals", by naming the
owner in the "doas" parameter of "delegation/token", as a Hadoop proxy user
does. With "bound_cidrs" set, the request must also come from one of those
addresses. Any proxy satisfying all of these grants the request. The
counterparts in Hadoop are hadoop.proxyuser.<name>.users and
hadoop.proxyuser.<name>.hosts. Proxies are independent of roles: the
requesting principal needs no role, while the owner needs one as usual.
`
