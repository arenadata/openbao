// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

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
against the full principal name (primary/instance@REALM) and needs a realm
after its last "@", "*" for any realm. "*" is the only wildcard and also
matches "/" and "@". Required.`,
			},
			"allowed_principals": {
				Type: framework.TypeCommaStringSlice,
				Description: `Comma-separated list of principals the bound principals may
request delegation tokens for, written like bound_principals. Required.`,
			},
			"bound_cidrs": {
				Type: framework.TypeCommaStringSlice,
				Description: `Comma-separated list of IP addresses or CIDR blocks the
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
	b.proxyLock.RLock()
	defer b.proxyLock.RUnlock()

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
	// The framework would ignore them without a warning, and a misspelled
	// bound_cidrs would leave the proxy unrestricted.
	var unknown []string
	for k := range d.Raw {
		if _, ok := d.Schema[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return logical.ErrorResponse("unknown parameters: %s", strings.Join(unknown, ", ")), logical.ErrInvalidRequest
	}
	name := d.Get("name").(string)

	b.proxyLock.Lock()
	defer b.proxyLock.Unlock()

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
		cidrs, err := parseBoundCIDRs(strutil.RemoveEmpty(raw.([]string)))
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		proxy.BoundCIDRs = cidrs
	}
	if err := checkPrincipalPatterns("bound_principals", proxy.BoundPrincipals); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if err := checkPrincipalPatterns("allowed_principals", proxy.AllowedPrincipals); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if err := putJSON(ctx, req.Storage, proxyPrefix+name, proxy); err != nil {
		return nil, err
	}

	return nil, logical.EndTxStorage(ctx, req)
}

// checkPrincipalPatterns rejects an empty list and entries that cannot match
// a principal: each needs a name and, after its last "@", a realm, which "*"
// stands in for to match any. Only "*" is a wildcard.
func checkPrincipalPatterns(field string, patterns []string) error {
	if len(patterns) == 0 {
		return fmt.Errorf("%s must contain at least one entry", field)
	}
	for _, p := range patterns {
		i := strings.LastIndex(p, "@")
		switch {
		case i < 0 || i == len(p)-1:
			return fmt.Errorf(`%s entry %q has no realm; use "@*" for any realm`, field, p)
		case slices.Contains(strings.Split(p[:i], "/"), ""):
			return fmt.Errorf("%s entry %q has an empty name component", field, p)
		case !utf8.ValidString(p) || strings.ContainsFunc(p, func(r rune) bool {
			return !unicode.IsPrint(r) || r == '?' || r == '['
		}):
			return fmt.Errorf(`%s entry %q is not a principal pattern; "*" is the only wildcard`, field, p)
		}
	}
	return nil
}

// parseBoundCIDRs accepts IP addresses and CIDR blocks only; on its own,
// parseutil.ParseAddrs also takes host:port, resolving the host, as well as
// hex netmasks and UNIX socket paths.
func parseBoundCIDRs(entries []string) ([]*sockaddr.SockAddrMarshaler, error) {
	for _, e := range entries {
		prefix, err := netip.ParsePrefix(e)
		addr := prefix.Addr()
		if err != nil {
			addr, err = netip.ParseAddr(e)
		}
		if err != nil || addr.Is4In6() || addr.Zone() != "" {
			return nil, fmt.Errorf("bound_cidrs entry %q is not an IP address or CIDR block", e)
		}
	}
	return parseutil.ParseAddrs(entries)
}

func (b *backend) pathProxyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.proxyLock.Lock()
	defer b.proxyLock.Unlock()

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
hadoop.proxyuser.<name>.hosts; hadoop.proxyuser.<name>.groups has none.
Proxies are independent of roles: the requesting principal needs no role,
while the owner needs one as usual.
`
