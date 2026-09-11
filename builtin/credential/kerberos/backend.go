// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	configPath string = "config"

	// operationPrefixKerberos is used as a prefix for OpenAPI operation id's.
	operationPrefixKerberos = "kerberos"
)

type backend struct {
	*framework.Backend

	// delegationLock serializes delegation token issuance, renewal,
	// cancellation and key rotation, which all read-modify-write storage.
	delegationLock sync.Mutex
	lastCleanup    time.Time
	now            func() time.Time
}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	b := &backend{now: time.Now}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				delegationTokenPathName,
				delegationRenewPathName,
				delegationCancelPathName,
			},
			SealWrapStorage: []string{configPath, delegationKeyPrefix},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathConfig(),
				b.pathConfigLdap(),
				b.pathConfigDelegation(),
				b.pathLogin(),
				b.pathGroups(),
				b.pathGroupsList(),
				b.pathRoles(),
				b.pathRolesList(),
				b.pathDelegationToken(),
				b.pathDelegationRenew(),
				b.pathDelegationCancel(),
			},
		),
		AuthRenew:    b.pathLoginRenew,
		PeriodicFunc: b.periodicDelegation,
	}

	return b
}

func (b *backend) config(ctx context.Context, s logical.Storage) (*kerberosConfig, error) {
	raw, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	conf := &kerberosConfig{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}

	return conf, nil
}

var backendHelp string = `
The Kerberos Auth Backend allows authentication via Kerberos SPNEGO.
Policies are resolved either from LDAP group membership ("config/ldap" and
"groups/") or, when LDAP is not configured, from roles binding Kerberos
principals directly ("roles/"). With roles, "config/delegation" enables
Hadoop-style delegation tokens that Kerberos-authenticated principals issue
for processes without Kerberos credentials.
`
