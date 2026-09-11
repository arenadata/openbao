// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	delegationConfigPath = "config/delegation"

	// delegationPrefix holds every delegation token record: keys, tokens
	// and the counters. Deleting the configuration purges it.
	delegationPrefix = "delegation/"

	defaultDelegationRenewInterval       = 24 * time.Hour
	defaultDelegationMaxLifetime         = 7 * 24 * time.Hour
	defaultDelegationKeyRotationInterval = 24 * time.Hour
	defaultDelegationCleanupInterval     = time.Hour
	defaultDelegationTokenKind           = "OPENBAO_DELEGATION_TOKEN"
)

// delegationConfig enables delegation tokens; its absence disables them.
type delegationConfig struct {
	// RenewInterval is how far a renewal pushes the expiry, capped by the
	// token's max date.
	RenewInterval time.Duration `json:"renew_interval"`
	// MaxLifetime bounds the max date baked into every issued token.
	MaxLifetime time.Duration `json:"max_lifetime"`
	// KeyRotationInterval is how often a new signing key replaces the
	// current one.
	KeyRotationInterval time.Duration `json:"key_rotation_interval"`
	// CleanupInterval is how often expired tokens and unreferenced keys
	// are removed.
	CleanupInterval time.Duration `json:"cleanup_interval"`
	// TokenKind is the Hadoop token kind written into every token.
	TokenKind string `json:"token_kind"`
}

func (b *backend) pathConfigDelegation() *framework.Path {
	return &framework.Path{
		Pattern: delegationConfigPath + "$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKerberos,
		},
		Fields: map[string]*framework.FieldSchema{
			"renew_interval": {
				Type:    framework.TypeDurationSecond,
				Default: int(defaultDelegationRenewInterval.Seconds()),
				Description: `How far a renewal extends a token's expiry, capped by its
max date. Also the initial expiry of a new token. Defaults to 24h.`,
			},
			"max_lifetime": {
				Type:    framework.TypeDurationSecond,
				Default: int(defaultDelegationMaxLifetime.Seconds()),
				Description: `Hard lifetime ceiling of an issued token; renewals never
extend a token past it. Defaults to 7d.`,
			},
			"key_rotation_interval": {
				Type:    framework.TypeDurationSecond,
				Default: int(defaultDelegationKeyRotationInterval.Seconds()),
				Description: `How often the signing key is replaced. Old keys are kept
while tokens signed with them exist. Defaults to 24h.`,
			},
			"cleanup_interval": {
				Type:    framework.TypeDurationSecond,
				Default: int(defaultDelegationCleanupInterval.Seconds()),
				Description: `How often expired tokens and unreferenced signing keys are
removed from storage. Defaults to 1h.`,
			},
			"token_kind": {
				Type:    framework.TypeString,
				Default: defaultDelegationTokenKind,
				Description: `Hadoop token kind written into issued tokens and required on
presented ones. Defaults to OPENBAO_DELEGATION_TOKEN.`,
			},
		},
		ExistenceCheck: b.pathConfigDelegationExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigDelegationWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "delegation",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigDelegationWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "delegation",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigDelegationRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "delegation-configuration",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelegationDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "delegation-configuration",
				},
			},
		},

		HelpSynopsis:    confDelegationHelpSynopsis,
		HelpDescription: confDelegationHelpDescription,
	}
}

func (b *backend) delegationConfig(ctx context.Context, s logical.Storage) (*delegationConfig, error) {
	entry, err := s.Get(ctx, delegationConfigPath)
	if err != nil || entry == nil {
		return nil, err
	}
	cfg := &delegationConfig{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (b *backend) pathConfigDelegationExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	cfg, err := b.delegationConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

func (b *backend) pathConfigDelegationRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.delegationConfig(ctx, req.Storage)
	if err != nil || cfg == nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"renew_interval":        int64(cfg.RenewInterval.Seconds()),
			"max_lifetime":          int64(cfg.MaxLifetime.Seconds()),
			"key_rotation_interval": int64(cfg.KeyRotationInterval.Seconds()),
			"cleanup_interval":      int64(cfg.CleanupInterval.Seconds()),
			"token_kind":            cfg.TokenKind,
		},
	}, nil
}

func (b *backend) pathConfigDelegationWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.delegationLock.Lock()
	defer b.delegationLock.Unlock()

	cfg, err := b.delegationConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		// Records left behind by an interrupted purge must not carry over
		// into a fresh configuration.
		if err := b.purgeDelegationRecords(ctx, req.Storage); err != nil {
			return nil, err
		}
		cfg = &delegationConfig{
			RenewInterval:       defaultDelegationRenewInterval,
			MaxLifetime:         defaultDelegationMaxLifetime,
			KeyRotationInterval: defaultDelegationKeyRotationInterval,
			CleanupInterval:     defaultDelegationCleanupInterval,
			TokenKind:           defaultDelegationTokenKind,
		}
	}

	durations := map[string]*time.Duration{
		"renew_interval":        &cfg.RenewInterval,
		"max_lifetime":          &cfg.MaxLifetime,
		"key_rotation_interval": &cfg.KeyRotationInterval,
		"cleanup_interval":      &cfg.CleanupInterval,
	}
	for field, target := range durations {
		raw, ok := d.GetOk(field)
		if !ok {
			continue
		}
		v := time.Duration(raw.(int)) * time.Second
		if v <= 0 {
			return logical.ErrorResponse("%s must be positive", field), logical.ErrInvalidRequest
		}
		*target = v
	}
	if raw, ok := d.GetOk("token_kind"); ok {
		cfg.TokenKind = raw.(string)
	}

	if cfg.TokenKind == "" {
		return logical.ErrorResponse("token_kind must not be empty"), logical.ErrInvalidRequest
	}
	if cfg.RenewInterval > cfg.MaxLifetime {
		return logical.ErrorResponse("renew_interval %s exceeds max_lifetime %s", cfg.RenewInterval, cfg.MaxLifetime), logical.ErrInvalidRequest
	}

	entry, err := logical.StorageEntryJSON(delegationConfigPath, cfg)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

// pathConfigDelegationDelete disables delegation tokens and purges every
// issued token and signing key, so re-enabling starts from a clean state.
// The configuration goes first and on its own, so the feature is off even
// if the purge, which may span many records, is interrupted.
func (b *backend) pathConfigDelegationDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.delegationLock.Lock()
	defer b.delegationLock.Unlock()

	if err := req.Storage.Delete(ctx, delegationConfigPath); err != nil {
		return nil, err
	}
	return nil, b.purgeDelegationRecords(ctx, req.Storage)
}

// purgeDelegationRecords deletes every token, key and counter, one storage
// write per record. Caller holds delegationLock.
func (b *backend) purgeDelegationRecords(ctx context.Context, s logical.Storage) error {
	if err := logical.ClearViewWithLogging(ctx, logical.NewStorageView(s, delegationPrefix), b.Logger()); err != nil {
		return fmt.Errorf("failed to purge delegation token records: %w", err)
	}
	return nil
}

const (
	confDelegationHelpSynopsis    = `Enables Hadoop-style delegation tokens.`
	confDelegationHelpDescription = `
Writing this configuration enables the "delegation/" endpoints and delegation
token logins; deleting it disables them and removes every issued token and
signing key. Delegation tokens are only available while policies are resolved
through roles, that is while "config/ldap" is not set.
`
)
