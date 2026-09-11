// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"strconv"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	delegationStatePath   = delegationPrefix + "state"
	delegationKeyPrefix   = delegationPrefix + "key/"
	delegationTokenPrefix = delegationPrefix + "token/"

	delegationKeyLength       = 32
	delegationCleanupPageSize = 1000
)

// delegationState holds the issuance counters. It is only modified under
// delegationLock.
type delegationState struct {
	NextSequence int32 `json:"next_sequence"`
	CurrentKeyID int32 `json:"current_key_id"`
}

// delegationKey signs token identifiers.
type delegationKey struct {
	ID      int32     `json:"id"`
	Key     []byte    `json:"key"`
	Created time.Time `json:"created"`
	// Expires is set when the key stops being current: the latest max date
	// a token signed with it can carry. Zero while the key is current.
	Expires time.Time `json:"expires,omitempty"`
}

// delegationTokenEntry is the server-side record of an issued token. The
// password is never stored: it is recomputed from the identifier.
type delegationTokenEntry struct {
	Identifier []byte    `json:"identifier"`
	Expiry     time.Time `json:"expiry"`
	Role       string    `json:"role"`
}

func delegationPassword(key, identifier []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(identifier)
	return mac.Sum(nil)
}

func delegationKeyPath(id int32) string {
	return delegationKeyPrefix + strconv.FormatInt(int64(id), 10)
}

func delegationTokenPath(seq int32) string {
	return delegationTokenPrefix + strconv.FormatInt(int64(seq), 10)
}

func (b *backend) delegationState(ctx context.Context, s logical.Storage) (*delegationState, error) {
	state := &delegationState{}
	entry, err := s.Get(ctx, delegationStatePath)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		if err := entry.DecodeJSON(state); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func putJSON(ctx context.Context, s logical.Storage, path string, v interface{}) error {
	entry, err := logical.StorageEntryJSON(path, v)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *backend) delegationKey(ctx context.Context, s logical.Storage, id int32) (*delegationKey, error) {
	entry, err := s.Get(ctx, delegationKeyPath(id))
	if err != nil || entry == nil {
		return nil, err
	}
	key := &delegationKey{}
	if err := entry.DecodeJSON(key); err != nil {
		return nil, err
	}
	return key, nil
}

// rotateDelegationKey retires the current key and makes a fresh random one
// current. Caller holds delegationLock.
func (b *backend) rotateDelegationKey(ctx context.Context, s logical.Storage, cfg *delegationConfig, state *delegationState) (*delegationKey, error) {
	now := b.now()
	if state.CurrentKeyID > 0 {
		old, err := b.delegationKey(ctx, s, state.CurrentKeyID)
		if err != nil {
			return nil, err
		}
		if old != nil {
			old.Expires = now.Add(cfg.MaxLifetime)
			if err := putJSON(ctx, s, delegationKeyPath(old.ID), old); err != nil {
				return nil, err
			}
		}
	}

	key := &delegationKey{
		ID:      state.CurrentKeyID + 1,
		Key:     make([]byte, delegationKeyLength),
		Created: now,
	}
	if _, err := rand.Read(key.Key); err != nil {
		return nil, err
	}
	if err := putJSON(ctx, s, delegationKeyPath(key.ID), key); err != nil {
		return nil, err
	}
	state.CurrentKeyID = key.ID
	if err := putJSON(ctx, s, delegationStatePath, state); err != nil {
		return nil, err
	}
	return key, nil
}

// currentDelegationKey returns the signing key in use, creating the first
// one on demand. Caller holds delegationLock.
func (b *backend) currentDelegationKey(ctx context.Context, s logical.Storage, cfg *delegationConfig, state *delegationState) (*delegationKey, error) {
	if state.CurrentKeyID > 0 {
		key, err := b.delegationKey(ctx, s, state.CurrentKeyID)
		if err != nil || key != nil {
			return key, err
		}
	}
	return b.rotateDelegationKey(ctx, s, cfg, state)
}

func (b *backend) delegationTokenEntry(ctx context.Context, s logical.Storage, seq int32) (*delegationTokenEntry, error) {
	entry, err := s.Get(ctx, delegationTokenPath(seq))
	if err != nil || entry == nil {
		return nil, err
	}
	tok := &delegationTokenEntry{}
	if err := entry.DecodeJSON(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// issueDelegationToken signs a new token for owner with the current key and
// records it. Caller holds delegationLock.
func (b *backend) issueDelegationToken(ctx context.Context, s logical.Storage, cfg *delegationConfig, owner, renewer, service, role string, maxLifetime time.Duration) (*delegationToken, *delegationTokenIdentifier, *delegationTokenEntry, error) {
	state, err := b.delegationState(ctx, s)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := b.currentDelegationKey(ctx, s, cfg, state)
	if err != nil {
		return nil, nil, nil, err
	}

	if maxLifetime <= 0 || maxLifetime > cfg.MaxLifetime {
		maxLifetime = cfg.MaxLifetime
	}
	now := b.now()
	seq := state.NextSequence
	if seq <= 0 {
		seq = 1
	}
	id := &delegationTokenIdentifier{
		Owner:          owner,
		Renewer:        renewer,
		IssueDate:      now.UnixMilli(),
		MaxDate:        now.Add(maxLifetime).UnixMilli(),
		SequenceNumber: seq,
		MasterKeyID:    key.ID,
	}
	entry := &delegationTokenEntry{
		Identifier: id.marshal(),
		Expiry:     delegationExpiry(now, cfg, id),
		Role:       role,
	}
	if err := putJSON(ctx, s, delegationTokenPath(seq), entry); err != nil {
		return nil, nil, nil, err
	}
	state.NextSequence = seq + 1
	if err := putJSON(ctx, s, delegationStatePath, state); err != nil {
		return nil, nil, nil, err
	}

	tok := &delegationToken{
		Identifier: entry.Identifier,
		Password:   delegationPassword(key.Key, entry.Identifier),
		Kind:       cfg.TokenKind,
		Service:    service,
	}
	return tok, id, entry, nil
}

// delegationExpiry is the renewable deadline reached from now: one renew
// interval ahead, never past the identifier's max date.
func delegationExpiry(now time.Time, cfg *delegationConfig, id *delegationTokenIdentifier) time.Time {
	expiry := now.Add(cfg.RenewInterval)
	if maxDate := time.UnixMilli(id.MaxDate); expiry.After(maxDate) {
		expiry = maxDate
	}
	return expiry
}

// verifyDelegationToken checks a presented token against the signing key
// and the stored record as of now. A valid signature alone is not enough:
// the record must exist and match, which is what makes cancel and expiry
// effective. On failure the response and error to return are set.
func (b *backend) verifyDelegationToken(ctx context.Context, s logical.Storage, cfg *delegationConfig, urlString string, now time.Time) (*delegationTokenIdentifier, *delegationTokenEntry, *logical.Response, error) {
	tok, err := decodeURLString(urlString)
	if err != nil {
		return nil, nil, logical.ErrorResponse("invalid delegation token: %v", err), logical.ErrInvalidRequest
	}
	if tok.Kind != cfg.TokenKind {
		return nil, nil, logical.ErrorResponse("delegation token kind %q is not %q", tok.Kind, cfg.TokenKind), logical.ErrInvalidRequest
	}
	id, err := unmarshalIdentifier(tok.Identifier)
	if err != nil {
		return nil, nil, logical.ErrorResponse("invalid delegation token identifier: %v", err), logical.ErrInvalidRequest
	}

	key, err := b.delegationKey(ctx, s, id.MasterKeyID)
	if err != nil {
		return nil, nil, nil, err
	}
	if key == nil || !hmac.Equal(tok.Password, delegationPassword(key.Key, tok.Identifier)) {
		return nil, nil, logical.ErrorResponse("delegation token signature is invalid"), logical.ErrPermissionDenied
	}

	entry, err := b.delegationTokenEntry(ctx, s, id.SequenceNumber)
	if err != nil {
		return nil, nil, nil, err
	}
	if entry == nil || !hmac.Equal(entry.Identifier, tok.Identifier) {
		return nil, nil, logical.ErrorResponse("delegation token %d is not known; it may have been cancelled", id.SequenceNumber), logical.ErrPermissionDenied
	}
	if !now.Before(entry.Expiry) {
		return nil, nil, logical.ErrorResponse("delegation token %d has expired", id.SequenceNumber), logical.ErrPermissionDenied
	}
	return id, entry, nil, nil
}

// periodicDelegation rotates the signing key when due and, every cleanup
// interval, prunes retired keys and expired tokens. Only the key work runs
// under delegationLock; the token scan may be long and needs no lock, since
// an expired record is never renewed.
func (b *backend) periodicDelegation(ctx context.Context, req *logical.Request) error {
	s := req.Storage
	cleanup, err := b.rotateAndPruneKeys(ctx, s)
	if err != nil || !cleanup {
		return err
	}
	return b.expireDelegationTokens(ctx, s)
}

func (b *backend) rotateAndPruneKeys(ctx context.Context, s logical.Storage) (bool, error) {
	b.delegationLock.Lock()
	defer b.delegationLock.Unlock()

	cfg, err := b.delegationConfig(ctx, s)
	if err != nil || cfg == nil {
		return false, err
	}
	state, err := b.delegationState(ctx, s)
	if err != nil {
		return false, err
	}
	key, err := b.currentDelegationKey(ctx, s, cfg, state)
	if err != nil {
		return false, err
	}
	now := b.now()
	if now.Sub(key.Created) >= cfg.KeyRotationInterval {
		if _, err := b.rotateDelegationKey(ctx, s, cfg, state); err != nil {
			return false, err
		}
	}

	if now.Sub(b.lastCleanup) < cfg.CleanupInterval {
		return false, nil
	}
	b.lastCleanup = now
	return true, b.pruneDelegationKeys(ctx, s, cfg, state, now)
}

// pruneDelegationKeys deletes retired keys past the max date of the last
// token they could have signed. Caller holds delegationLock.
func (b *backend) pruneDelegationKeys(ctx context.Context, s logical.Storage, cfg *delegationConfig, state *delegationState, now time.Time) error {
	names, err := s.ListPage(ctx, delegationKeyPrefix, "", -1)
	if err != nil {
		return err
	}
	for _, name := range names {
		id, err := strconv.ParseInt(name, 10, 32)
		if err != nil || int32(id) == state.CurrentKeyID {
			continue
		}
		key, err := b.delegationKey(ctx, s, int32(id))
		if err != nil {
			return err
		}
		if key == nil {
			continue
		}
		expires := key.Expires
		if expires.IsZero() {
			// Never retired: an orphan from an interrupted rotation, which
			// signed nothing after the rotation interval.
			expires = key.Created.Add(cfg.KeyRotationInterval + cfg.MaxLifetime)
		}
		if now.After(expires) {
			if err := s.Delete(ctx, delegationKeyPath(int32(id))); err != nil {
				return err
			}
		}
	}
	return nil
}

// expireDelegationTokens deletes token records past their expiry, one page
// at a time.
func (b *backend) expireDelegationTokens(ctx context.Context, s logical.Storage) error {
	now := b.now()
	after := ""
	for {
		names, err := s.ListPage(ctx, delegationTokenPrefix, after, delegationCleanupPageSize)
		if err != nil {
			return err
		}
		for _, name := range names {
			seq, err := strconv.ParseInt(name, 10, 32)
			if err != nil {
				continue
			}
			entry, err := b.delegationTokenEntry(ctx, s, int32(seq))
			if err != nil {
				return err
			}
			if entry != nil && !now.Before(entry.Expiry) {
				if err := s.Delete(ctx, delegationTokenPath(int32(seq))); err != nil {
					return err
				}
			}
		}
		if len(names) < delegationCleanupPageSize {
			return nil
		}
		after = names[len(names)-1]
	}
}
