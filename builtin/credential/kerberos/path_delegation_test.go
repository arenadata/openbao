// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/keytab"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	testRenewInterval = time.Hour
	testMaxLifetime   = 2 * time.Hour
	testKeyRotation   = 30 * time.Minute
	testCleanup       = 10 * time.Minute
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time              { return c.t }
func (c *fakeClock) advance(d time.Duration)     { c.t = c.t.Add(d) }
func (c *fakeClock) after(d time.Duration) int64 { return c.t.Add(d).UnixMilli() }

// delegationHarness is a configured backend with roles, delegation tokens
// enabled and a controllable clock.
type delegationHarness struct {
	t       *testing.T
	b       *backend
	storage logical.Storage
	kt      *keytab.Keytab
	clock   *fakeClock
}

func newDelegationHarness(t *testing.T) *delegationHarness {
	t.Helper()
	storage := &logical.InmemStorage{}
	b := Backend()
	clock := &fakeClock{t: time.Now().Truncate(time.Millisecond)}
	b.now = clock.now
	if err := b.Setup(context.Background(), &logical.BackendConfig{
		System:      &logical.StaticSystemView{DefaultLeaseTTLVal: 12 * time.Hour, MaxLeaseTTLVal: 24 * time.Hour},
		StorageView: storage,
	}); err != nil {
		t.Fatal(err)
	}

	kt, ktB64 := testKeytab(t)
	mustRequest(t, b, storage, logical.UpdateOperation, configPath, map[string]interface{}{
		"keytab":          ktB64,
		"service_account": testServiceSPN,
	})
	writeRole(t, b, storage, "hadoop", map[string]interface{}{
		"bound_principals": "hadoop/*@" + testRealm,
		"token_policies":   "hadoop-keys",
		"token_ttl":        300,
	})
	writeRole(t, b, storage, "users", map[string]interface{}{
		"bound_principals": "alice@" + testRealm + ",bob@" + testRealm,
		"token_policies":   "user-keys",
	})
	mustRequest(t, b, storage, logical.UpdateOperation, delegationConfigPath, map[string]interface{}{
		"renew_interval":        int(testRenewInterval.Seconds()),
		"max_lifetime":          int(testMaxLifetime.Seconds()),
		"key_rotation_interval": int(testKeyRotation.Seconds()),
		"cleanup_interval":      int(testCleanup.Seconds()),
	})
	return &delegationHarness{t: t, b: b, storage: storage, kt: kt, clock: clock}
}

// spnego sends an update to path authenticated as principal.
func (h *delegationHarness) spnego(principal, path string, data map[string]interface{}) (*logical.Response, error) {
	h.t.Helper()
	return h.spnegoRealm(principal, testRealm, path, data)
}

func (h *delegationHarness) spnegoRealm(principal, realm, path string, data map[string]interface{}) (*logical.Response, error) {
	h.t.Helper()
	if data == nil {
		data = map[string]interface{}{}
	}
	return h.b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       path,
		Storage:    h.storage,
		Data:       data,
		Headers:    map[string][]string{"Authorization": {mintNegotiateRealm(h.t, h.kt, principal, realm)}},
		Connection: &logical.Connection{RemoteAddr: "10.1.2.3"},
	})
}

func (h *delegationHarness) issue(principal string, data map[string]interface{}) *logical.Response {
	h.t.Helper()
	resp, err := h.spnego(principal, delegationTokenPathName, data)
	if err != nil || resp == nil || resp.IsError() || resp.Data["token"] == nil {
		h.t.Fatalf("issue: err %v resp %#v", err, resp)
	}
	return resp
}

func (h *delegationHarness) login(token string, data map[string]interface{}) (*logical.Response, error) {
	h.t.Helper()
	return h.loginFrom("10.9.9.9", token, data)
}

func (h *delegationHarness) loginFrom(remoteAddr, token string, data map[string]interface{}) (*logical.Response, error) {
	h.t.Helper()
	if data == nil {
		data = map[string]interface{}{}
	}
	data["delegation_token"] = token
	return h.b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Storage:    h.storage,
		Data:       data,
		Connection: &logical.Connection{RemoteAddr: remoteAddr},
	})
}

func (h *delegationHarness) periodic() {
	h.t.Helper()
	if err := h.b.periodicDelegation(context.Background(), &logical.Request{Storage: h.storage}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *delegationHarness) list(prefix string) []string {
	h.t.Helper()
	keys, err := h.storage.List(context.Background(), prefix)
	if err != nil {
		h.t.Fatal(err)
	}
	return keys
}

func assertDenied(t *testing.T, name string, resp *logical.Response, err error, want error, msg string) {
	t.Helper()
	if !errors.Is(err, want) || resp == nil || !resp.IsError() {
		t.Fatalf("%s: expected %v, got err %v resp %#v", name, want, err, resp)
	}
	if got := resp.Error().Error(); !strings.Contains(got, msg) {
		t.Fatalf("%s: expected message containing %q, got %q", name, msg, got)
	}
}

func TestDelegation_IssueLoginRenewCancel(t *testing.T) {
	h := newDelegationHarness(t)
	owner := "hadoop/nn1.example.com@" + testRealm

	resp := h.issue("hadoop/nn1.example.com", map[string]interface{}{
		"renewer": "yarn",
		"service": "openbao.example.com:8200",
	})
	want := map[string]interface{}{
		"kind":            defaultDelegationTokenKind,
		"service":         "openbao.example.com:8200",
		"owner":           owner,
		"real_user":       "",
		"renewer":         "yarn",
		"issue_date":      h.clock.now().UnixMilli(),
		"max_date":        h.clock.after(testMaxLifetime),
		"expiry":          h.clock.after(testRenewInterval),
		"sequence_number": int32(1),
		"master_key_id":   int32(1),
		"role":            "hadoop",
	}
	for k, v := range want {
		if got := resp.Data[k]; !reflect.DeepEqual(got, v) {
			t.Errorf("issue %s: got %#v want %#v", k, got, v)
		}
	}
	urlString := resp.Data["token"].(string)
	tok, err := decodeURLString(urlString)
	if err != nil {
		t.Fatal(err)
	}
	id, err := unmarshalIdentifier(tok.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	if id.Owner != owner || id.Renewer != "yarn" || id.RealUser != "" || id.SequenceNumber != 1 || id.MasterKeyID != 1 ||
		id.IssueDate != want["issue_date"] || id.MaxDate != want["max_date"] || tok.Kind != defaultDelegationTokenKind || tok.Service != "openbao.example.com:8200" {
		t.Fatalf("decoded token %+v identifier %+v", tok, id)
	}

	// The holder logs in as the owner with the role fixed at issuance; the
	// OpenBao token cannot outlive the delegation token's expiry.
	resp, err = h.login(urlString, nil)
	if err != nil || resp == nil || resp.IsError() || resp.Auth == nil {
		t.Fatalf("login: err %v resp %#v", err, resp)
	}
	auth := resp.Auth
	if !reflect.DeepEqual(auth.Policies, []string{"hadoop-keys"}) || auth.TTL.Seconds() != 300 || auth.ExplicitMaxTTL != testRenewInterval ||
		auth.Alias.Name != owner || auth.Metadata["role"] != "hadoop" || auth.Metadata["delegation_token"] != "1" || auth.Metadata["user"] != "hadoop/nn1.example.com" || auth.Metadata["domain"] != testRealm {
		t.Fatalf("login auth: %+v", auth)
	}
	auth.TokenPolicies = auth.Policies
	renewReq := logical.RenewAuthRequest("login", auth, nil)
	renewReq.Storage = h.storage
	if resp, err := h.b.HandleRequest(context.Background(), renewReq); err != nil || resp == nil || resp.IsError() || resp.Auth == nil {
		t.Fatalf("token renew: err %v resp %#v", err, resp)
	}

	resp, err = h.login(urlString, map[string]interface{}{"role": "hadoop"})
	assertDenied(t, "login with role", resp, err, logical.ErrInvalidRequest, "role is not applicable")

	resp, err = h.b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Storage:    h.storage,
		Data:       map[string]interface{}{"delegation_token": urlString},
		Headers:    map[string][]string{"Authorization": {mintNegotiate(t, h.kt, "alice")}},
		Connection: &logical.Connection{RemoteAddr: "10.9.9.9"},
	})
	assertDenied(t, "login with both credentials", resp, err, logical.ErrInvalidRequest, "cannot be combined")

	// Renewal is reserved for the renewer, matched by primary name within
	// the owner's realm only.
	h.clock.advance(20 * time.Minute)
	resp, err = h.spnego("alice", delegationRenewPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "renew by stranger", resp, err, logical.ErrPermissionDenied, "is not the renewer")
	resp, err = h.spnegoRealm("yarn/rm.other.example", "OTHER.REALM", delegationRenewPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "renew from foreign realm", resp, err, logical.ErrPermissionDenied, "is not the renewer")
	resp, err = h.spnegoRealm("yarn", "OTHER.REALM", delegationCancelPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "cancel from foreign realm", resp, err, logical.ErrPermissionDenied, "neither the owner nor the renewer")
	resp, err = h.spnego("yarn/rm.example.com", delegationRenewPathName, map[string]interface{}{"token": urlString})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("renew: err %v resp %#v", err, resp)
	}
	if got := resp.Data["expiry"]; got != h.clock.after(testRenewInterval) {
		t.Fatalf("renew expiry: got %v want %v", got, h.clock.after(testRenewInterval))
	}

	// Renewal never passes the max date.
	h.clock.advance(50 * time.Minute)
	resp, err = h.spnego("yarn", delegationRenewPathName, map[string]interface{}{"token": urlString})
	if err != nil || resp == nil || resp.IsError() || resp.Data["expiry"] != want["max_date"] {
		t.Fatalf("renew near max date: err %v resp %#v", err, resp)
	}

	// Cancel: owner or renewer only, and it takes effect immediately.
	resp, err = h.spnego("alice", delegationCancelPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "cancel by stranger", resp, err, logical.ErrPermissionDenied, "neither the owner nor the renewer")
	if resp, err := h.spnego("yarn/rm.example.com", delegationCancelPathName, map[string]interface{}{"token": urlString}); err != nil || resp != nil {
		t.Fatalf("cancel: err %v resp %#v", err, resp)
	}
	resp, err = h.login(urlString, nil)
	assertDenied(t, "login after cancel", resp, err, logical.ErrPermissionDenied, "may have been cancelled")
	resp, err = h.spnego("yarn", delegationRenewPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "renew after cancel", resp, err, logical.ErrPermissionDenied, "may have been cancelled")
	if resp, err := h.b.HandleRequest(context.Background(), renewReq); err == nil {
		t.Fatalf("token renew after cancel: expected error, got %#v", resp)
	}
	if got := h.list(delegationTokenPrefix); len(got) != 0 {
		t.Fatalf("token records after cancel: %v", got)
	}
}

func TestDelegation_Rejections(t *testing.T) {
	h := newDelegationHarness(t)

	resp, err := h.b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       delegationTokenPathName,
		Storage:    h.storage,
		Data:       map[string]interface{}{"authorization": ""},
		Connection: &logical.Connection{RemoteAddr: "10.1.2.3"},
	})
	assertNegotiateChallenge(t, "issue without negotiate", resp, err)

	resp, err = h.spnego("alice", delegationTokenPathName, map[string]interface{}{"role": "hadoop"})
	assertDenied(t, "issue with unbound role", resp, err, logical.ErrPermissionDenied, "is not bound to principal")
	resp, err = h.spnego("carol", delegationTokenPathName, nil)
	assertDenied(t, "issue for unbound principal", resp, err, logical.ErrPermissionDenied, "no role is bound")

	urlString := h.issue("alice", map[string]interface{}{"renewer": "yarn"}).Data["token"].(string)
	tok, err := decodeURLString(urlString)
	if err != nil {
		t.Fatal(err)
	}

	forged := *tok
	forged.Password = append([]byte{}, tok.Password...)
	forged.Password[0] ^= 1
	resp, err = h.login(forged.encodeURLString(), nil)
	assertDenied(t, "forged password", resp, err, logical.ErrPermissionDenied, "signature is invalid")

	id, _ := unmarshalIdentifier(tok.Identifier)
	id.Owner = "bob@" + testRealm
	forged = *tok
	forged.Identifier = id.marshal()
	resp, err = h.login(forged.encodeURLString(), nil)
	assertDenied(t, "forged owner", resp, err, logical.ErrPermissionDenied, "signature is invalid")

	forged = *tok
	forged.Kind = "HDFS_DELEGATION_TOKEN"
	resp, err = h.login(forged.encodeURLString(), nil)
	assertDenied(t, "foreign kind", resp, err, logical.ErrInvalidRequest, "kind")

	resp, err = h.login("not a token", nil)
	assertDenied(t, "garbage", resp, err, logical.ErrInvalidRequest, "invalid delegation token")

	// A non-renewable token can still be cancelled by its owner.
	plain := h.issue("alice", nil).Data["token"].(string)
	resp, err = h.spnego("alice", delegationRenewPathName, map[string]interface{}{"token": plain})
	assertDenied(t, "renew non-renewable", resp, err, logical.ErrPermissionDenied, "has no renewer")
	if resp, err := h.spnego("alice", delegationCancelPathName, map[string]interface{}{"token": plain}); err != nil || resp != nil {
		t.Fatalf("owner cancel: err %v resp %#v", err, resp)
	}

	// The requested max lifetime is honoured below the configured ceiling
	// and bounds the initial expiry.
	resp = h.issue("alice", map[string]interface{}{"max_lifetime": 600})
	if resp.Data["max_date"] != h.clock.after(10*time.Minute) || resp.Data["expiry"] != h.clock.after(10*time.Minute) {
		t.Fatalf("short max_lifetime: %#v", resp.Data)
	}
	resp = h.issue("alice", map[string]interface{}{"max_lifetime": int(testMaxLifetime.Seconds()) * 10})
	if resp.Data["max_date"] != h.clock.after(testMaxLifetime) {
		t.Fatalf("capped max_lifetime: %#v", resp.Data)
	}

	// Expiry without renewal denies login and derived token renewal.
	short := h.issue("alice", map[string]interface{}{"renewer": "yarn"})
	resp, err = h.login(short.Data["token"].(string), nil)
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login: err %v resp %#v", err, resp)
	}
	derived := resp.Auth
	derived.TokenPolicies = derived.Policies
	h.clock.t = time.UnixMilli(short.Data["expiry"].(int64))
	resp, err = h.login(short.Data["token"].(string), nil)
	assertDenied(t, "login at expiry", resp, err, logical.ErrPermissionDenied, "has expired")
	h.clock.advance(time.Second)
	resp, err = h.login(short.Data["token"].(string), nil)
	assertDenied(t, "expired login", resp, err, logical.ErrPermissionDenied, "has expired")
	resp, err = h.spnego("yarn", delegationRenewPathName, map[string]interface{}{"token": short.Data["token"].(string)})
	assertDenied(t, "expired renew", resp, err, logical.ErrPermissionDenied, "has expired")
	renewReq := logical.RenewAuthRequest("login", derived, nil)
	renewReq.Storage = h.storage
	if _, err := h.b.HandleRequest(context.Background(), renewReq); err == nil || !strings.Contains(err.Error(), "has expired") {
		t.Fatalf("derived token renew after expiry: %v", err)
	}
}

func TestDelegation_Availability(t *testing.T) {
	h := newDelegationHarness(t)
	urlString := h.issue("alice", nil).Data["token"].(string)

	mustRequest(t, h.b, h.storage, logical.UpdateOperation, ldapConfPath, map[string]interface{}{"url": "ldap://127.0.0.1:1", "token_bound_cidrs": "10.0.0.0/8"})
	resp, err := h.spnego("alice", delegationTokenPathName, nil)
	assertDenied(t, "issue with ldap", resp, err, logical.ErrInvalidRequest, "config/ldap is set")
	resp, err = h.login(urlString, nil)
	assertDenied(t, "login with ldap", resp, err, logical.ErrInvalidRequest, "config/ldap is set")
	// The LDAP CIDR gate applies before the delegation branch is reached.
	if resp, err := h.loginFrom("203.0.113.5", urlString, nil); !errors.Is(err, logical.ErrPermissionDenied) || resp != nil {
		t.Fatalf("login with ldap outside cidrs: err %v resp %#v", err, resp)
	}
	mustRequest(t, h.b, h.storage, logical.DeleteOperation, ldapConfPath, nil)

	resp, err = h.login(urlString, nil)
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login after ldap removal: err %v resp %#v", err, resp)
	}
	derived := resp.Auth
	derived.TokenPolicies = derived.Policies

	// Disabling purges every record; re-enabling starts clean.
	mustRequest(t, h.b, h.storage, logical.DeleteOperation, delegationConfigPath, nil)
	resp, err = h.b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       delegationTokenPathName,
		Storage:    h.storage,
		Data:       map[string]interface{}{"authorization": ""},
		Connection: &logical.Connection{RemoteAddr: "10.1.2.3"},
	})
	assertNegotiateChallenge(t, "issue disabled without negotiate", resp, err)
	if mustRequest(t, h.b, h.storage, logical.ReadOperation, delegationConfigPath, nil) != nil {
		t.Fatal("delegation config still present")
	}
	resp, err = h.login(urlString, nil)
	assertDenied(t, "login disabled", resp, err, logical.ErrInvalidRequest, "not enabled")
	resp, err = h.spnego("alice", delegationTokenPathName, nil)
	assertDenied(t, "issue disabled", resp, err, logical.ErrInvalidRequest, "not enabled")
	if got := h.list(delegationPrefix); len(got) != 0 {
		t.Fatalf("records after disable: %v", got)
	}

	mustRequest(t, h.b, h.storage, logical.UpdateOperation, delegationConfigPath, nil)
	resp = mustRequest(t, h.b, h.storage, logical.ReadOperation, delegationConfigPath, nil)
	if resp.Data["renew_interval"] != int64(defaultDelegationRenewInterval.Seconds()) || resp.Data["token_kind"] != defaultDelegationTokenKind {
		t.Fatalf("defaults: %#v", resp.Data)
	}
	resp, err = h.login(urlString, nil)
	assertDenied(t, "old token after re-enable", resp, err, logical.ErrPermissionDenied, "signature is invalid")
	if got := h.issue("alice", nil).Data["sequence_number"]; got != int32(1) {
		t.Fatalf("sequence after re-enable: %v", got)
	}
	// The OpenBao token from the purged token #1 does not renew against
	// the new token #1.
	renewReq := logical.RenewAuthRequest("login", derived, nil)
	renewReq.Storage = h.storage
	if _, err := h.b.HandleRequest(context.Background(), renewReq); err == nil || !strings.Contains(err.Error(), "has been cancelled") {
		t.Fatalf("derived token renew after purge: %v", err)
	}

	for name, data := range map[string]map[string]interface{}{
		"zero":        {"renew_interval": 0},
		"renew > max": {"renew_interval": 10, "max_lifetime": 5},
		"empty kind":  {"token_kind": ""},
	} {
		resp, err := doRequest(t, h.b, h.storage, logical.UpdateOperation, delegationConfigPath, data)
		assertDenied(t, "config "+name, resp, err, logical.ErrInvalidRequest, "")
	}
}

func TestDelegation_KeyRotationAndCleanup(t *testing.T) {
	h := newDelegationHarness(t)

	first := h.issue("alice", nil).Data["token"].(string)
	h.clock.advance(testKeyRotation)
	h.periodic()
	if got := h.list(delegationKeyPrefix); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Fatalf("keys after rotation: %v", got)
	}

	// Tokens signed with the previous key stay valid; new ones use the new key.
	if resp, err := h.login(first, nil); err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login with old key: err %v resp %#v", err, resp)
	}
	second := h.issue("alice", nil)
	if second.Data["master_key_id"] != int32(2) {
		t.Fatalf("new token key: %#v", second.Data)
	}

	// Once the first token expires, cleanup drops it; the retired key stays
	// until the last token it could have signed is past its max date. The
	// rotation due at the same tick adds a third key.
	h.clock.advance(testRenewInterval - testKeyRotation + time.Second)
	h.periodic()
	if got := h.list(delegationTokenPrefix); !reflect.DeepEqual(got, []string{"2"}) {
		t.Fatalf("tokens after cleanup: %v", got)
	}
	if got := h.list(delegationKeyPrefix); !reflect.DeepEqual(got, []string{"1", "2", "3"}) {
		t.Fatalf("keys after cleanup: %v", got)
	}
	resp, err := h.login(first, nil)
	assertDenied(t, "login after cleanup", resp, err, logical.ErrPermissionDenied, "may have been cancelled")
	if resp, err := h.login(second.Data["token"].(string), nil); err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login with surviving token: err %v resp %#v", err, resp)
	}

	// Key 1 was retired at t0+30m and outlives any token it signed by
	// max_lifetime; past that it is pruned. Key 2 retired later and stays.
	h.clock.advance(testMaxLifetime - testRenewInterval + testKeyRotation)
	h.periodic()
	if got := h.list(delegationKeyPrefix); !reflect.DeepEqual(got, []string{"2", "3", "4"}) {
		t.Fatalf("keys after key expiry: %v", got)
	}
	if got := h.list(delegationTokenPrefix); len(got) != 0 {
		t.Fatalf("tokens after key expiry: %v", got)
	}
	resp, err = h.login(first, nil)
	assertDenied(t, "login after key pruned", resp, err, logical.ErrPermissionDenied, "signature is invalid")
}

// hookedStorage runs a callback the first time key is read, standing in for
// a write that lands between the cleanup scan's read and its delete.
type hookedStorage struct {
	logical.Storage

	key  string
	once func()
}

func (s *hookedStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	entry, err := s.Storage.Get(ctx, key)
	if key == s.key && s.once != nil {
		fire := s.once
		s.once = nil
		fire()
	}
	return entry, err
}

func TestDelegation_CleanupKeepsRenewedToken(t *testing.T) {
	h := newDelegationHarness(t)
	ctx := context.Background()
	urlString := h.issue("alice", map[string]interface{}{"renewer": "yarn"}).Data["token"].(string)
	h.clock.advance(testRenewInterval + time.Second)

	path := delegationTokenPath(1)
	scanned := false
	storage := &hookedStorage{Storage: h.storage, key: path, once: func() {
		entry, err := h.b.delegationTokenEntry(ctx, h.storage, 1)
		if err != nil || entry == nil {
			t.Fatalf("token record during scan: err %v entry %#v", err, entry)
		}
		entry.Expiry = h.clock.now().Add(testRenewInterval)
		if err := putJSON(ctx, h.storage, path, entry); err != nil {
			t.Fatal(err)
		}
		scanned = true
	}}

	if err := h.b.periodicDelegation(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatal(err)
	}
	if !scanned {
		t.Fatal("cleanup never read the token record")
	}
	if got := h.list(delegationTokenPrefix); !reflect.DeepEqual(got, []string{"1"}) {
		t.Fatalf("renewed token was deleted: %v", got)
	}
	if resp, err := h.login(urlString, nil); err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login after cleanup: err %v resp %#v", err, resp)
	}
}

func TestDelegation_KeyOutlivesTokensAfterShorterMaxLifetime(t *testing.T) {
	h := newDelegationHarness(t)
	urlString := h.issue("alice", nil).Data["token"].(string)

	// Shortening the configured lifetimes must not retire the key ahead of
	// the tokens it already signed.
	h.clock.advance(5 * time.Minute)
	mustRequest(t, h.b, h.storage, logical.UpdateOperation, delegationConfigPath, map[string]interface{}{
		"renew_interval": 300,
		"max_lifetime":   600,
	})

	h.clock.advance(testKeyRotation - 5*time.Minute)
	h.periodic()
	if got := h.list(delegationKeyPrefix); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Fatalf("keys after rotation: %v", got)
	}

	h.clock.advance(15 * time.Minute)
	h.periodic()
	if got := h.list(delegationKeyPrefix); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Fatalf("signing key of a live token was pruned: %v", got)
	}
	if resp, err := h.login(urlString, nil); err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login after key pruning: err %v resp %#v", err, resp)
	}
}

func TestDelegation_CallerMatches(t *testing.T) {
	rm := testIdentity("yarn/rm.example.com", testRealm)
	for name, want := range map[string]bool{
		"yarn": true, "yarn/rm.example.com": true, "yarn/rm.example.com@" + testRealm: true,
		"yarn2": false, "rm.example.com": false, "yarn@" + testRealm: false, "": false,
	} {
		if got := callerMatches(rm, name, testRealm); got != want {
			t.Errorf("callerMatches(%q) = %v", name, got)
		}
	}
	if !callerMatches(testIdentity("alice", testRealm), "alice", testRealm) || callerMatches(testIdentity("alice", testRealm), "alice/x", testRealm) {
		t.Error("plain principal matching")
	}

	// Short forms are honoured only inside the owner's realm; the full
	// principal always is.
	foreign := testIdentity("yarn/rm.example.com", "OTHER.REALM")
	for name, want := range map[string]bool{
		"yarn": false, "yarn/rm.example.com": false, "yarn/rm.example.com@OTHER.REALM": true,
	} {
		if got := callerMatches(foreign, name, testRealm); got != want {
			t.Errorf("foreign callerMatches(%q) = %v", name, got)
		}
	}
}

// writeProxyRole binds hive/* to a role allowed to impersonate alice and
// carol; carol is bound to no role of her own.
func (h *delegationHarness) writeProxyRole() {
	h.t.Helper()
	writeRole(h.t, h.b, h.storage, "hive", map[string]interface{}{
		"bound_principals":         "hive/*@" + testRealm,
		"allowed_proxy_principals": "alice@" + testRealm + ",carol@" + testRealm,
		"token_policies":           "hive-keys",
	})
}

func (h *delegationHarness) identifier(urlString string) *delegationTokenIdentifier {
	h.t.Helper()
	tok, err := decodeURLString(urlString)
	if err != nil {
		h.t.Fatal(err)
	}
	id, err := unmarshalIdentifier(tok.Identifier)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

// renewAuth renews an OpenBao token logged in with a delegation token.
func (h *delegationHarness) renewAuth(auth *logical.Auth) (*logical.Response, error) {
	h.t.Helper()
	auth.TokenPolicies = auth.Policies
	req := logical.RenewAuthRequest("login", auth, nil)
	req.Storage = h.storage
	return h.b.HandleRequest(context.Background(), req)
}

func TestDelegation_DoAs(t *testing.T) {
	h := newDelegationHarness(t)
	h.writeProxyRole()
	ctx := context.Background()
	hive := "hive/hs2.example.com@" + testRealm
	alice := "alice@" + testRealm

	// A name without a realm is in the caller's realm. The impersonated
	// principal owns the token, with the role bound to it; the caller is the
	// real user and its role is recorded as the grant.
	resp := h.issue("hive/hs2.example.com", map[string]interface{}{"doas": "alice", "renewer": "yarn"})
	if resp.Data["owner"] != alice || resp.Data["real_user"] != hive || resp.Data["role"] != "users" {
		t.Fatalf("issue: %#v", resp.Data)
	}
	urlString := resp.Data["token"].(string)
	if id := h.identifier(urlString); id.Owner != alice || id.RealUser != hive || id.Renewer != "yarn" {
		t.Fatalf("identifier %+v", id)
	}
	if entry, err := h.b.delegationTokenEntry(ctx, h.storage, 1); err != nil || entry == nil || entry.Role != "users" || entry.ProxyRole != "hive" {
		t.Fatalf("token record: err %v entry %+v", err, entry)
	}

	resp, err := h.login(urlString, nil)
	if err != nil || resp == nil || resp.IsError() || resp.Auth == nil {
		t.Fatalf("login: err %v resp %#v", err, resp)
	}
	auth := resp.Auth
	if !reflect.DeepEqual(auth.Policies, []string{"user-keys"}) || auth.Alias.Name != alice || auth.Metadata["user"] != "alice" ||
		auth.Metadata["role"] != "users" || auth.Metadata["real_user"] != hive {
		t.Fatalf("login auth: %+v", auth)
	}
	if resp, err := h.renewAuth(auth); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("token renew: err %v resp %#v", err, resp)
	}

	// Once the recorded role stops listing the owner, the token can neither
	// log in nor be renewed, and neither can OpenBao tokens from it, even
	// while another role would grant the impersonation.
	writeRole(t, h.b, h.storage, "hive", map[string]interface{}{"allowed_proxy_principals": "carol@" + testRealm})
	writeRole(t, h.b, h.storage, "hive-other", map[string]interface{}{
		"bound_principals":         "hive/*@" + testRealm,
		"allowed_proxy_principals": alice,
	})
	revoked := `real user "` + hive + `" of delegation token 1 may no longer impersonate "` + alice + `"`
	resp, err = h.login(urlString, nil)
	assertDenied(t, "login after revocation", resp, err, logical.ErrPermissionDenied, revoked)
	if _, err := h.renewAuth(auth); err == nil || !strings.Contains(err.Error(), revoked) {
		t.Fatalf("token renew after revocation: %v", err)
	}
	resp, err = h.spnego("yarn/rm.example.com", delegationRenewPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "renew after revocation", resp, err, logical.ErrPermissionDenied, revoked)
	mustRequest(t, h.b, h.storage, logical.DeleteOperation, "roles/hive-other", nil)
	resp, err = h.spnego("hive/hs2.example.com", delegationTokenPathName, map[string]interface{}{"doas": "alice"})
	assertDenied(t, "issue after revocation", resp, err, logical.ErrPermissionDenied, "does not allow impersonating")

	h.writeProxyRole()
	if resp, err := h.login(urlString, nil); err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login after restoring: err %v resp %#v", err, resp)
	}
	if resp, err := h.spnego("yarn/rm.example.com", delegationRenewPathName, map[string]interface{}{"token": urlString}); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("renew after restoring: err %v resp %#v", err, resp)
	}
	resp, err = h.spnego("hive/hs2.example.com", delegationRenewPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "renew by real user", resp, err, logical.ErrPermissionDenied, "is not the renewer")

	// Besides the owner and the renewer, a principal that may impersonate
	// the owner now can cancel, such as another instance of the service, but
	// not from outside its role's CIDRs.
	resp, err = h.spnego("bob", delegationCancelPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "cancel by stranger", resp, err, logical.ErrPermissionDenied, "may not impersonate its owner")
	writeRole(t, h.b, h.storage, "hive", map[string]interface{}{"token_bound_cidrs": "192.0.2.0/24"})
	resp, err = h.spnego("hive/hs2.example.com", delegationCancelPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "cancel outside the grant's cidrs", resp, err, logical.ErrPermissionDenied, "may not impersonate its owner")
	writeRole(t, h.b, h.storage, "hive", map[string]interface{}{"token_bound_cidrs": ""})
	if resp, err := h.spnego("hive/hs2b.example.com", delegationCancelPathName, map[string]interface{}{"token": urlString}); err != nil || resp != nil {
		t.Fatalf("cancel by another instance: err %v resp %#v", err, resp)
	}
	resp, err = h.login(urlString, nil)
	assertDenied(t, "login after cancel", resp, err, logical.ErrPermissionDenied, "may have been cancelled")

	// Naming oneself is no impersonation.
	resp = h.issue("hive/hs2.example.com", map[string]interface{}{"doas": "hive/hs2.example.com"})
	if resp.Data["owner"] != hive || resp.Data["real_user"] != "" || resp.Data["role"] != "hive" {
		t.Fatalf("issue for oneself: %#v", resp.Data)
	}
	resp, err = h.login(resp.Data["token"].(string), nil)
	if err != nil || resp == nil || resp.Auth == nil || resp.Auth.Metadata["real_user"] != "" {
		t.Fatalf("login for oneself: err %v resp %#v", err, resp)
	}

	// So do rebinding the granting role away from the real user and deleting
	// it.
	urlString = h.issue("hive/hs2.example.com", map[string]interface{}{"doas": "alice"}).Data["token"].(string)
	writeRole(t, h.b, h.storage, "hive", map[string]interface{}{"bound_principals": "hive/other.example.com@" + testRealm})
	resp, err = h.login(urlString, nil)
	assertDenied(t, "login after rebinding the grant", resp, err, logical.ErrPermissionDenied, "may no longer impersonate")
	h.writeProxyRole()
	if resp, err := h.login(urlString, nil); err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login after binding the grant back: err %v resp %#v", err, resp)
	}
	mustRequest(t, h.b, h.storage, logical.DeleteOperation, "roles/hive", nil)
	resp, err = h.login(urlString, nil)
	assertDenied(t, "login after deleting the grant", resp, err, logical.ErrPermissionDenied, "may no longer impersonate")
}

func TestDelegation_DoAsRejections(t *testing.T) {
	h := newDelegationHarness(t)
	h.writeProxyRole()

	hive := "hive/hs2.example.com"
	for name, c := range map[string]struct {
		caller string
		doas   interface{}
		role   string
		want   error
		msg    string
	}{
		"not allowed":          {hive, "bob", "", logical.ErrPermissionDenied, `role "hive" of principal "` + hive + "@" + testRealm + `" does not allow impersonating "bob@` + testRealm + `"`},
		"other realm":          {hive, "alice@OTHER.REALM", "", logical.ErrPermissionDenied, "does not allow impersonating"},
		"no grant":             {"alice", "bob", "", logical.ErrPermissionDenied, `role "users" of principal "alice@` + testRealm + `" does not allow impersonating`},
		"unbound caller":       {"eve", "alice", "", logical.ErrPermissionDenied, `no role is bound to principal "eve@` + testRealm + `"`},
		"before owner roles":   {hive, "dave", "missing", logical.ErrPermissionDenied, "does not allow impersonating"},
		"owner without role":   {hive, "carol", "", logical.ErrPermissionDenied, `no role is bound to principal "carol@` + testRealm + `"`},
		"owner role not bound": {hive, "alice", "hadoop", logical.ErrPermissionDenied, `role "hadoop" is not bound to principal "alice@` + testRealm + `"`},
		"empty realm":          {hive, "alice@", "", logical.ErrInvalidRequest, `doas "alice@" is not a principal name`},
		"space":                {hive, " alice", "", logical.ErrInvalidRequest, "is not a principal name"},
		"boolean":              {hive, false, "", logical.ErrInvalidRequest, "doas must be a string"},
		"number":               {hive, 7, "", logical.ErrInvalidRequest, "doas must be a string"},
	} {
		data := map[string]interface{}{"doas": c.doas}
		if c.role != "" {
			data["role"] = c.role
		}
		resp, err := h.spnego(c.caller, delegationTokenPathName, data)
		assertDenied(t, name, resp, err, c.want, c.msg)
	}

	// The service's role must admit its address and be the only role bound
	// to the service.
	writeRole(t, h.b, h.storage, "hive", map[string]interface{}{"token_bound_cidrs": "192.0.2.0/24"})
	if resp, err := h.spnego(hive, delegationTokenPathName, map[string]interface{}{"doas": "alice"}); !errors.Is(err, logical.ErrPermissionDenied) || resp != nil {
		t.Fatalf("outside the service role's cidrs: err %v resp %#v", err, resp)
	}
	writeRole(t, h.b, h.storage, "hive", map[string]interface{}{"token_bound_cidrs": ""})
	writeRole(t, h.b, h.storage, "hive-other", map[string]interface{}{
		"bound_principals":         hive + "@" + testRealm,
		"allowed_proxy_principals": "alice@" + testRealm,
	})
	resp, err := h.spnego(hive, delegationTokenPathName, map[string]interface{}{"doas": "alice"})
	assertDenied(t, "several service roles", resp, err, logical.ErrPermissionDenied, "is bound to roles hive, hive-other; impersonation requires exactly one")
	mustRequest(t, h.b, h.storage, logical.DeleteOperation, "roles/hive-other", nil)

	// The owner's role must admit the caller's address as well.
	h.issue(hive, map[string]interface{}{"doas": "alice"})
	writeRole(t, h.b, h.storage, "users", map[string]interface{}{"token_bound_cidrs": "192.0.2.0/24"})
	if resp, err := h.spnego(hive, delegationTokenPathName, map[string]interface{}{"doas": "alice"}); !errors.Is(err, logical.ErrPermissionDenied) || resp != nil {
		t.Fatalf("outside the owner's role cidrs: err %v resp %#v", err, resp)
	}
}

func TestDelegation_DoAsRealm(t *testing.T) {
	h := newDelegationHarness(t)
	const users = "USERS.REALM"
	writeRole(t, h.b, h.storage, "hive", map[string]interface{}{
		"bound_principals":         "hive/*@" + testRealm,
		"allowed_proxy_principals": "*@" + users,
	})
	writeRole(t, h.b, h.storage, "trusted", map[string]interface{}{
		"bound_principals": "*@" + users,
		"token_policies":   "trusted-keys",
	})

	// doas_realm places a short name in the users' realm.
	mustRequest(t, h.b, h.storage, logical.UpdateOperation, delegationConfigPath, map[string]interface{}{"doas_realm": users})
	if got := mustRequest(t, h.b, h.storage, logical.ReadOperation, delegationConfigPath, nil).Data["doas_realm"]; got != users {
		t.Fatalf("doas_realm: %v", got)
	}
	resp := h.issue("hive/hs2.example.com", map[string]interface{}{"doas": "alice", "renewer": "yarn"})
	if resp.Data["owner"] != "alice@"+users || resp.Data["role"] != "trusted" {
		t.Fatalf("issue: %#v", resp.Data)
	}
	urlString := resp.Data["token"].(string)

	// A short renewer name is resolved in the realm of the service that
	// requested the token, not in the owner's.
	if resp, err := h.spnego("yarn/rm.example.com", delegationRenewPathName, map[string]interface{}{"token": urlString}); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("renew from the service's realm: err %v resp %#v", err, resp)
	}
	resp, err := h.spnegoRealm("yarn", users, delegationRenewPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "renew from the owner's realm", resp, err, logical.ErrPermissionDenied, "is not the renewer")
	resp, err = h.spnegoRealm("yarn/rm.users.example", users, delegationCancelPathName, map[string]interface{}{"token": urlString})
	assertDenied(t, "cancel from the owner's realm", resp, err, logical.ErrPermissionDenied, "may not impersonate its owner")

	for name, realm := range map[string]string{"with @": "A@B", "with space": "A B"} {
		resp, err := doRequest(t, h.b, h.storage, logical.UpdateOperation, delegationConfigPath, map[string]interface{}{"doas_realm": realm})
		assertDenied(t, "doas_realm "+name, resp, err, logical.ErrInvalidRequest, "is not a realm name")
	}

	// A realm in the name wins; without doas_realm a short name is in the
	// caller's realm.
	if got := h.issue("hive/hs2.example.com", map[string]interface{}{"doas": "bob@" + users}).Data["owner"]; got != "bob@"+users {
		t.Fatalf("qualified doas: %v", got)
	}
	mustRequest(t, h.b, h.storage, logical.UpdateOperation, delegationConfigPath, map[string]interface{}{"doas_realm": ""})
	resp, err = h.spnego("hive/hs2.example.com", delegationTokenPathName, map[string]interface{}{"doas": "alice"})
	assertDenied(t, "short name without doas_realm", resp, err, logical.ErrPermissionDenied, `does not allow impersonating "alice@`+testRealm+`"`)

	// The realm follows the last "@", so a principal name with "@" in it
	// can name itself.
	upn := "alice@corp.example.com"
	writeRole(t, h.b, h.storage, "upn", map[string]interface{}{"bound_principals": "*@corp.example.com@" + testRealm})
	resp = h.issue(upn, map[string]interface{}{"doas": upn + "@" + testRealm})
	if resp.Data["owner"] != upn+"@"+testRealm || resp.Data["real_user"] != "" {
		t.Fatalf("issue for oneself with an enterprise name: %#v", resp.Data)
	}
}

func TestDelegation_DoAsPrincipal(t *testing.T) {
	for doas, want := range map[string]string{
		"alice":                         "alice@" + testRealm,
		"hive/hs2.example.com":          "hive/hs2.example.com@" + testRealm,
		"alice@OTHER.REALM":             "alice@OTHER.REALM",
		"alice@corp.example.com@AD.COM": "alice@corp.example.com@AD.COM",
	} {
		if got, err := doasPrincipal(doas, testRealm); err != nil || got != want {
			t.Errorf("doasPrincipal(%q) = %q, %v; want %q", doas, got, err, want)
		}
	}
	for _, doas := range []string{
		"", "@" + testRealm, "alice@", "alice@corp.example.com@", "/x", "x/", "x//y",
		" alice", "alice ", "al ice", "alice\n", "al\x00ice", "al\u200bice", "al\xffice",
		"*", "a,b", strings.Repeat("a", maxDoasLength+1),
	} {
		if got, err := doasPrincipal(doas, testRealm); err == nil {
			t.Errorf("doasPrincipal(%q) = %q; want an error", doas, got)
		}
	}
}
