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

	"github.com/jcmturner/gokrb5/v8/keytab"
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
