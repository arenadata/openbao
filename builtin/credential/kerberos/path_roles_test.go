// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"gopkg.in/jcmturner/goidentity.v3"
)

func doRequest(t *testing.T, b logical.Backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Storage:   storage,
		Data:      data,
	})
}

func mustRequest(t *testing.T, b logical.Backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := doRequest(t, b, storage, op, path, data)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("%s %s: err: %s resp: %#v\n", op, path, err, resp)
	}
	return resp
}

func writeRole(t *testing.T, b logical.Backend, storage logical.Storage, name string, data map[string]interface{}) {
	t.Helper()
	mustRequest(t, b, storage, logical.UpdateOperation, "roles/"+name, data)
}

func testIdentity(username, realm string) goidentity.Identity {
	user := goidentity.NewUser(username)
	user.SetDomain(realm)
	return &user
}

func TestRoles_CRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	writeRole(t, b, storage, "hadoop", map[string]interface{}{
		"bound_principals": "hadoop/*@EXAMPLE.COM, nn/*@EXAMPLE.COM",
		"token_policies":   "hadoop-keys,default",
		"token_ttl":        300,
	})

	resp := mustRequest(t, b, storage, logical.ReadOperation, "roles/hadoop", nil)
	if resp == nil {
		t.Fatal("expected role")
	}
	wantPrincipals := []string{"hadoop/*@EXAMPLE.COM", "nn/*@EXAMPLE.COM"}
	if got := resp.Data["bound_principals"]; !reflect.DeepEqual(got, wantPrincipals) {
		t.Fatalf("bound_principals: got %#v want %#v", got, wantPrincipals)
	}
	if got := resp.Data["token_policies"]; !reflect.DeepEqual(got, []string{"hadoop-keys", "default"}) {
		t.Fatalf("token_policies: got %#v", got)
	}
	if got := resp.Data["token_ttl"]; got != int64(300) {
		t.Fatalf("token_ttl: got %#v", got)
	}

	resp = mustRequest(t, b, storage, logical.ListOperation, "roles/", nil)
	if got := resp.Data["keys"]; !reflect.DeepEqual(got, []string{"hadoop"}) {
		t.Fatalf("list: got %#v", got)
	}

	// Update keeps fields that are not sent.
	writeRole(t, b, storage, "hadoop", map[string]interface{}{
		"token_policies": "other",
	})
	resp = mustRequest(t, b, storage, logical.ReadOperation, "roles/hadoop", nil)
	if got := resp.Data["bound_principals"]; !reflect.DeepEqual(got, wantPrincipals) {
		t.Fatalf("bound_principals after update: got %#v", got)
	}
	if got := resp.Data["token_policies"]; !reflect.DeepEqual(got, []string{"other"}) {
		t.Fatalf("token_policies after update: got %#v", got)
	}

	mustRequest(t, b, storage, logical.DeleteOperation, "roles/hadoop", nil)
	if resp := mustRequest(t, b, storage, logical.ReadOperation, "roles/hadoop", nil); resp != nil {
		t.Fatalf("expected role to be deleted, got %#v", resp)
	}
	resp = mustRequest(t, b, storage, logical.ListOperation, "roles/", nil)
	if keys, _ := resp.Data["keys"].([]string); len(keys) != 0 {
		t.Fatalf("list after delete: got %#v", resp.Data)
	}
}

func TestRoles_RejectsBadWrites(t *testing.T) {
	b, storage := getTestBackend(t)

	cases := map[string]map[string]interface{}{
		"missing bound_principals": {"token_policies": "x"},
		"empty entries only":       {"bound_principals": " , "},
		"period above max ttl":     {"bound_principals": "*@EXAMPLE.COM", "token_period": "48h"},
	}
	for name, data := range cases {
		resp, err := doRequest(t, b, storage, logical.UpdateOperation, "roles/bad", data)
		if !errors.Is(err, logical.ErrInvalidRequest) || resp == nil || !resp.IsError() {
			t.Fatalf("%s: expected invalid request, got err %v resp %#v", name, err, resp)
		}
	}

	// Empty entries inside an otherwise valid list are dropped.
	writeRole(t, b, storage, "ok", map[string]interface{}{"bound_principals": "a@EXAMPLE.COM,,b@EXAMPLE.COM"})
	resp := mustRequest(t, b, storage, logical.ReadOperation, "roles/ok", nil)
	if got := resp.Data["bound_principals"]; !reflect.DeepEqual(got, []string{"a@EXAMPLE.COM", "b@EXAMPLE.COM"}) {
		t.Fatalf("bound_principals: got %#v", got)
	}
}

func TestRole_Matches(t *testing.T) {
	cases := []struct {
		patterns  []string
		principal string
		want      bool
	}{
		{[]string{"hadoop/*@EXAMPLE.COM"}, "hadoop/nn1.example.com@EXAMPLE.COM", true},
		{[]string{"hadoop/*"}, "hadoop/nn1.example.com@EXAMPLE.COM", true},
		{[]string{"alice@EXAMPLE.COM"}, "alice@example.com", false},
		{nil, "alice@EXAMPLE.COM", false},
	}
	for _, c := range cases {
		r := &kerberosRole{BoundPrincipals: c.patterns}
		if got := r.matches(c.principal); got != c.want {
			t.Errorf("patterns %v principal %q: got %v want %v", c.patterns, c.principal, got, c.want)
		}
	}
}

func TestMatchingRoles(t *testing.T) {
	b, storage := getTestBackend(t)
	kb := b.(*backend)

	writeRole(t, b, storage, "b-hadoop", map[string]interface{}{"bound_principals": "hadoop/*@EXAMPLE.COM"})
	writeRole(t, b, storage, "a-all", map[string]interface{}{"bound_principals": "*@EXAMPLE.COM"})
	writeRole(t, b, storage, "c-hdfs", map[string]interface{}{"bound_principals": "hdfs/*@EXAMPLE.COM"})

	ctx := context.Background()
	principal := "hadoop/nn1.example.com@EXAMPLE.COM"

	names := func(roles []*kerberosRole) []string {
		var out []string
		for _, r := range roles {
			out = append(out, r.Name)
		}
		return out
	}

	roles, err := kb.matchingRoles(ctx, storage, principal, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := names(roles); !reflect.DeepEqual(got, []string{"a-all", "b-hadoop"}) {
		t.Fatalf("all roles: got %v", got)
	}

	for role, want := range map[string]int{"b-hadoop": 1, "c-hdfs": 0, "missing": 0} {
		roles, err := kb.matchingRoles(ctx, storage, principal, role)
		if err != nil {
			t.Fatal(err)
		}
		if len(roles) != want {
			t.Fatalf("role %q: got %v", role, names(roles))
		}
	}
}

func TestLoginWithRoles(t *testing.T) {
	b, storage := getTestBackend(t)
	kb := b.(*backend)
	ctx := context.Background()

	writeRole(t, b, storage, "hadoop", map[string]interface{}{
		"bound_principals":  "hadoop/*@EXAMPLE.COM",
		"token_policies":    "hadoop-keys",
		"token_ttl":         600,
		"token_bound_cidrs": "10.0.0.0/8",
	})
	writeRole(t, b, storage, "hdfs", map[string]interface{}{
		"bound_principals": "hdfs/*@EXAMPLE.COM",
		"token_policies":   "hdfs-keys",
	})
	writeRole(t, b, storage, "wide", map[string]interface{}{
		"bound_principals": "*@WIDE.COM",
		"token_policies":   "wide",
	})
	writeRole(t, b, storage, "wide2", map[string]interface{}{
		"bound_principals": "ops/*@WIDE.COM",
		"token_policies":   "ops",
	})

	reqFrom := func(addr string) *logical.Request {
		return &logical.Request{Storage: storage, Connection: &logical.Connection{RemoteAddr: addr}}
	}
	hadoop := testIdentity("hadoop/nn1.example.com", "EXAMPLE.COM")

	resp, err := kb.loginWithRoles(ctx, reqFrom("10.1.2.3"), hadoop, "")
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	auth := resp.Auth
	if !reflect.DeepEqual(auth.Policies, []string{"hadoop-keys"}) || auth.TTL.Seconds() != 600 {
		t.Fatalf("policies %v ttl %v", auth.Policies, auth.TTL)
	}
	if auth.Alias.Name != "hadoop/nn1.example.com@EXAMPLE.COM" || auth.DisplayName != auth.Alias.Name {
		t.Fatalf("alias %q display %q", auth.Alias.Name, auth.DisplayName)
	}
	if auth.Metadata["role"] != "hadoop" || auth.InternalData["role"] != "hadoop" || auth.InternalData["principal"] != auth.Alias.Name {
		t.Fatalf("metadata %v internal %v", auth.Metadata, auth.InternalData)
	}
	if !auth.Renewable || len(auth.BoundCIDRs) != 1 {
		t.Fatalf("renewable %v cidrs %v", auth.Renewable, auth.BoundCIDRs)
	}

	// Named role behaves the same.
	resp, err = kb.loginWithRoles(ctx, reqFrom("10.1.2.3"), hadoop, "hadoop")
	if err != nil || resp == nil || resp.Auth.Metadata["role"] != "hadoop" {
		t.Fatalf("named role: err %v resp %#v", err, resp)
	}

	denied := map[string]struct {
		addr     string
		identity goidentity.Identity
		role     string
		contains string
	}{
		"outside bound cidrs":    {"203.0.113.5", hadoop, "", ""},
		"no matching role":       {"10.1.2.3", testIdentity("alice", "OTHER.COM"), "", "no role is bound"},
		"named role not bound":   {"10.1.2.3", hadoop, "hdfs", "is not bound"},
		"named role missing":     {"10.1.2.3", hadoop, "missing", "is not bound"},
		"ambiguous without role": {"10.1.2.3", testIdentity("ops/x", "WIDE.COM"), "", "wide, wide2"},
	}
	for name, c := range denied {
		resp, err := kb.loginWithRoles(ctx, reqFrom(c.addr), c.identity, c.role)
		if !errors.Is(err, logical.ErrPermissionDenied) {
			t.Fatalf("%s: expected permission denied, got err %v resp %#v", name, err, resp)
		}
		if c.contains != "" && (resp == nil || !strings.Contains(resp.Error().Error(), c.contains)) {
			t.Fatalf("%s: expected %q in response, got %#v", name, c.contains, resp)
		}
	}

	// Ambiguity is resolved by naming the role.
	resp, err = kb.loginWithRoles(ctx, reqFrom("10.1.2.3"), testIdentity("ops/x", "WIDE.COM"), "wide2")
	if err != nil || resp == nil || !reflect.DeepEqual(resp.Auth.Policies, []string{"ops"}) {
		t.Fatalf("ambiguity resolved: err %v resp %#v", err, resp)
	}
}

func TestLoginRenew(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	writeRole(t, b, storage, "hadoop", map[string]interface{}{
		"bound_principals": "hadoop/*@EXAMPLE.COM",
		"token_policies":   "hadoop-keys",
		"token_ttl":        600,
		"token_max_ttl":    3600,
	})

	resp, err := b.(*backend).loginWithRoles(ctx, &logical.Request{Storage: storage, Connection: &logical.Connection{RemoteAddr: "10.1.2.3"}},
		testIdentity("hadoop/nn1.example.com", "EXAMPLE.COM"), "")
	if err != nil {
		t.Fatal(err)
	}
	issued := resp.Auth
	issued.TokenPolicies = issued.Policies

	renew := func() (*logical.Response, error) {
		auth := *issued
		req := logical.RenewAuthRequest("login", &auth, nil)
		req.Storage = storage
		return b.HandleRequest(ctx, req)
	}

	resp, err = renew()
	if err != nil || resp == nil || resp.IsError() || resp.Auth == nil {
		t.Fatalf("renew: err %v resp %#v", err, resp)
	}
	if resp.Auth.TTL.Seconds() != 600 || resp.Auth.MaxTTL.Seconds() != 3600 {
		t.Fatalf("renew ttl %v max %v", resp.Auth.TTL, resp.Auth.MaxTTL)
	}

	writeRole(t, b, storage, "hadoop", map[string]interface{}{"token_policies": "changed"})
	if resp, err := renew(); err == nil {
		t.Fatalf("expected renew failure after policy change, got %#v", resp)
	}

	writeRole(t, b, storage, "hadoop", map[string]interface{}{"token_policies": "hadoop-keys", "bound_principals": "other/*@EXAMPLE.COM"})
	if resp, err := renew(); err == nil {
		t.Fatalf("expected renew failure after unbinding, got %#v", resp)
	}

	mustRequest(t, b, storage, logical.DeleteOperation, "roles/hadoop", nil)
	if resp, err := renew(); err == nil {
		t.Fatalf("expected renew failure for deleted role, got %#v", resp)
	}

	// Tokens without role data (LDAP mode) are not renewable.
	issued.InternalData = map[string]interface{}{}
	if resp, err := renew(); err == nil {
		t.Fatalf("expected renew failure without role data, got %#v", resp)
	}
}
