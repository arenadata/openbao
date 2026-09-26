// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func writeProxy(t *testing.T, b logical.Backend, storage logical.Storage, name string, data map[string]interface{}) {
	t.Helper()
	mustRequest(t, b, storage, logical.UpdateOperation, "proxy/"+name, data)
}

func TestProxies_CRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	writeProxy(t, b, storage, "hive", map[string]interface{}{
		"bound_principals":   "hive/*@EXAMPLE.COM,",
		"allowed_principals": "alice@EXAMPLE.COM, *@OTHER.COM",
		"bound_cidrs":        "10.0.0.0/8, 192.0.2.7",
	})
	want := map[string]interface{}{
		"bound_principals":   []string{"hive/*@EXAMPLE.COM"},
		"allowed_principals": []string{"alice@EXAMPLE.COM", "*@OTHER.COM"},
		"bound_cidrs":        []string{"10.0.0.0/8", "192.0.2.7"},
	}
	if resp := mustRequest(t, b, storage, logical.ReadOperation, "proxy/hive", nil); resp == nil || !reflect.DeepEqual(resp.Data, want) {
		t.Fatalf("read: got %#v", resp)
	}

	// Update keeps fields that are not sent; an empty bound_cidrs clears it.
	writeProxy(t, b, storage, "hive", map[string]interface{}{
		"allowed_principals": "bob@EXAMPLE.COM",
		"bound_cidrs":        "",
	})
	want["allowed_principals"] = []string{"bob@EXAMPLE.COM"}
	want["bound_cidrs"] = []string{}
	if resp := mustRequest(t, b, storage, logical.ReadOperation, "proxy/hive", nil); resp == nil || !reflect.DeepEqual(resp.Data, want) {
		t.Fatalf("read after update: got %#v", resp)
	}

	writeProxy(t, b, storage, "oozie", map[string]interface{}{
		"bound_principals":   "oozie/*@EXAMPLE.COM",
		"allowed_principals": "*@EXAMPLE.COM",
	})
	resp := mustRequest(t, b, storage, logical.ListOperation, "proxy/", nil)
	if got := resp.Data["keys"]; !reflect.DeepEqual(got, []string{"hive", "oozie"}) {
		t.Fatalf("list: got %#v", got)
	}

	mustRequest(t, b, storage, logical.DeleteOperation, "proxy/hive", nil)
	if resp := mustRequest(t, b, storage, logical.ReadOperation, "proxy/hive", nil); resp != nil {
		t.Fatalf("expected proxy to be deleted, got %#v", resp)
	}
	resp = mustRequest(t, b, storage, logical.ListOperation, "proxy/", nil)
	if got := resp.Data["keys"]; !reflect.DeepEqual(got, []string{"oozie"}) {
		t.Fatalf("list after delete: got %#v", got)
	}
}

func TestProxies_RejectsBadWrites(t *testing.T) {
	b, storage := getTestBackend(t)

	const bound, allowed = "hive/*@EXAMPLE.COM", "alice@EXAMPLE.COM"
	for name, c := range map[string]struct {
		data map[string]interface{}
		msg  string
	}{
		"missing bound_principals":   {map[string]interface{}{"allowed_principals": allowed}, "bound_principals must contain at least one entry"},
		"missing allowed_principals": {map[string]interface{}{"bound_principals": bound}, "allowed_principals must contain at least one entry"},
		"empty entries only":         {map[string]interface{}{"bound_principals": " , ", "allowed_principals": allowed}, "bound_principals must contain at least one entry"},
		"bound entry sans realm":     {map[string]interface{}{"bound_principals": "hive/hs2.example.com", "allowed_principals": allowed}, `bound_principals entry "hive/hs2.example.com" has no realm`},
		"allowed entry sans realm":   {map[string]interface{}{"bound_principals": bound, "allowed_principals": allowed + ",bob"}, `allowed_principals entry "bob" has no realm`},
		"host name":                  {map[string]interface{}{"bound_principals": bound, "allowed_principals": allowed, "bound_cidrs": "hs2.example.com"}, "invalid bound_cidrs"},
		"malformed block":            {map[string]interface{}{"bound_principals": bound, "allowed_principals": allowed, "bound_cidrs": "10.0.0.0/33"}, `bound_cidrs entry "10.0.0.0/33" is not an IP address or CIDR block`},
	} {
		resp, err := doRequest(t, b, storage, logical.UpdateOperation, "proxy/bad", c.data)
		assertDenied(t, name, resp, err, logical.ErrInvalidRequest, c.msg)
	}
	if resp := mustRequest(t, b, storage, logical.ReadOperation, "proxy/bad", nil); resp != nil {
		t.Fatalf("rejected writes stored %#v", resp.Data)
	}

	// An update may not empty a list either.
	writeProxy(t, b, storage, "ok", map[string]interface{}{"bound_principals": bound, "allowed_principals": allowed})
	resp, err := doRequest(t, b, storage, logical.UpdateOperation, "proxy/ok", map[string]interface{}{"allowed_principals": ""})
	assertDenied(t, "clearing allowed_principals", resp, err, logical.ErrInvalidRequest, "allowed_principals must contain at least one entry")
}

func TestMatchingProxies(t *testing.T) {
	b, storage := getTestBackend(t)
	kb := b.(*backend)

	writeProxy(t, b, storage, "c-hive", map[string]interface{}{
		"bound_principals":   "hive/*@EXAMPLE.COM",
		"allowed_principals": "alice@EXAMPLE.COM,*@USERS.COM",
	})
	writeProxy(t, b, storage, "a-all", map[string]interface{}{
		"bound_principals":   "*@EXAMPLE.COM",
		"allowed_principals": "*@USERS.COM",
	})
	writeProxy(t, b, storage, "b-oozie", map[string]interface{}{
		"bound_principals":   "oozie/*@EXAMPLE.COM",
		"allowed_principals": "alice@EXAMPLE.COM",
	})

	for _, c := range []struct {
		realUser, owner string
		want            []string
	}{
		{"hive/hs2@EXAMPLE.COM", "alice@EXAMPLE.COM", []string{"c-hive"}},
		{"hive/hs2@EXAMPLE.COM", "bob@USERS.COM", []string{"a-all", "c-hive"}},
		{"hive/hs2@EXAMPLE.COM", "bob@EXAMPLE.COM", nil},
		{"hive/hs2@OTHER.COM", "alice@EXAMPLE.COM", nil},
		{"oozie/host@EXAMPLE.COM", "alice@EXAMPLE.COM", []string{"b-oozie"}},
	} {
		proxies, err := kb.matchingProxies(context.Background(), storage, c.realUser, c.owner)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range proxies {
			got = append(got, p.Name)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s as %s: got %v want %v", c.realUser, c.owner, got, c.want)
		}
	}
}
