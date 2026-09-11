// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ory/dockertest/v3"
)

func setupTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b, storage := getTestBackend(t)

	data := map[string]interface{}{
		"keytab":          testValidKeytab,
		"service_account": "testuser",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	return b, storage
}

func TestLogin(t *testing.T) {
	b, storage := setupTestBackend(t)

	cleanup, connURL := prepareLDAPTestContainer(t)
	defer cleanup()

	ldapReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      ldapConfPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"url": connURL,
		},
	}

	resp, err := b.HandleRequest(context.Background(), ldapReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	data := map[string]interface{}{
		"authorization": "",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: connURL,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || resp == nil || resp.IsError() {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	if e, ok := err.(logical.HTTPCodedError); !ok || e.Code() != 401 {
		t.Fatalf("no 401 thrown. err: %s resp: %#v\n", err, resp)
	}

	if headerVal, ok := resp.Headers["www-authenticate"]; ok {
		if strings.Compare(headerVal[0], "Negotiate") != 0 {
			t.Fatalf("www-authenticate not set to Negotiate. err: %s resp: %#v\n", err, resp)
		}
	} else {
		t.Fatalf("no www-authenticate header. err: %s resp: %#v\n", err, resp)
	}
}

func TestLogin_Challenge(t *testing.T) {
	for name, withRole := range map[string]bool{"unconfigured": false, "roles only": true} {
		b, storage := setupTestBackend(t)
		if withRole {
			writeRole(t, b, storage, "hadoop", map[string]interface{}{"bound_principals": "hadoop/*@EXAMPLE.COM"})
		}

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation:  logical.UpdateOperation,
			Path:       "login",
			Storage:    storage,
			Data:       map[string]interface{}{"authorization": ""},
			Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
		})
		assertNegotiateChallenge(t, name, resp, err)
	}
}

func assertNegotiateChallenge(t *testing.T, name string, resp *logical.Response, err error) {
	t.Helper()
	if err == nil || resp == nil || resp.IsError() {
		t.Fatalf("%s: err: %s resp: %#v\n", name, err, resp)
	}
	if e, ok := err.(logical.HTTPCodedError); !ok || e.Code() != 401 {
		t.Fatalf("%s: no 401 thrown. err: %s resp: %#v\n", name, err, resp)
	}
	if headerVal, ok := resp.Headers["www-authenticate"]; !ok || len(headerVal) != 1 || headerVal[0] != "Negotiate" {
		t.Fatalf("%s: www-authenticate not set to Negotiate. resp: %#v\n", name, resp)
	}
}

func TestLogin_RoleRejectedWithLdap(t *testing.T) {
	b, storage := setupTestBackend(t)
	mustRequest(t, b, storage, logical.UpdateOperation, ldapConfPath, map[string]interface{}{"url": "ldap://127.0.0.1:1"})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Storage:    storage,
		Data:       map[string]interface{}{"authorization": "", "role": "hadoop"},
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	if !errors.Is(err, logical.ErrInvalidRequest) || resp == nil || !resp.IsError() {
		t.Fatalf("expected invalid request, got err %v resp %#v", err, resp)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Storage:    storage,
		Data:       map[string]interface{}{"authorization": "", "role": "../config"},
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	if !errors.Is(err, logical.ErrInvalidRequest) || resp == nil || !resp.IsError() {
		t.Fatalf("expected invalid role name, got err %v resp %#v", err, resp)
	}
}

func TestConfigLdap_Delete(t *testing.T) {
	b, storage := setupTestBackend(t)
	mustRequest(t, b, storage, logical.UpdateOperation, ldapConfPath, map[string]interface{}{"url": "ldap://127.0.0.1:1"})
	if resp := mustRequest(t, b, storage, logical.ReadOperation, ldapConfPath, nil); resp == nil {
		t.Fatal("expected ldap config")
	}
	mustRequest(t, b, storage, logical.DeleteOperation, ldapConfPath, nil)
	if resp := mustRequest(t, b, storage, logical.ReadOperation, ldapConfPath, nil); resp != nil {
		t.Fatalf("expected ldap config to be deleted, got %#v", resp)
	}
}

const (
	testRealm      = "EXAMPLE.COM"
	testServiceSPN = "HTTP/openbao.example.com"
)

// testKeytab returns a keytab holding the key of testServiceSPN and its base64
// form for the config endpoint.
func testKeytab(t *testing.T) (*keytab.Keytab, string) {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(testServiceSPN, testRealm, "service-password", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return kt, base64.StdEncoding.EncodeToString(raw)
}

// mintNegotiate mints a service ticket for principal against kt and wraps it
// into a SPNEGO Authorization header value, standing in for a KDC.
func mintNegotiate(t *testing.T, kt *keytab.Keytab, principal string) string {
	t.Helper()
	return mintNegotiateRealm(t, kt, principal, testRealm)
}

// mintNegotiateRealm is mintNegotiate for a client from realm, as a
// cross-realm trust would present it.
func mintNegotiateRealm(t *testing.T, kt *keytab.Keytab, principal, realm string) string {
	t.Helper()
	cl := client.NewWithPassword(principal, realm, "unused", config.New())
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), realm,
		types.NewPrincipalName(nametype.KRB_NT_SRV_INST, testServiceSPN), testRealm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	negInit, err := spnego.NewNegTokenInitKRB5(cl, tkt, sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	token := spnego.SPNEGOToken{Init: true, NegTokenInit: negInit}
	raw, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return "Negotiate " + base64.StdEncoding.EncodeToString(raw)
}

func TestLogin_RolesEndToEnd(t *testing.T) {
	b, storage := getTestBackend(t)
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

	login := func(principal string, viaHeader bool, data map[string]interface{}) (*logical.Response, error) {
		negotiate := mintNegotiate(t, kt, principal)
		req := &logical.Request{
			Operation:  logical.UpdateOperation,
			Path:       "login",
			Storage:    storage,
			Data:       map[string]interface{}{},
			Connection: &logical.Connection{RemoteAddr: "10.1.2.3"},
		}
		for k, v := range data {
			req.Data[k] = v
		}
		if viaHeader {
			req.Headers = map[string][]string{"Authorization": {negotiate}}
		} else {
			req.Data["authorization"] = negotiate
		}
		return b.HandleRequest(context.Background(), req)
	}

	for name, viaHeader := range map[string]bool{"header": true, "field": false} {
		resp, err := login("hadoop/nn1.example.com", viaHeader, nil)
		if err != nil || resp == nil || resp.IsError() || resp.Auth == nil {
			t.Fatalf("%s: err %v resp %#v", name, err, resp)
		}
		auth := resp.Auth
		if !reflect.DeepEqual(auth.Policies, []string{"hadoop-keys"}) || auth.TTL.Seconds() != 300 || !auth.Renewable {
			t.Fatalf("%s: policies %v ttl %v renewable %v", name, auth.Policies, auth.TTL, auth.Renewable)
		}
		if auth.Alias.Name != "hadoop/nn1.example.com@"+testRealm || auth.Metadata["role"] != "hadoop" {
			t.Fatalf("%s: alias %q metadata %v", name, auth.Alias.Name, auth.Metadata)
		}

		auth.TokenPolicies = auth.Policies
		renewReq := logical.RenewAuthRequest("login", auth, nil)
		renewReq.Storage = storage
		resp, err = b.HandleRequest(context.Background(), renewReq)
		if err != nil || resp == nil || resp.IsError() || resp.Auth == nil || resp.Auth.TTL.Seconds() != 300 {
			t.Fatalf("%s renew: err %v resp %#v", name, err, resp)
		}
	}

	resp, err := login("hadoop/nn1.example.com", true, map[string]interface{}{"role": "hadoop"})
	if err != nil || resp == nil || resp.IsError() || resp.Auth == nil {
		t.Fatalf("named role: err %v resp %#v", err, resp)
	}

	resp, err = login("alice", true, nil)
	if !errors.Is(err, logical.ErrPermissionDenied) || resp == nil || !resp.IsError() {
		t.Fatalf("unbound principal: expected permission denied, got err %v resp %#v", err, resp)
	}

	// A ticket for another service does not verify against the keytab.
	other := keytab.New()
	if err := other.AddEntry(testServiceSPN, testRealm, "wrong-password", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Storage:    storage,
		Data:       map[string]interface{}{},
		Headers:    map[string][]string{"Authorization": {mintNegotiate(t, other, "hadoop/nn1.example.com")}},
		Connection: &logical.Connection{RemoteAddr: "10.1.2.3"},
	})
	if err != nil || resp == nil || resp.Auth != nil {
		t.Fatalf("forged ticket: expected rejection, got err %v resp %#v", err, resp)
	}
	if code, ok := resp.Data[logical.HTTPStatusCode]; !ok || code == 200 {
		t.Fatalf("forged ticket: expected non-200 status, got %#v", resp.Data)
	}
}

func prepareLDAPTestContainer(t *testing.T) (cleanup func(), retURL string) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	runOpts := &dockertest.RunOptions{
		Repository: "quay.io/minio/openldap",
		Tag:        "latest",
		Env: []string{
			"LDAP_TLS=false",
			"LDAP_DOMAIN=min.io", // Required for minio/openldap to boot up...
		},
	}
	resource, err := pool.RunWithOptions(runOpts)
	if err != nil {
		t.Fatalf("Could not start local MSSQL docker container: %s", err)
	}

	cleanup = func() {
		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	retURL = fmt.Sprintf("ldap://localhost:%s", resource.GetPort("389/tcp"))

	// exponential backoff-retry
	if err = pool.Retry(func() error {
		conn, err := ldap.DialURL(retURL)
		if err != nil {
			return err
		}
		defer conn.Close()

		if err := conn.Bind("cn=admin,dc=min,dc=io", "admin"); err != nil {
			return err
		}

		searchRequest := ldap.NewSearchRequest(
			"dc=min,dc=io",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(&(objectClass=*))",
			[]string{"dn", "cn"},
			nil,
		)
		if _, err := conn.Search(searchRequest); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("Could not connect to ldap auth docker container: %s", err)
	}

	return cleanup, retURL
}
