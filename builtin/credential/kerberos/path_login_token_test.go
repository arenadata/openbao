// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// mintKRB5Token returns a marshalled KRB5 AP-REQ mech token for principal
// carrying oid as its mechanism identifier.
func mintKRB5Token(t *testing.T, kt *keytab.Keytab, principal string, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	cl := client.NewWithPassword(principal, testRealm, "unused", config.New())
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), testRealm,
		types.NewPrincipalName(nametype.KRB_NT_SRV_INST, testServiceSPN), testRealm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mt, err := spnego.NewKRB5TokenAPREQ(cl, tkt, sessionKey, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, []int{})
	if err != nil {
		t.Fatal(err)
	}
	mt.OID = oid
	raw, err := mt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLogin_TokenVariants(t *testing.T) {
	b, storage := getTestBackend(t)
	kt, ktB64 := testKeytab(t)
	mustRequest(t, b, storage, logical.UpdateOperation, configPath, map[string]interface{}{
		"keytab":          ktB64,
		"service_account": testServiceSPN,
	})
	writeRole(t, b, storage, "hadoop", map[string]interface{}{"bound_principals": "hadoop/*@" + testRealm})

	login := func(authorization string) (*logical.Response, error) {
		return b.HandleRequest(context.Background(), &logical.Request{
			Operation:  logical.UpdateOperation,
			Path:       "login",
			Storage:    storage,
			Data:       map[string]interface{}{},
			Headers:    map[string][]string{"Authorization": {authorization}},
			Connection: &logical.Connection{RemoteAddr: "10.1.2.3"},
		})
	}
	assertAccepted := func(t *testing.T, resp *logical.Response, err error) {
		t.Helper()
		if err != nil || resp == nil || resp.IsError() || resp.Auth == nil {
			t.Fatalf("expected login, got err %v resp %#v", err, resp)
		}
		if got := resp.Auth.Alias.Name; got != "hadoop/nn1.example.com@"+testRealm {
			t.Fatalf("alias: got %q", got)
		}
	}
	assertRejected := func(t *testing.T, resp *logical.Response, err error, reason string) {
		t.Helper()
		if err != nil || resp == nil || resp.Auth != nil {
			t.Fatalf("expected rejection, got err %v resp %#v", err, resp)
		}
		if code, ok := resp.Data[logical.HTTPStatusCode]; !ok || code != 401 {
			t.Fatalf("expected 401, got %#v", resp.Data)
		}
		// RespondWithStatusCode moves the response into the raw body.
		body, _ := resp.Data[logical.HTTPRawBody].(string)
		var decoded struct {
			Warnings []string `json:"warnings"`
		}
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("decoding raw body %q: %v", body, err)
		}
		if len(decoded.Warnings) != 1 || !strings.Contains(decoded.Warnings[0], reason) {
			t.Fatalf("expected warning containing %q, got %#v", reason, decoded.Warnings)
		}
	}
	negotiateFor := func(mechToken []byte, mech asn1.ObjectIdentifier) string {
		token := spnego.SPNEGOToken{Init: true, NegTokenInit: spnego.NegTokenInit{
			MechTypes:      []asn1.ObjectIdentifier{mech},
			MechTokenBytes: mechToken,
		}}
		raw, err := token.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return "Negotiate " + base64.StdEncoding.EncodeToString(raw)
	}

	t.Run("raw KRB5 token", func(t *testing.T) {
		raw := mintKRB5Token(t, kt, "hadoop/nn1.example.com", gssapi.OIDKRB5.OID())
		resp, err := login("Negotiate " + base64.StdEncoding.EncodeToString(raw))
		assertAccepted(t, resp, err)
	})

	t.Run("MS legacy Kerberos OID", func(t *testing.T) {
		oid := gssapi.OIDMSLegacyKRB5.OID()
		resp, err := login(negotiateFor(mintKRB5Token(t, kt, "hadoop/nn1.example.com", oid), oid))
		assertAccepted(t, resp, err)
	})

	t.Run("replayed token", func(t *testing.T) {
		negotiate := mintNegotiate(t, kt, "hadoop/nn1.example.com")
		resp, err := login(negotiate)
		assertAccepted(t, resp, err)
		resp, err = login(negotiate)
		assertRejected(t, resp, err, "replay")
	})

	t.Run("not base64", func(t *testing.T) {
		resp, err := login("Negotiate %%%")
		assertRejected(t, resp, err, "base64")
	})

	t.Run("not a token", func(t *testing.T) {
		resp, err := login("Negotiate " + base64.StdEncoding.EncodeToString([]byte("garbage")))
		assertRejected(t, resp, err, "unmarshalling SPNEGO token")
	})
}
