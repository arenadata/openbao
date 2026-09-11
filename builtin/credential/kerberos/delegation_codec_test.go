// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Byte vectors below were produced by hadoop-common 3.4 (WritableUtils,
// AbstractDelegationTokenIdentifier.write, Token.write and
// Token.encodeToUrlString).

var (
	hadoopIdentA = delegationTokenIdentifier{
		Owner: "alice@EXAMPLE.COM", Renewer: "bob", RealUser: "",
		IssueDate: 1756339200000, MaxDate: 1756944000000, SequenceNumber: 42, MasterKeyID: 1,
	}
	hadoopIdentAHex = "0011616c696365404558414d504c452e434f4d03626f62008a0198edf960008a01991205e4002a01"

	hadoopIdentB = delegationTokenIdentifier{
		Owner: "сервис/host@REALM.RU", Renewer: "rm", RealUser: "proxyUser",
		IssueDate: 1700000000123, MaxDate: 1700604800456, SequenceNumber: 123456, MasterKeyID: 7,
	}
	hadoopIdentBHex = "001ad181d0b5d180d0b2d0b8d1812f686f7374405245414c4d2e525502726d0970726f7879557365728a018bcfe5687b8a018bf3f1edc88d01e24007"

	hadoopTokenHex = "280011616c696365404558414d504c452e434f4d03626f62008a0198edf960008a01991205e4002a01200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20184f50454e42414f5f44454c45474154494f4e5f544f4b454e186f70656e62616f2e6578616d706c652e636f6d3a38323030"
	hadoopTokenURL = "KAARYWxpY2VARVhBTVBMRS5DT00DYm9iAIoBmO35YACKAZkSBeQAKgEgAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAYT1BFTkJBT19ERUxFR0FUSU9OX1RPS0VOGG9wZW5iYW8uZXhhbXBsZS5jb206ODIwMA"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDelegationCodec_VLong(t *testing.T) {
	vectors := map[int64]string{
		0: "00", 1: "01", -1: "ff", 127: "7f", 128: "8f80", -112: "90", -113: "8770",
		-120: "8777", -121: "8778", 255: "8fff", 256: "8e0100", 65535: "8effff",
		65536: "8d010000", 2147483647: "8c7fffffff", -2147483648: "847fffffff",
		1756339200000: "8a0198edf96000", -1756339200000: "820198edf95fff",
		9223372036854775807: "887fffffffffffffff", -9223372036854775808: "807fffffffffffffff",
	}
	for v, want := range vectors {
		var buf bytes.Buffer
		writeVLong(&buf, v)
		if got := hex.EncodeToString(buf.Bytes()); got != want {
			t.Errorf("writeVLong(%d) = %s, want %s", v, got, want)
		}
		r := bytes.NewReader(mustHex(t, want))
		got, err := readVLong(r)
		if err != nil || got != v || r.Len() != 0 {
			t.Errorf("readVLong(%s) = %d, %v (left %d), want %d", want, got, err, r.Len(), v)
		}
	}

	if _, err := readVInt(bytes.NewReader(mustHex(t, "8a0198edf96000"))); err == nil {
		t.Error("readVInt accepted a value outside int32")
	}
	if _, err := readVLong(bytes.NewReader(mustHex(t, "8a0198"))); err == nil {
		t.Error("readVLong accepted a truncated value")
	}
}

func TestDelegationCodec_Identifier(t *testing.T) {
	for name, tc := range map[string]struct {
		id  delegationTokenIdentifier
		hex string
	}{"ascii": {hadoopIdentA, hadoopIdentAHex}, "utf8": {hadoopIdentB, hadoopIdentBHex}} {
		want := mustHex(t, tc.hex)
		if got := tc.id.marshal(); !bytes.Equal(got, want) {
			t.Errorf("%s: marshal = %x, want %x", name, got, want)
		}
		got, err := unmarshalIdentifier(want)
		if err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if *got != tc.id {
			t.Errorf("%s: unmarshal = %+v, want %+v", name, *got, tc.id)
		}
	}

	valid := mustHex(t, hadoopIdentAHex)
	for name, raw := range map[string][]byte{
		"empty":         nil,
		"version":       append([]byte{1}, valid[1:]...),
		"trailing":      append(append([]byte{}, valid...), 0),
		"truncated":     valid[:len(valid)-1],
		"empty owner":   (&delegationTokenIdentifier{Renewer: "bob"}).marshal(),
		"bad utf8":      append([]byte{0, 2, 0xff, 0xfe}, valid[19:]...),
		"negative text": {0, 0xff},
	} {
		if _, err := unmarshalIdentifier(raw); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDelegationCodec_Token(t *testing.T) {
	password := make([]byte, 32)
	for i := range password {
		password[i] = byte(i + 1)
	}
	tok := &delegationToken{
		Identifier: hadoopIdentA.marshal(),
		Password:   password,
		Kind:       "OPENBAO_DELEGATION_TOKEN",
		Service:    "openbao.example.com:8200",
	}
	if got := hex.EncodeToString(tok.marshal()); got != hadoopTokenHex {
		t.Errorf("marshal = %s, want %s", got, hadoopTokenHex)
	}
	if got := tok.encodeURLString(); got != hadoopTokenURL {
		t.Errorf("encodeURLString = %s, want %s", got, hadoopTokenURL)
	}

	padded := hadoopTokenURL + strings.Repeat("=", (4-len(hadoopTokenURL)%4)%4)
	standard := strings.NewReplacer("-", "+", "_", "/").Replace(padded)
	for name, s := range map[string]string{"raw": hadoopTokenURL, "padded": padded, "standard alphabet": standard, "spaced": " " + hadoopTokenURL + "\n"} {
		got, err := decodeURLString(s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got.Identifier, tok.Identifier) || !bytes.Equal(got.Password, tok.Password) || got.Kind != tok.Kind || got.Service != tok.Service {
			t.Errorf("%s: decoded %+v", name, got)
		}
	}

	for name, s := range map[string]string{
		"not base64": "!!!",
		"trailing":   tok.encodeURLString() + "AA",
		"truncated":  hadoopTokenURL[:len(hadoopTokenURL)-8],
	} {
		if _, err := decodeURLString(s); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
