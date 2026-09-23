// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/keytab"
)

func TestCLI_RemoveInstanceName(t *testing.T) {
	type test struct {
		principalName string
		realm         string
		want          string
	}

	tests := []test{
		{principalName: "foobar/localhost", realm: "hashicorp.com", want: "foobar"},
		{principalName: "foobar/localhost/test", realm: "hashicorp.com", want: "foobar"},
		{principalName: "/localhost/test", realm: "hashicorp.com", want: ""},
	}

	for _, tc := range tests {
		kt := keytab.Keytab{}
		err := kt.AddEntry(tc.principalName, tc.realm, "password", time.Now(), 1, 17)
		if err != nil {
			t.Fatalf("got error adding entry, shouldn't have: %v", err)
		}

		removeInstanceNameFromKeytab(&kt)
		if kt.Entries[0].Principal.NumComponents != 1 {
			t.Fatalf("expected num components to be 1, got %d", kt.Entries[0].Principal.NumComponents)
		}

		if kt.Entries[0].Principal.Components[0] != tc.want {
			t.Fatalf("expected principal name to be %s, got %s", tc.want, kt.Entries[0].Principal.Components[0])
		}
	}
}

func TestCLI_LoginCfg(t *testing.T) {
	uidCache := fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())

	tests := map[string]struct {
		opts           map[string]string
		env            string
		defaultService string
		want           LoginCfg
		wantErr        string
	}{
		"service from server address": {
			opts:           map[string]string{},
			defaultService: "HTTP/bao.example.com",
			want:           LoginCfg{Service: "HTTP/bao.example.com", CCachePath: uidCache},
		},
		"explicit service wins": {
			opts:           map[string]string{"service": "HTTP/other.example.com"},
			defaultService: "HTTP/bao.example.com",
			want:           LoginCfg{Service: "HTTP/other.example.com", CCachePath: uidCache},
		},
		"keytab": {
			opts: map[string]string{"username": "grace", "realm": "EXAMPLE.COM", "service": "HTTP/bao.example.com", "keytab_path": "/etc/grace.keytab", "krb5conf_path": "/opt/krb5.conf"},
			want: LoginCfg{Username: "grace", Realm: "EXAMPLE.COM", Service: "HTTP/bao.example.com", KeytabPath: "/etc/grace.keytab", Krb5ConfPath: "/opt/krb5.conf"},
		},
		"keytab without username": {
			opts:    map[string]string{"realm": "EXAMPLE.COM", "service": "HTTP/bao.example.com", "keytab_path": "/etc/grace.keytab"},
			wantErr: `"username" is required with "keytab_path"`,
		},
		"keytab without realm": {
			opts:    map[string]string{"username": "grace", "service": "HTTP/bao.example.com", "keytab_path": "/etc/grace.keytab"},
			wantErr: `"realm" is required with "keytab_path"`,
		},
		"service missing is left to GetAuthHeaderVal": {
			opts: map[string]string{"username": "grace"},
			want: LoginCfg{Username: "grace", CCachePath: uidCache},
		},
		"ccache explicit": {
			opts: map[string]string{"service": "HTTP/bao.example.com", "ccache_path": "/tmp/cc"},
			env:  "FILE:/ignored",
			want: LoginCfg{Service: "HTTP/bao.example.com", CCachePath: "/tmp/cc"},
		},
		"ccache from KRB5CCNAME with FILE prefix": {
			opts: map[string]string{"service": "HTTP/bao.example.com"},
			env:  "FILE:/tmp/krb5cc_grace",
			want: LoginCfg{Service: "HTTP/bao.example.com", CCachePath: "/tmp/krb5cc_grace"},
		},
		"ccache from KRB5CCNAME without prefix": {
			opts: map[string]string{"service": "HTTP/bao.example.com"},
			env:  "/tmp/krb5cc_grace",
			want: LoginCfg{Service: "HTTP/bao.example.com", CCachePath: "/tmp/krb5cc_grace"},
		},
		"ccache default per user": {
			opts: map[string]string{"service": "HTTP/bao.example.com"},
			want: LoginCfg{Service: "HTTP/bao.example.com", CCachePath: uidCache},
		},
		"ccache FILE prefix without path": {
			opts:    map[string]string{"service": "HTTP/bao.example.com"},
			env:     "FILE:",
			wantErr: "credential cache path is empty",
		},
		"ccache unsupported type": {
			opts:    map[string]string{"service": "HTTP/bao.example.com"},
			env:     "KEYRING:persistent:1003",
			wantErr: `credential cache type "KEYRING" is not supported`,
		},
		"flags": {
			opts: map[string]string{"service": "HTTP/bao.example.com", "disable_fast_negotiation": "true", "remove_instance_name": "true"},
			want: LoginCfg{Service: "HTTP/bao.example.com", CCachePath: uidCache, DisableFASTNegotiation: true, RemoveInstanceName: true},
		},
		"bad flag": {
			opts:    map[string]string{"service": "HTTP/bao.example.com", "disable_fast_negotiation": "maybe"},
			wantErr: `invalid value "maybe" for disable_fast_negotiation`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("KRB5CCNAME", tc.env)
			got, err := newLoginCfg(tc.opts, tc.defaultService)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if *got != tc.want {
				t.Fatalf("want %+v, got %+v", tc.want, *got)
			}
		})
	}
}

func TestCLI_GetAuthHeaderVal_MissingCCache(t *testing.T) {
	krb5Conf := t.TempDir() + "/krb5.conf"
	if err := os.WriteFile(krb5Conf, []byte("[libdefaults]\n  default_realm = EXAMPLE.COM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := GetAuthHeaderVal(&LoginCfg{Service: "HTTP/bao.example.com", Krb5ConfPath: krb5Conf, CCachePath: t.TempDir() + "/missing"})
	if err == nil || !strings.Contains(err.Error(), "not found: run kinit") {
		t.Fatalf("want missing-cache error, got %v", err)
	}
}

func TestCLI_GetAuthHeaderVal_ServiceRequired(t *testing.T) {
	_, err := GetAuthHeaderVal(&LoginCfg{KeytabPath: "/etc/grace.keytab"})
	if !errors.Is(err, ErrServiceRequired) {
		t.Fatalf("want ErrServiceRequired, got %v", err)
	}
}

// TestCLI_GetAuthHeaderVal_DefaultKrb5Conf points the default at a fixture:
// reaching the credential cache step proves the fixture was loaded.
func TestCLI_GetAuthHeaderVal_DefaultKrb5Conf(t *testing.T) {
	fixture := t.TempDir() + "/krb5.conf"
	if err := os.WriteFile(fixture, []byte("[libdefaults]\n  default_realm = EXAMPLE.COM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := defaultKrb5ConfPath
	defaultKrb5ConfPath = fixture
	t.Cleanup(func() { defaultKrb5ConfPath = saved })

	_, err := GetAuthHeaderVal(&LoginCfg{Service: "HTTP/bao.example.com", CCachePath: t.TempDir() + "/missing"})
	if err == nil || !strings.Contains(err.Error(), "not found: run kinit") {
		t.Fatalf("want missing-cache error after the default krb5.conf loaded, got %v", err)
	}
}

func TestCLI_ServiceFromAddress(t *testing.T) {
	for addr, want := range map[string]string{
		"https://bao.example.com:8200":  "HTTP/bao.example.com",
		"http://bao.example.com":        "HTTP/bao.example.com",
		"https://BAO.Example.com:8200":  "HTTP/bao.example.com",
		"https://bao.example.com.:8200": "HTTP/bao.example.com",
		"https://[::1]:8200":            "",
		"https://[fe80::1%25eth0]:8200": "",
		"http://127.0.0.1:8200":         "",
		"unix:///run/bao.sock":          "",
		"":                              "",
		"not a url":                     "",
	} {
		if got := ServiceFromAddress(addr); got != want {
			t.Errorf("%q: want %q, got %q", addr, want, got)
		}
	}
}
