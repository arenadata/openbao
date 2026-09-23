// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"errors"
	"testing"

	"github.com/hashicorp/go-hclog"
	kerberos "github.com/openbao/openbao/builtin/credential/kerberos"
	"github.com/openbao/openbao/command/agentproxyshared/auth"
)

const testAddress = "https://bao.matrix.lan:8200"

func TestNewKerberosAuthMethod(t *testing.T) {
	if _, err := NewKerberosAuthMethod(nil, testAddress); err == nil {
		t.Fatal("err should be returned for nil input")
	}
	if _, err := NewKerberosAuthMethod(&auth.AuthConfig{}, testAddress); err == nil {
		t.Fatal("err should be returned for nil config map")
	}

	authConfig := simpleAuthConfig()
	delete(authConfig.Config, "username")
	if _, err := NewKerberosAuthMethod(authConfig, testAddress); err == nil {
		t.Fatal("err should be returned for missing username")
	}

	authConfig = simpleAuthConfig()
	delete(authConfig.Config, "realm")
	if _, err := NewKerberosAuthMethod(authConfig, testAddress); err == nil {
		t.Fatal("err should be returned for missing realm")
	}

	authConfig = simpleAuthConfig()
	delete(authConfig.Config, "keytab_path")
	if _, err := NewKerberosAuthMethod(authConfig, testAddress); err == nil {
		t.Fatal("err should be returned for missing keytab_path")
	}

	authConfig = simpleAuthConfig()
	delete(authConfig.Config, "krb5conf_path")
	authMethod, err := NewKerberosAuthMethod(authConfig, testAddress)
	if err != nil {
		t.Fatalf("krb5conf_path is optional, got %v", err)
	}
	if actual := authMethod.(*kerberosMethod).loginCfg.Krb5ConfPath; actual != "" {
		t.Fatalf("krb5conf_path should stay empty for the /etc/krb5.conf default, got %q", actual)
	}

	authConfig = simpleAuthConfig()
	authMethod, err = NewKerberosAuthMethod(authConfig, testAddress)
	if err != nil {
		t.Fatal(err)
	}

	// False by default
	if actual := authMethod.(*kerberosMethod).loginCfg.DisableFASTNegotiation; actual {
		t.Fatalf("disable_fast_negotiation should be false, it wasn't: %t", actual)
	}

	authConfig.Config["disable_fast_negotiation"] = "true"
	authMethod, err = NewKerberosAuthMethod(authConfig, testAddress)
	if err != nil {
		t.Fatal(err)
	}

	// True from override
	if actual := authMethod.(*kerberosMethod).loginCfg.DisableFASTNegotiation; !actual {
		t.Fatalf("disable_fast_negotiation should be true, it wasn't: %t", actual)
	}

	// Role is optional and passed through verbatim
	if actual := authMethod.(*kerberosMethod).role; actual != "" {
		t.Fatalf("role should be empty by default, got %q", actual)
	}

	authConfig.Config["role"] = "hadoop"
	authMethod, err = NewKerberosAuthMethod(authConfig, testAddress)
	if err != nil {
		t.Fatal(err)
	}
	if actual := authMethod.(*kerberosMethod).role; actual != "hadoop" {
		t.Fatalf("role should be hadoop, got %q", actual)
	}

	authConfig.Config["role"] = 42
	if _, err := NewKerberosAuthMethod(authConfig, testAddress); err == nil {
		t.Fatal("err should be returned for non-string role")
	}
}

// TestNewKerberosAuthMethod_Service checks the service a ticket is requested
// for: the configured one, else HTTP/<host> of the server address.
func TestNewKerberosAuthMethod_Service(t *testing.T) {
	for name, tc := range map[string]struct {
		service, address, want string
		wantErr                bool
	}{
		"configured service":        {service: "HTTP/bao.matrix.lan", address: "http://127.0.0.1:8200", want: "HTTP/bao.matrix.lan"},
		"service from address":      {address: testAddress, want: "HTTP/bao.matrix.lan"},
		"address without host name": {address: "http://127.0.0.1:8200", wantErr: true},
		"unix socket address":       {address: "unix:///run/bao.sock", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			authConfig := simpleAuthConfig()
			delete(authConfig.Config, "service")
			if tc.service != "" {
				authConfig.Config["service"] = tc.service
			}
			authMethod, err := NewKerberosAuthMethod(authConfig, tc.address)
			if tc.wantErr {
				if !errors.Is(err, kerberos.ErrServiceRequired) {
					t.Fatalf("want ErrServiceRequired, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := authMethod.(*kerberosMethod).loginCfg.Service; got != tc.want {
				t.Fatalf("want service %q, got %q", tc.want, got)
			}
		})
	}
}

func simpleAuthConfig() *auth.AuthConfig {
	return &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "kerberos",
		WrapTTL:   20,
		Config: map[string]interface{}{
			"username":      "grace",
			"service":       "HTTP/05a65fad28ef.matrix.lan:8200",
			"realm":         "MATRIX.LAN",
			"keytab_path":   "grace.keytab",
			"krb5conf_path": "krb5.conf",
		},
	}
}
