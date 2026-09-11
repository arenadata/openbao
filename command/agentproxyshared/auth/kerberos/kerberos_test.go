// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/command/agentproxyshared/auth"
)

func TestNewKerberosAuthMethod(t *testing.T) {
	if _, err := NewKerberosAuthMethod(nil); err == nil {
		t.Fatal("err should be returned for nil input")
	}
	if _, err := NewKerberosAuthMethod(&auth.AuthConfig{}); err == nil {
		t.Fatal("err should be returned for nil config map")
	}

	authConfig := simpleAuthConfig()
	delete(authConfig.Config, "username")
	if _, err := NewKerberosAuthMethod(authConfig); err == nil {
		t.Fatal("err should be returned for missing username")
	}

	authConfig = simpleAuthConfig()
	delete(authConfig.Config, "service")
	if _, err := NewKerberosAuthMethod(authConfig); err == nil {
		t.Fatal("err should be returned for missing service")
	}

	authConfig = simpleAuthConfig()
	delete(authConfig.Config, "realm")
	if _, err := NewKerberosAuthMethod(authConfig); err == nil {
		t.Fatal("err should be returned for missing realm")
	}

	authConfig = simpleAuthConfig()
	delete(authConfig.Config, "keytab_path")
	if _, err := NewKerberosAuthMethod(authConfig); err == nil {
		t.Fatal("err should be returned for missing keytab_path")
	}

	authConfig = simpleAuthConfig()
	delete(authConfig.Config, "krb5conf_path")
	if _, err := NewKerberosAuthMethod(authConfig); err == nil {
		t.Fatal("err should be returned for missing krb5conf_path")
	}

	authConfig = simpleAuthConfig()
	authMethod, err := NewKerberosAuthMethod(authConfig)
	if err != nil {
		t.Fatal(err)
	}

	// False by default
	if actual := authMethod.(*kerberosMethod).loginCfg.DisableFASTNegotiation; actual {
		t.Fatalf("disable_fast_negotiation should be false, it wasn't: %t", actual)
	}

	authConfig.Config["disable_fast_negotiation"] = "true"
	authMethod, err = NewKerberosAuthMethod(authConfig)
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
	authMethod, err = NewKerberosAuthMethod(authConfig)
	if err != nil {
		t.Fatal(err)
	}
	if actual := authMethod.(*kerberosMethod).role; actual != "hadoop" {
		t.Fatalf("role should be hadoop, got %q", actual)
	}

	authConfig.Config["role"] = 42
	if _, err := NewKerberosAuthMethod(authConfig); err == nil {
		t.Fatal("err should be returned for non-string role")
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
