// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
	"github.com/stretchr/testify/require"
)

const testKrb5Conf = `
[libdefaults]
  default_realm = EXAMPLE.COM
  dns_lookup_kdc = false

[realms]
  EXAMPLE.COM = {
    kdc = kdc.example.com:88
  }
  OTHER.COM = {
    kdc = kdc.other.com:88
  }
`

// writeTestFiles writes a krb5.conf, pointed to by KRB5_CONFIG, and a keytab
// with keys for openbao@EXAMPLE.COM and openbao@OTHER.COM.
func writeTestFiles(t *testing.T) (keytabFile string) {
	t.Helper()

	keytabFile = writeTestKeytab(t)

	dir := t.TempDir()
	krb5ConfFile := filepath.Join(dir, "krb5.conf")
	require.NoError(t, os.WriteFile(krb5ConfFile, []byte(testKrb5Conf), 0o600))
	t.Setenv("KRB5_CONFIG", krb5ConfFile)
	return keytabFile
}

// writeTestKeytab writes a keytab with keys for openbao@EXAMPLE.COM and
// openbao@OTHER.COM.
func writeTestKeytab(t *testing.T) (keytabFile string) {
	t.Helper()

	kt := keytab.New()
	require.NoError(t, kt.AddEntry("openbao", "EXAMPLE.COM", "password", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96))
	require.NoError(t, kt.AddEntry("openbao", "OTHER.COM", "password", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96))
	b, err := kt.Marshal()
	require.NoError(t, err)

	keytabFile = filepath.Join(t.TempDir(), "openbao.keytab")
	require.NoError(t, os.WriteFile(keytabFile, b, 0o600))
	return keytabFile
}

func TestNewClient(t *testing.T) {
	keytabFile := writeTestFiles(t)

	tests := map[string]struct {
		config        Config
		expectedName  string
		expectedRealm string
		expectedErr   string
	}{
		"realm from krb5.conf": {
			config:        Config{Principal: "openbao", KeytabFile: keytabFile},
			expectedName:  "openbao",
			expectedRealm: "EXAMPLE.COM",
		},
		"realm from principal": {
			config:        Config{Principal: "openbao@OTHER.COM", KeytabFile: keytabFile},
			expectedName:  "openbao",
			expectedRealm: "OTHER.COM",
		},
		"missing principal": {
			config:      Config{KeytabFile: keytabFile},
			expectedErr: "principal is required",
		},
		"missing keytab file": {
			config:      Config{Principal: "openbao"},
			expectedErr: "keytab_file is required",
		},
		"empty name": {
			config:      Config{Principal: "@EXAMPLE.COM", KeytabFile: keytabFile},
			expectedErr: "unable to determine name and realm",
		},
		"principal not in keytab": {
			config:      Config{Principal: "other@EXAMPLE.COM", KeytabFile: keytabFile},
			expectedErr: "no key for other@EXAMPLE.COM",
		},
		"nonexistent keytab": {
			config:      Config{Principal: "openbao", KeytabFile: filepath.Join(t.TempDir(), "missing.keytab")},
			expectedErr: "failed to load keytab",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cl, err := NewClient(tc.config)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedName, cl.Credentials.UserName())
			require.Equal(t, tc.expectedRealm, cl.Credentials.Domain())
			require.True(t, cl.Credentials.HasKeytab())
		})
	}
}

func TestNewClient_UnsupportedDirective(t *testing.T) {
	keytabFile := writeTestKeytab(t)

	conf := strings.Replace(testKrb5Conf, "[realms]", "  unknown_option = yes\n\n[realms]", 1)
	krb5ConfFile := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(krb5ConfFile, []byte(conf), 0o600))
	t.Setenv("KRB5_CONFIG", krb5ConfFile)

	_, err := NewClient(Config{Principal: "openbao@EXAMPLE.COM", KeytabFile: keytabFile})
	require.NoError(t, err)
}

func TestNewClient_MissingKrb5Conf(t *testing.T) {
	keytabFile := writeTestFiles(t)
	t.Setenv("KRB5_CONFIG", filepath.Join(t.TempDir(), "missing.conf"))

	_, err := NewClient(Config{Principal: "openbao@EXAMPLE.COM", KeytabFile: keytabFile})
	require.ErrorContains(t, err, "failed to load krb5 configuration")
}

func TestSetup(t *testing.T) {
	keytabFile := writeTestFiles(t)
	t.Cleanup(Clear)

	Clear()
	_, err := provider()
	require.ErrorContains(t, err, "no credentials are configured")

	// Without previously loaded credentials, connections report why loading failed.
	require.Error(t, Setup(Config{Principal: "other@EXAMPLE.COM", KeytabFile: keytabFile}))
	_, err = provider()
	require.ErrorContains(t, err, "no key for other@EXAMPLE.COM")

	require.NoError(t, Setup(Config{Principal: "openbao@EXAMPLE.COM", KeytabFile: keytabFile}))
	g, err := provider()
	require.NoError(t, err)
	first := g.(gss).cl
	require.Equal(t, "EXAMPLE.COM", first.Credentials.Domain())

	// A failed reload keeps the previously loaded credentials in use.
	require.Error(t, Setup(Config{Principal: "other@EXAMPLE.COM", KeytabFile: keytabFile}))
	g, err = provider()
	require.NoError(t, err)
	require.Same(t, first, g.(gss).cl)

	// A successful reload replaces and destroys them.
	require.NoError(t, Setup(Config{Principal: "openbao@OTHER.COM", KeytabFile: keytabFile}))
	g, err = provider()
	require.NoError(t, err)
	require.NotSame(t, first, g.(gss).cl)
	require.Equal(t, "OTHER.COM", g.(gss).cl.Credentials.Domain())
	require.Empty(t, first.Credentials.UserName())

	Clear()
	_, err = provider()
	require.ErrorContains(t, err, "no credentials are configured")
}

func TestGSS_Continue(t *testing.T) {
	done, out, err := gss{}.Continue([]byte("not a token"))
	require.True(t, done)
	require.Nil(t, out)
	require.ErrorContains(t, err, "failed to parse server token")
}

func TestCanonicalizeHostname(t *testing.T) {
	require.Equal(t, "127.0.0.1", canonicalizeHostname("127.0.0.1"))
	require.Equal(t, "::1", canonicalizeHostname("::1"))
	require.Equal(t, "localhost", canonicalizeHostname("localhost"))
}
