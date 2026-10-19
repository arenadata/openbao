// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseKerberos(t *testing.T) {
	t.Parallel()

	config, err := LoadConfigFile("./test-fixtures/kerberos.hcl", nil)
	require.NoError(t, err)
	require.NotNil(t, config.Kerberos)
	require.Equal(t, "openbao@EXAMPLE.COM", config.Kerberos.Principal)
	require.Equal(t, "/etc/openbao/openbao.keytab", config.Kerberos.KeytabFile)
	require.Empty(t, config.Validate("kerberos.hcl"))
	require.Equal(t, map[string]any{
		"principal":   "openbao@EXAMPLE.COM",
		"keytab_file": "/etc/openbao/openbao.keytab",
	}, config.Sanitized()["kerberos"])

	// The block is carried over and overridden when merging configurations.
	require.Same(t, config.Kerberos, config.Merge(NewConfig()).Kerberos)
	require.Same(t, config.Kerberos, NewConfig().Merge(config).Kerberos)
	override, err := ParseConfig(`kerberos { principal = "other@EXAMPLE.COM" keytab_file = "/other.keytab" }`, "")
	require.NoError(t, err)
	require.Same(t, override.Kerberos, config.Merge(override).Kerberos)

	// Unknown parameters are reported by validation.
	config, err = ParseConfig(`kerberos { principal = "openbao" keytab_file = "/k" realm = "EXAMPLE.COM" }`, "")
	require.NoError(t, err)
	require.Len(t, config.Validate("test"), 1)

	_, err = ParseConfig(``, "")
	require.NoError(t, err)

	for name, hcl := range map[string]string{
		"missing principal":   `kerberos { keytab_file = "/k" }`,
		"missing keytab_file": `kerberos { principal = "openbao" }`,
		"duplicate block":     `kerberos { principal = "a" keytab_file = "/a" } kerberos { principal = "b" keytab_file = "/b" }`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig(hcl, "")
			require.ErrorContains(t, err, "error parsing 'kerberos'")
		})
	}
}
