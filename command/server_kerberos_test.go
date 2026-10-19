// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/kerberos"
	"github.com/stretchr/testify/require"
)

func TestServerCommand_applyKerberosFlags(t *testing.T) {
	t.Parallel()

	// Without flags the stanza is left as is.
	config := server.NewConfig()
	(&ServerCommand{}).applyKerberosFlags(config)
	require.Nil(t, config.Kerberos)

	stanza := &server.Kerberos{Principal: "config@EXAMPLE.COM", KeytabFile: "/config.keytab"}
	config.Kerberos = stanza
	(&ServerCommand{}).applyKerberosFlags(config)
	require.Same(t, stanza, config.Kerberos)
	require.Equal(t, &server.Kerberos{Principal: "config@EXAMPLE.COM", KeytabFile: "/config.keytab"}, config.Kerberos)

	// Flags create the stanza when the configuration has none.
	config = server.NewConfig()
	(&ServerCommand{flagKerberosPrincipal: "flag@EXAMPLE.COM", flagKerberosKeytabFile: "/flag.keytab"}).applyKerberosFlags(config)
	require.Equal(t, &server.Kerberos{Principal: "flag@EXAMPLE.COM", KeytabFile: "/flag.keytab"}, config.Kerberos)

	// A single flag overrides only its parameter.
	config = server.NewConfig()
	config.Kerberos = &server.Kerberos{Principal: "config@EXAMPLE.COM", KeytabFile: "/config.keytab"}
	(&ServerCommand{flagKerberosKeytabFile: "/flag.keytab"}).applyKerberosFlags(config)
	require.Equal(t, &server.Kerberos{Principal: "config@EXAMPLE.COM", KeytabFile: "/flag.keytab"}, config.Kerberos)
}

func TestServerCommand_KerberosFlags(t *testing.T) {
	t.Setenv("BAO_KERBEROS_PRINCIPAL", "env@EXAMPLE.COM")
	t.Setenv("BAO_KERBEROS_KEYTAB_FILE", "/env.keytab")

	c := &ServerCommand{BaseCommand: &BaseCommand{}}
	require.NoError(t, c.Flags().Parse([]string{"-kerberos-keytab-file=/flag.keytab"}))
	require.Equal(t, "env@EXAMPLE.COM", c.flagKerberosPrincipal)
	require.Equal(t, "/flag.keytab", c.flagKerberosKeytabFile)
}

func TestServerCommand_setupKerberos_Clear(t *testing.T) {
	t.Cleanup(kerberos.Clear)

	// No stanza and no flags: the credentials are cleared, not dereferenced.
	(&ServerCommand{BaseCommand: &BaseCommand{}}).setupKerberos(server.NewConfig())
}

func TestServerCommand_setupKerberos_BadKeytab(t *testing.T) {
	t.Cleanup(kerberos.Clear)

	var buf bytes.Buffer
	c := &ServerCommand{
		BaseCommand:            &BaseCommand{},
		logger:                 hclog.NewInterceptLogger(&hclog.LoggerOptions{Output: &buf, Level: hclog.Warn}),
		flagKerberosPrincipal:  "openbao@EXAMPLE.COM",
		flagKerberosKeytabFile: filepath.Join(t.TempDir(), "missing.keytab"),
	}
	c.setupKerberos(server.NewConfig())
	require.Contains(t, buf.String(), "kerberos credentials could not be loaded")
}
