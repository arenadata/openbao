// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/spnego"
	"github.com/openbao/openbao/api/v2"
)

// CLIHandler fulfills Vault's LoginHandler interface.
type CLIHandler struct{}

// Auth takes a client and a config map, and returns a secret if appropriate.
func (h *CLIHandler) Auth(c *api.Client, m map[string]string, nonInteractive bool) (*api.Secret, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "kerberos"
	}
	username := m["username"]
	if username == "" {
		return nil, errors.New(`"username" is required`)
	}
	service := m["service"]
	if service == "" {
		return nil, errors.New(`"service" is required`)
	}
	realm := m["realm"]
	if realm == "" {
		return nil, errors.New(`"realm" is required`)
	}
	keytabPath := m["keytab_path"]
	if keytabPath == "" {
		return nil, errors.New(`"keytab_path" is required`)
	}

	krb5ConfPath := m["krb5conf_path"]
	if krb5ConfPath == "" {
		return nil, errors.New(`"krb5conf_path" is required`)
	}

	disableFAST := false
	disableFASTNegotiation := m["disable_fast_negotiation"]
	if disableFASTNegotiation != "" {
		setting, err := strconv.ParseBool(disableFASTNegotiation)
		if err != nil {
			return nil, fmt.Errorf(`invalid value "%s" for disable_fast_negotiation, must be "true" or "false"`, disableFASTNegotiation)
		}
		disableFAST = setting
	}

	removeInstanceName := false
	removeinstanceNameRaw := m["remove_instance_name"]
	if removeinstanceNameRaw != "" {
		setting, err := strconv.ParseBool(removeinstanceNameRaw)
		if err != nil {
			return nil, fmt.Errorf(`invalid value "%s" for remove_instance_name, must be "true" or "false"`, removeinstanceNameRaw)
		}
		removeInstanceName = setting
	}

	loginCfg := &LoginCfg{
		Username:               username,
		Service:                service,
		Realm:                  realm,
		KeytabPath:             keytabPath,
		Krb5ConfPath:           krb5ConfPath,
		DisableFASTNegotiation: disableFAST,
		RemoveInstanceName:     removeInstanceName,
	}

	authHeaderVal, err := GetAuthHeaderVal(loginCfg)
	if err != nil {
		return nil, err
	}
	c.AddHeader(spnego.HTTPHeaderAuthRequest, authHeaderVal)

	path := fmt.Sprintf("auth/%s/login", mount)

	var body map[string]interface{}
	if role := m["role"]; role != "" {
		body = map[string]interface{}{"role": role}
	}

	secret, err := c.Logical().Write(path, body)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("empty response from credential provider")
	}
	return secret, nil
}

func (h *CLIHandler) Help() string {
	help := `
Usage: bao login -method=kerberos [CONFIG K=V...]

  The Kerberos auth method allows users to authenticate using Kerberos,
  resolving policies either through LDAP group membership or through
  roles bound to Kerberos principals.

  Example authentication:

      $ bao login -method=kerberos \
            username=grace \
            service="HTTP/ab10dfy3be7v.matrix.lan:8200" \
            realm=MATRIX.LAN \
            keytab_path=/etc/krb5/krb5.keytab \
            krb5conf_path=/etc/krb5.conf

Configuration:

  krb5conf_path=<string>
      The path to a valid krb5.conf file describing how to communicate with the Kerberos environment.

  keytab_path=<string>
      The path to the keytab in which the entry lives for the entity authenticating to Vault.

  username=<string>
      The username for the entry _within_ the keytab to use for logging into Kerberos.

  service=<string>
      The service principal name to use in obtaining a service ticket for gaining a SPNEGO token.

  realm=<string>
      The name of the Kerberos realm.

  disable_fast_negotiation=<bool>
      When set to true, disables the FAST pre-authentication framework.

  remove_instance_name=<bool>
      When set to true, strips instance names from the principal name in the keytab file.

  role=<string>
      Optional role to log in with when the auth method resolves policies
      through roles instead of LDAP. Without it exactly one role must match
      the principal.
`

	return strings.TrimSpace(help)
}

// LoginCfg is a struct with explicitly-named string fields to prevent
// bugs related to incorrectly ordering the strings being passed into
// GetAuthHeaderVal.
type LoginCfg struct {
	Username, Service, Realm, KeytabPath, Krb5ConfPath string

	// FAST is a pre-authentication framework for Kerberos. It includes
	// a mechanism for tunneling pre-authentication exchanges using armoured
	// KDC messages. FAST provides increased resistance to passive password
	// guessing attacks.
	// Some common Kerberos implementations do not support FAST negotiation.
	DisableFASTNegotiation bool

	// Some keytab creators include FQDN in the username, which can cause
	// issues during login when finding the user principal name in LDAP.
	// When true, we will strip out any data after the username.
	RemoveInstanceName bool
}

// GetAuthHeaderVal is a convenience function that takes a given loginCfg
// and returns the value for the "Authorization" header that should be
// provided to Vault for a successful SPNEGO login.
func GetAuthHeaderVal(loginCfg *LoginCfg) (string, error) {
	kt, err := keytab.Load(loginCfg.KeytabPath)
	if err != nil {
		return "", fmt.Errorf("couldn't load keytab: %w", err)
	}

	if loginCfg.RemoveInstanceName {
		removeInstanceNameFromKeytab(kt)
	}

	krb5Conf, err := config.Load(loginCfg.Krb5ConfPath)
	if err != nil {
		return "", fmt.Errorf("couldn't parse krb5Conf: %w", err)
	}

	settings := []func(*client.Settings){
		client.AssumePreAuthentication(true),
	}
	if loginCfg.DisableFASTNegotiation {
		settings = append(settings, client.DisablePAFXFAST(true))
	}

	cl := client.NewWithKeytab(loginCfg.Username, loginCfg.Realm, kt, krb5Conf, settings...)
	defer cl.Destroy()

	r := &http.Request{Header: http.Header{}}
	if err := spnego.SetSPNEGOHeader(cl, r, loginCfg.Service); err != nil {
		return "", fmt.Errorf("couldn't build SPNEGO token: %w", err)
	}
	return r.Header.Get(spnego.HTTPHeaderAuthRequest), nil
}

func removeInstanceNameFromKeytab(kt *keytab.Keytab) {
	for i := range kt.Entries {
		p := &kt.Entries[i].Principal
		if len(p.Components) > 1 {
			p.Components = p.Components[:1]
			p.NumComponents = 1
		}
	}
}
