// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
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
	loginCfg, err := newLoginCfg(m)
	if err != nil {
		return nil, err
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

  Example authentication with a keytab:

      $ bao login -method=kerberos \
            username=grace \
            service="HTTP/ab10dfy3be7v.matrix.lan:8200" \
            realm=MATRIX.LAN \
            keytab_path=/etc/krb5/krb5.keytab \
            krb5conf_path=/etc/krb5.conf

  Example authentication with the ticket obtained by kinit:

      $ bao login -method=kerberos service="HTTP/ab10dfy3be7v.matrix.lan:8200"

Configuration:

  krb5conf_path=<string>
      The path to a valid krb5.conf file describing how to communicate with the Kerberos environment.
      Defaults to /etc/krb5.conf.

  keytab_path=<string>
      The path to the keytab in which the entry lives for the entity authenticating to Vault.
      Without it the ticket in the credential cache is used instead.

  ccache_path=<string>
      The path to the credential cache holding a ticket-granting ticket. Defaults to
      KRB5CCNAME, then to /tmp/krb5cc_<uid>. Only FILE caches are supported. Ignored when
      keytab_path is set.

  username=<string>
      The username for the entry _within_ the keytab to use for logging into Kerberos.
      Required with keytab_path.

  service=<string>
      The service principal name to use in obtaining a service ticket for gaining a SPNEGO token.

  realm=<string>
      The name of the Kerberos realm. Required with keytab_path.

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

	// CCachePath is the credential cache used when KeytabPath is empty.
	CCachePath string

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

const defaultKrb5ConfPath = "/etc/krb5.conf"

// newLoginCfg validates the CLI options. A keytab_path selects the keytab
// flow, which needs username and realm; otherwise the ticket in the
// credential cache is used.
func newLoginCfg(m map[string]string) (*LoginCfg, error) {
	cfg := &LoginCfg{
		Username:     m["username"],
		Service:      m["service"],
		Realm:        m["realm"],
		KeytabPath:   m["keytab_path"],
		Krb5ConfPath: m["krb5conf_path"],
	}
	if cfg.Service == "" {
		return nil, errors.New(`"service" is required`)
	}
	if cfg.Krb5ConfPath == "" {
		cfg.Krb5ConfPath = defaultKrb5ConfPath
	}

	if cfg.KeytabPath != "" {
		if cfg.Username == "" {
			return nil, errors.New(`"username" is required with "keytab_path"`)
		}
		if cfg.Realm == "" {
			return nil, errors.New(`"realm" is required with "keytab_path"`)
		}
	} else {
		path, err := ccachePath(m["ccache_path"])
		if err != nil {
			return nil, err
		}
		cfg.CCachePath = path
	}

	for key, target := range map[string]*bool{
		"disable_fast_negotiation": &cfg.DisableFASTNegotiation,
		"remove_instance_name":     &cfg.RemoveInstanceName,
	} {
		raw := m[key]
		if raw == "" {
			continue
		}
		setting, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf(`invalid value "%s" for %s, must be "true" or "false"`, raw, key)
		}
		*target = setting
	}
	return cfg, nil
}

// ccachePath resolves the credential cache the way kinit and klist do:
// the explicit option, then KRB5CCNAME, then the per-user default.
func ccachePath(explicit string) (string, error) {
	path := explicit
	if path == "" {
		path = os.Getenv("KRB5CCNAME")
	}
	if path == "" {
		return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid()), nil
	}
	if prefix, rest, ok := strings.Cut(path, ":"); ok {
		if !strings.EqualFold(prefix, "FILE") {
			return "", fmt.Errorf("credential cache type %q is not supported, only FILE caches are", prefix)
		}
		path = rest
	}
	return path, nil
}

// GetAuthHeaderVal is a convenience function that takes a given loginCfg
// and returns the value for the "Authorization" header that should be
// provided to Vault for a successful SPNEGO login.
func GetAuthHeaderVal(loginCfg *LoginCfg) (string, error) {
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

	var cl *client.Client
	if loginCfg.KeytabPath != "" {
		kt, err := keytab.Load(loginCfg.KeytabPath)
		if err != nil {
			return "", fmt.Errorf("couldn't load keytab: %w", err)
		}
		if loginCfg.RemoveInstanceName {
			removeInstanceNameFromKeytab(kt)
		}
		cl = client.NewWithKeytab(loginCfg.Username, loginCfg.Realm, kt, krb5Conf, settings...)
	} else {
		ccache, err := credentials.LoadCCache(loginCfg.CCachePath)
		if err != nil {
			return "", fmt.Errorf("couldn't load credential cache %s: %w", loginCfg.CCachePath, err)
		}
		cl, err = client.NewFromCCache(ccache, krb5Conf, settings...)
		if err != nil {
			return "", fmt.Errorf("couldn't use credential cache %s: %w", loginCfg.CCachePath, err)
		}
	}
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
