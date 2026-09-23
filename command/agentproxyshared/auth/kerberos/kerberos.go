// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-krb5/krb5/spnego"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/api/v2"
	kerberos "github.com/openbao/openbao/builtin/credential/kerberos"
	"github.com/openbao/openbao/command/agentproxyshared/auth"
)

type kerberosMethod struct {
	logger    hclog.Logger
	mountPath string
	loginCfg  kerberos.LoginCfg
	role      string
}

// NewKerberosAuthMethod reads the auto_auth config. A service left out is
// the one clients of vaultAddress request, HTTP/<host>.
func NewKerberosAuthMethod(conf *auth.AuthConfig, vaultAddress string) (auth.AuthMethod, error) {
	if conf == nil {
		return nil, errors.New("empty config")
	}
	if conf.Config == nil {
		return nil, errors.New("empty config data")
	}
	username, err := read("username", conf.Config, true)
	if err != nil {
		return nil, err
	}
	service, err := read("service", conf.Config, false)
	if err != nil {
		return nil, err
	}
	if service == "" {
		if service = kerberos.ServiceFromAddress(vaultAddress); service == "" {
			return nil, kerberos.ErrServiceRequired
		}
	}
	realm, err := read("realm", conf.Config, true)
	if err != nil {
		return nil, err
	}
	keytabPath, err := read("keytab_path", conf.Config, true)
	if err != nil {
		return nil, err
	}
	krb5ConfPath, err := read("krb5conf_path", conf.Config, false)
	if err != nil {
		return nil, err
	}

	disableFast := false
	disableFastRaw, ok := conf.Config["disable_fast_negotiation"]
	if ok {
		disableFast, err = parseutil.ParseBool(disableFastRaw)
		if err != nil {
			return nil, fmt.Errorf("error parsing 'disable_fast_negotiation': %s", err)
		}
	}

	role, err := read("role", conf.Config, false)
	if err != nil {
		return nil, err
	}

	return &kerberosMethod{
		logger:    conf.Logger,
		mountPath: conf.MountPath,
		role:      role,
		loginCfg: kerberos.LoginCfg{
			Username:               username,
			Service:                service,
			Realm:                  realm,
			KeytabPath:             keytabPath,
			Krb5ConfPath:           krb5ConfPath,
			DisableFASTNegotiation: disableFast,
		},
	}, nil
}

func (k *kerberosMethod) Authenticate(context.Context, *api.Client) (string, http.Header, map[string]interface{}, error) {
	k.logger.Trace("beginning authentication")
	authHeaderVal, err := kerberos.GetAuthHeaderVal(&k.loginCfg)
	if err != nil {
		return "", nil, nil, err
	}
	var header http.Header
	header = make(map[string][]string)
	header.Set(spnego.HTTPHeaderAuthRequest, authHeaderVal)
	data := map[string]interface{}{}
	if k.role != "" {
		data["role"] = k.role
	}
	return k.mountPath + "/login", header, data, nil
}

// These functions are implemented to meet the AuthHandler interface,
// but we don't need to take advantage of them.
func (k *kerberosMethod) NewCreds() chan struct{} { return nil }
func (k *kerberosMethod) CredSuccess()            {}
func (k *kerberosMethod) Shutdown()               {}

// read returns the string at key; a missing key is an error only when required.
func read(key string, m map[string]interface{}, required bool) (string, error) {
	raw, ok := m[key]
	if !ok {
		if required {
			return "", fmt.Errorf("%q is required", key)
		}
		return "", nil
	}
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%q must be a string", key)
	}
	return v, nil
}
