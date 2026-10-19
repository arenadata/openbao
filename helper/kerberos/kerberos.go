// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Package kerberos configures the Kerberos (GSSAPI) client credentials used
// by the PostgreSQL connections of the server process.
package kerberos

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/spnego"
	"github.com/jackc/pgx/v5/pgconn"
)

const defaultKrb5ConfPath = "/etc/krb5.conf"

// Config holds the Kerberos credentials of the server.
type Config struct {
	// Principal is the name of the principal to authenticate as, for example
	// "openbao@EXAMPLE.COM". When the realm is omitted, the default realm of
	// the krb5 configuration is used.
	Principal string

	// KeytabFile is the path of the keytab holding the keys of Principal.
	KeytabFile string
}

// state is the outcome of the last Setup: the client in use, or the error
// that prevented loading the credentials when no client is in use.
type state struct {
	cl  *client.Client
	err error
}

var (
	registerOnce sync.Once
	current      atomic.Pointer[state]
)

// Setup loads the credentials and makes them the ones used by every
// PostgreSQL connection made through pgx by this process. It can be called
// again, for example on SIGHUP, to pick up a changed keytab. When the
// credentials cannot be loaded, the error is returned; previously loaded
// credentials, if any, remain in use, otherwise the error is reported by
// every connection that requests GSSAPI authentication.
func Setup(cfg Config) error {
	registerProvider()

	cl, err := NewClient(cfg)
	if err != nil {
		if st := current.Load(); st == nil || st.cl == nil {
			current.Store(&state{err: err})
		}
		return err
	}

	destroy(current.Swap(&state{cl: cl}))
	return nil
}

// Clear drops the credentials. Connections that request GSSAPI
// authentication fail until Setup is called again.
func Clear() {
	registerProvider()
	destroy(current.Swap(nil))
}

func destroy(st *state) {
	if st != nil && st.cl != nil {
		st.cl.Destroy()
	}
}

// registerProvider registers the process-wide GSSAPI provider of pgx once;
// the provider reads the current credentials on every connection.
func registerProvider() {
	registerOnce.Do(func() {
		pgconn.RegisterGSSProvider(provider)
	})
}

func provider() (pgconn.GSS, error) {
	st := current.Load()
	switch {
	case st == nil:
		return nil, errors.New("kerberos: no credentials are configured, see the kerberos stanza of the server configuration")
	case st.cl == nil:
		return nil, st.err
	default:
		return gss{cl: st.cl}, nil
	}
}

// NewClient loads the keytab and the krb5 configuration, read from the file
// named by the KRB5_CONFIG environment variable or /etc/krb5.conf, and
// returns a client for the principal. The KDC is not contacted until a
// ticket is requested.
func NewClient(cfg Config) (*client.Client, error) {
	if cfg.Principal == "" {
		return nil, errors.New("kerberos: principal is required")
	}
	if cfg.KeytabFile == "" {
		return nil, errors.New("kerberos: keytab_file is required")
	}

	krb5Conf, err := loadKrb5Conf()
	if err != nil {
		return nil, err
	}

	kt, err := keytab.Load(cfg.KeytabFile)
	if err != nil {
		return nil, fmt.Errorf("kerberos: failed to load keytab %s: %w", cfg.KeytabFile, err)
	}

	username, realm := cfg.Principal, ""
	if i := strings.LastIndex(username, "@"); i >= 0 {
		username, realm = username[:i], username[i+1:]
	}
	if realm == "" {
		realm = krb5Conf.LibDefaults.DefaultRealm
	}
	if username == "" || realm == "" {
		return nil, fmt.Errorf("kerberos: invalid principal %q: unable to determine name and realm", cfg.Principal)
	}

	cl := client.NewWithKeytab(username, realm, kt, krb5Conf, client.DisablePAFXFAST(true))
	if ok, err := cl.IsConfigured(); !ok {
		return nil, fmt.Errorf("kerberos: invalid configuration: %w", err)
	}

	// Fail at startup rather than at the first connection if the keytab
	// does not hold a usable key for the principal.
	var keyErr error
	for _, etype := range krb5Conf.LibDefaults.DefaultTktEnctypeIDs {
		if _, _, keyErr = kt.GetEncryptionKey(cl.Credentials.CName(), realm, 0, etype); keyErr == nil {
			break
		}
	}
	if keyErr != nil {
		return nil, fmt.Errorf("kerberos: keytab %s has no key for %s@%s with a permitted encryption type: %w", cfg.KeytabFile, username, realm, keyErr)
	}

	return cl, nil
}

func loadKrb5Conf() (*config.Config, error) {
	path := os.Getenv("KRB5_CONFIG")
	if path == "" {
		path = defaultKrb5ConfPath
	}

	cfg, err := config.Load(path)
	var unsupported config.UnsupportedDirective
	if err != nil && !errors.As(err, &unsupported) {
		return nil, fmt.Errorf("kerberos: failed to load krb5 configuration %s: %w", path, err)
	}

	return cfg, nil
}

// gss implements pgconn.GSS with the SPNEGO mechanism.
type gss struct {
	cl *client.Client
}

var _ pgconn.GSS = gss{}

func (g gss) GetInitToken(host, service string) ([]byte, error) {
	if g.cl.Config.LibDefaults.DNSCanonicalizeHostname {
		host = canonicalizeHostname(host)
	}

	return g.GetInitTokenFromSPN(service + "/" + strings.ToLower(host))
}

func (g gss) GetInitTokenFromSPN(spn string) ([]byte, error) {
	if err := g.cl.AffirmLogin(); err != nil {
		return nil, fmt.Errorf("kerberos: login failed: %w", err)
	}

	token, err := spnego.SPNEGOClient(g.cl, spn).InitSecContext()
	if err != nil {
		return nil, fmt.Errorf("kerberos: failed to initialize security context for %s: %w", spn, err)
	}

	b, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("kerberos: failed to marshal token: %w", err)
	}

	return b, nil
}

func (gss) Continue(inToken []byte) (bool, []byte, error) {
	var token spnego.SPNEGOToken
	if err := token.Unmarshal(inToken); err != nil {
		return true, nil, fmt.Errorf("kerberos: failed to parse server token: %w", err)
	}
	if !token.Resp {
		return true, nil, errors.New("kerberos: expected negotiation response from server")
	}
	if state := token.NegTokenResp.State(); state != spnego.NegStateAcceptCompleted {
		return true, nil, fmt.Errorf("kerberos: authentication was not completed by server, negotiation state %d", state)
	}

	return true, nil, nil
}

// canonicalizeHostname resolves the canonical name of the host, as the KDC
// usually only knows the service principal of the canonical name.
func canonicalizeHostname(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}

	cname, err := net.LookupCNAME(host)
	if err != nil || cname == "" {
		return host
	}

	return strings.TrimSuffix(cname, ".")
}
