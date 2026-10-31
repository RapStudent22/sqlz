// Package krb5auth implements a self-contained Kerberos authenticator for
// go-mssqldb in the impacket style:
//
//   - the krb5 config is built at runtime (realm + KDC are explicit),
//   - keys are held in an in-memory keytab (never on disk),
//   - /etc/krb5.conf, KRB5_CONFIG and KRB5_KTNAME are never consulted.
//
// It registers itself as the "krb5" integratedauth provider of go-mssqldb.
// (The driver's own file-based krb5 provider is not linked by default, so the
// name is free — nothing else registers it.)
package krb5auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/microsoft/go-mssqldb/integratedauth"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// Connection string parameters consumed by this provider. They are arbitrary
// URL query parameters that msdsn passes through untouched.
const (
	paramRealm   = "krb5-realm"
	paramKDC     = "krb5-kdc"
	paramKey     = "krb5-key"     // AES key, hex (32 or 64 chars)
	paramHash    = "krb5-hash"    // NT hash (32 hex) or lm:nt pair
	paramCCache  = "krb5-ccache"  // credential cache file path (explicit only)
	paramEType   = "krb5-etype"   // comma-separated forced etype list
	paramKVNO    = "krb5-kvno"    // key version number for the in-memory keytab
	paramTimeout = "krb5-timeout" // seconds bound for the whole Kerberos handshake
)

// handshakeGrace is added to the caller's timeout for the KDC exchange:
// gokrb5's own dial deadlines already bound each network attempt to ~5s,
// so this only caps pathological multi-attempt paths.
const handshakeGrace = 15 * time.Second

func init() {
	// Registered before any connection is made (package init runs before
	// main), overwriting nothing: the driver's built-in krb5 provider is
	// only registered when its package is imported, and sqlz never imports it.
	_ = integratedauth.SetIntegratedAuthenticationProvider("krb5", integratedauth.ProviderFunc(getAuth))
}

type krbAuth struct {
	user     string
	realm    string
	kdc      string
	password string

	keytab    *keytab.Keytab
	rawKeys   []KeyEntry // raw key material, kept so the keytab can be rebuilt with another kvno
	ccache    string     // path, when non-empty
	etypes    []int32    // AS exchange list (collapsed for key modes)
	tgsETypes []int32    // TGS session key list (always the full preference)
	forced    bool
	kvno      uint8
	spn       string
	timeout   time.Duration
	ccacheErr error // set when the ccache file can't be loaded

	client *client.Client
}

// buildKeytab (re)builds the in-memory keytab from the raw keys.
func (a *krbAuth) buildKeytab() error {
	keys := make([]KeyEntry, len(a.rawKeys))
	for i, k := range a.rawKeys {
		keys[i] = k
		keys[i].KVNO = a.kvno
	}
	kt, err := keytabFromKeys(a.user, a.realm, keys)
	if err != nil {
		return err
	}
	a.keytab = kt
	return nil
}

// getAuth parses the login parameters out of the connection string and
// returns the authenticator. Called by the driver for every new connection
// with `authenticator=krb5`.
func getAuth(cfg msdsn.Config) (integratedauth.IntegratedAuthenticator, error) {
	p := cfg.Parameters

	a := &krbAuth{
		user:     cfg.User,
		password: cfg.Password,
		realm:    p[paramRealm],
		kdc:      p[paramKDC],
		ccache:   p[paramCCache],
		spn:      cfg.ServerSPN,
		kvno:     1,
	}

	// realm: explicit param wins, then username@realm, then error.
	if a.realm == "" && strings.Contains(a.user, "@") {
		parts := strings.SplitN(a.user, "@", 2)
		a.user, a.realm = parts[0], strings.ToUpper(parts[1])
	}
	if a.realm == "" {
		return nil, fmt.Errorf("kerberos: realm is required (krb5-realm parameter or user@realm)")
	}
	a.realm = strings.ToUpper(a.realm)

	if a.kdc == "" {
		return nil, fmt.Errorf("kerberos: KDC address is required (krb5-kdc parameter)")
	}

	if v := p[paramKVNO]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 255 {
			return nil, fmt.Errorf("kerberos: invalid %s value %q", paramKVNO, v)
		}
		a.kvno = uint8(n)
	}

	if v := p[paramTimeout]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("kerberos: invalid %s value %q", paramTimeout, v)
		}
		a.timeout = time.Duration(n) * time.Second
	}

	forced, err := parseEtypeList(p[paramEType])
	if err != nil {
		return nil, fmt.Errorf("kerberos: %w", err)
	}
	if forced != nil {
		a.etypes, a.forced = forced, true
	} else {
		a.etypes = append([]int32(nil), DefaultEtypePreference...)
	}
	// The TGS side always keeps the full preference: the service session
	// key is negotiated with the target service. Key modes later collapse
	// only the AS list.
	if forced != nil {
		a.tgsETypes = append([]int32(nil), forced...)
	} else {
		a.tgsETypes = append([]int32(nil), DefaultEtypePreference...)
	}

	// Credential material. Priority: AES key → NT hash → ccache → password.
	switch {
	case p[paramKey] != "":
		if a.user == "" {
			return nil, fmt.Errorf("kerberos: username is required with %s", paramKey)
		}
		if err := a.loadAESKey(p[paramKey]); err != nil {
			return nil, err
		}
	case p[paramHash] != "":
		if a.user == "" {
			return nil, fmt.Errorf("kerberos: username is required with %s", paramHash)
		}
		if err := a.loadNTHash(p[paramHash]); err != nil {
			return nil, err
		}
	case a.ccache != "":
		// ccache mode: no password/key needed, the TGT is in the cache.
	default:
		if a.user == "" {
			return nil, fmt.Errorf("kerberos: username and one of password / %s / %s / %s are required", paramKey, paramHash, paramCCache)
		}
		if a.password == "" {
			return nil, fmt.Errorf("kerberos: no credentials: provide a password, %s, %s or %s", paramKey, paramHash, paramCCache)
		}
	}

	return a, nil
}

// loadAESKey decodes a hex AES key (16 or 32 bytes) and pins the etype list
// to the matching encryption type only, per pass-the-key semantics.
func (a *krbAuth) loadAESKey(hexKey string) error {
	raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return fmt.Errorf("kerberos: %s must be hex (AES128: 32 chars, AES256: 64 chars)", paramKey)
	}
	et, ok := etypeForAESKeyLen(len(raw))
	if !ok {
		return fmt.Errorf("kerberos: %s must be 32 hex chars (AES128) or 64 hex chars (AES256), got %d bytes", paramKey, len(raw))
	}
	a.rawKeys = []KeyEntry{{EType: et, Key: raw}}
	if err := a.buildKeytab(); err != nil {
		return err
	}
	a.etypes, a.forced = []int32{et}, true
	return nil
}

// loadNTHash decodes an NT hash (or lm:nt pair) and stores it as an RC4
// keytab entry — the NT hash IS the RC4 key for Kerberos.
func (a *krbAuth) loadNTHash(hash string) error {
	h := strings.TrimSpace(hash)
	if strings.Contains(h, ":") {
		parts := strings.Split(h, ":")
		if len(parts) != 2 {
			return fmt.Errorf("kerberos: %s must be an NT hash (32 hex) or lm:nt pair", paramHash)
		}
		h = parts[1]
	}
	if len(h) != 32 {
		return fmt.Errorf("kerberos: %s must be an NT hash of 32 hex chars, got %d", paramHash, len(h))
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("kerberos: %s must be hex", paramHash)
	}
	a.rawKeys = []KeyEntry{{EType: etypeID.RC4_HMAC, Key: raw}}
	if err := a.buildKeytab(); err != nil {
		return err
	}
	a.etypes, a.forced = []int32{etypeID.RC4_HMAC}, true
	return nil
}

// clientFor builds the gokrb5 client for the current credential material.
func (a *krbAuth) clientFor(cfg *config.Config) *client.Client {
	opts := []func(*client.Settings){client.DisablePAFXFAST(true)}
	if a.keytab != nil {
		// Pre-authenticate with the etype of the key we hold (pinned via
		// preferred_preauth_types) instead of learning it from the KDC's
		// etype-info2, whose first entry may be an AES type a keytab-only
		// client cannot use (pass-the-hash has only RC4).
		opts = append(opts, client.AssumePreAuthentication(true))
	}

	switch {
	case a.keytab != nil:
		return client.NewWithKeytab(a.user, a.realm, a.keytab, cfg, opts...)
	case a.ccache != "":
		cc, err := credentials.LoadCCache(a.ccache)
		if err != nil {
			a.ccacheErr = err
			return client.NewWithPassword(a.user, a.realm, "", cfg, opts...)
		}
		cl, err := client.NewFromCCache(cc, cfg, opts...)
		if err != nil {
			a.ccacheErr = err
			return client.NewWithPassword(a.user, a.realm, "", cfg, opts...)
		}
		return cl
	default:
		return client.NewWithPassword(a.user, a.realm, a.password, cfg, opts...)
	}
}

// etypeAttempts returns the etype lists to try, in order: the full
// preference list first, then each etype individually. On
// KDC_ERR_ETYPE_NOSUPP the next list is tried (Phase 4 fallback).
func (a *krbAuth) etypeAttempts() [][]int32 {
	list := a.etypes
	if len(list) == 0 {
		list = DefaultEtypePreference
	}
	out := [][]int32{list}
	if len(list) > 1 {
		for _, et := range list {
			out = append(out, []int32{et})
		}
	}
	return out
}

// login obtains a TGT via the AS exchange, retrying with a narrower etype
// list when the KDC answers KDC_ERR_ETYPE_NOSUPP. For keytab modes it also
// recovers from a key-version mismatch: the KDC reports the account's kvno
// in the error, so the in-memory keytab is rebuilt with that kvno and the
// exchange retried once (the NT hash / AES key itself does not change with
// the kvno).
func (a *krbAuth) login() (*client.Client, error) {
	if a.ccacheErr != nil {
		return nil, fmt.Errorf("kerberos: ccache %s: %w", a.ccache, a.ccacheErr)
	}

	var lastErr error
	for _, ets := range a.etypeAttempts() {
		preauth := int32(0)
		if a.keytab != nil && len(ets) == 1 {
			// pass-the-key / pass-the-hash: pre-authenticate with the one
			// etype we actually hold a key for, instead of the first etype
			// the KDC advertises (which may be an AES type we can't derive).
			preauth = ets[0]
		}
		for attempt := 0; ; attempt++ {
			cfg, err := newKrb5Config(a.realm, a.kdc, ets, a.tgsETypes, preauth)
			if err != nil {
				return nil, err
			}
			cl := a.clientFor(cfg)
			if a.ccacheErr != nil {
				return nil, fmt.Errorf("kerberos: ccache %s: %w", a.ccache, a.ccacheErr)
			}
			if err := cl.Login(); err != nil {
				lastErr = err
				if isEtypeNoSupp(err) {
					break // try the next etype list
				}
				// kvno mismatch: rebuild the keytab with the kvno the KDC
				// reported and retry the same exchange once. The key bytes
				// themselves do not change with the kvno.
				if kvno, ok := keytabKVNOMismatch(err); ok && a.keytab != nil && attempt == 0 {
					a.kvno = uint8(kvno)
					if rbErr := a.buildKeytab(); rbErr != nil {
						return nil, rbErr
					}
					continue
				}
				return nil, fmt.Errorf("kerberos login for %s@%s via %s: %w", a.user, a.realm, a.kdc, err)
			}
			return cl, nil
		}
	}
	return nil, fmt.Errorf("kerberos login for %s@%s via %s: %w", a.user, a.realm, a.kdc, lastErr)
}

// InitialBytes performs the Kerberos login and returns the first SPNEGO
// token for the TDS login packet. The whole exchange is bounded: gokrb5's
// own dial deadlines cap each network attempt, and this wrapper caps the
// total so a blackholed KDC can never hang a connection indefinitely.
func (a *krbAuth) InitialBytes() ([]byte, error) {
	type result struct {
		cl  *client.Client
		tok []byte
		err error
	}
	timeout := a.timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	// The context bounds the handshake and lets the login goroutine notice
	// a timeout: gokrb5 v8.4.4 takes no context (its network calls have
	// their own ~5s deadlines), so a canceled ctx only makes the goroutine
	// stop early and drop the client instead of handing back a result
	// nobody will read.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+handshakeGrace)
	defer cancel()

	ch := make(chan result, 1)
	go func() {
		cl, err := a.login()
		if err != nil {
			if ctx.Err() == nil {
				ch <- result{err: err}
			}
			return
		}
		if ctx.Err() != nil {
			cl.Destroy() // timed out while logging in
			return
		}
		tkn, err := spnego.SPNEGOClient(cl, a.spn).InitSecContext()
		if err != nil {
			cl.Destroy()
			if ctx.Err() == nil {
				ch <- result{err: fmt.Errorf("kerberos: SPNEGO to %s: %w", a.spn, err)}
			}
			return
		}
		b, err := tkn.Marshal()
		if err != nil {
			cl.Destroy()
			if ctx.Err() == nil {
				ch <- result{err: err}
			}
			return
		}
		if ctx.Err() == nil {
			ch <- result{cl: cl, tok: b}
		} else {
			cl.Destroy()
		}
	}()

	select {
	case r := <-ch:
		a.client = r.cl
		return r.tok, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("kerberos: handshake with KDC %s timed out — KDC traffic goes through the SOCKS5 proxy via a local relay; check that port 88 is reachable from the proxy server", a.kdc)
	}
}

// NextBytes processes the server's SPNEGO response. The AP-REP verification
// is stateless, mirroring go-mssqldb's own krb5 provider.
func (a *krbAuth) NextBytes(b []byte) ([]byte, error) {
	var resp spnego.SPNEGOToken
	if err := resp.Unmarshal(b); err != nil {
		return nil, err
	}

	ok, status := resp.Verify()
	if ok { // we're ok, done
		return nil, nil
	}

	switch status.Code {
	case gssapi.StatusContinueNeeded:
		return nil, nil
	default:
		return nil, fmt.Errorf("kerberos: bad SPNEGO status: %+v", status)
	}
}

// Free releases the Kerberos client and its sessions.
func (a *krbAuth) Free() {
	if a.client != nil {
		a.client.Destroy()
		a.client = nil
	}
}
