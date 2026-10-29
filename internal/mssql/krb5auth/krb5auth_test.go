package krb5auth

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/microsoft/go-mssqldb/msdsn"
)

func TestKeytabRoundTrip(t *testing.T) {
	raw, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	kt, err := keytabFromKeys("test1", "CS.ORG", []KeyEntry{
		{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Key: raw, KVNO: 1},
	})
	if err != nil {
		t.Fatalf("keytabFromKeys: %v", err)
	}

	key, kvno, err := kt.GetEncryptionKey(
		types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"test1"}},
		"CS.ORG", 0, etypeID.AES128_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	if kvno != 1 {
		t.Errorf("kvno = %d, want 1", kvno)
	}
	if hex.EncodeToString(key.KeyValue) != hex.EncodeToString(raw) {
		t.Errorf("key mismatch: got %x want %x", key.KeyValue, raw)
	}
}

func TestKeytabDefaultKVNO(t *testing.T) {
	raw, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	kt, err := keytabFromKeys("u", "R", []KeyEntry{{EType: etypeID.RC4_HMAC, Key: raw}})
	if err != nil {
		t.Fatalf("keytabFromKeys: %v", err)
	}
	_, kvno, err := kt.GetEncryptionKey(
		types.PrincipalName{NameString: []string{"u"}}, "R", 0, etypeID.RC4_HMAC)
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	if kvno != 1 {
		t.Errorf("default kvno = %d, want 1", kvno)
	}
}

func TestNewKrb5Config(t *testing.T) {
	cfg, err := newKrb5Config("cs.org", "192.168.1.195:88", DefaultEtypePreference, DefaultEtypePreference, 0)
	if err != nil {
		t.Fatalf("newKrb5Config: %v", err)
	}
	if cfg.LibDefaults.DefaultRealm != "cs.org" {
		t.Errorf("default realm = %q, want cs.org", cfg.LibDefaults.DefaultRealm)
	}
	if cfg.LibDefaults.DNSLookupKDC {
		t.Error("dns_lookup_kdc must be false")
	}
	if len(cfg.LibDefaults.DefaultTktEnctypes) != 3 {
		t.Errorf("DefaultTktEnctypes = %v, want 3 entries", cfg.LibDefaults.DefaultTktEnctypes)
	}
	_, kdcs, err := cfg.GetKDCs("cs.org", true)
	if err != nil || len(kdcs) != 1 || kdcs[1] != "192.168.1.195:88" {
		t.Errorf("GetKDCs = %v, %v; want 192.168.1.195:88", kdcs, err)
	}

	// preauth etype pinning (keytab modes): AS side collapsed, TGS side wide
	cfg2, err := newKrb5Config("cs.org", "192.168.1.195:88", []int32{etypeID.RC4_HMAC}, DefaultEtypePreference, etypeID.RC4_HMAC)
	if err != nil {
		t.Fatalf("newKrb5Config pinned: %v", err)
	}
	if len(cfg2.LibDefaults.PreferredPreauthTypes) != 1 || cfg2.LibDefaults.PreferredPreauthTypes[0] != int(etypeID.RC4_HMAC) {
		t.Errorf("PreferredPreauthTypes = %v, want [23]", cfg2.LibDefaults.PreferredPreauthTypes)
	}
	if len(cfg2.LibDefaults.DefaultTktEnctypes) != 1 || cfg2.LibDefaults.DefaultTktEnctypes[0] != "rc4-hmac" {
		t.Errorf("DefaultTktEnctypes = %v, want [rc4-hmac]", cfg2.LibDefaults.DefaultTktEnctypes)
	}
	if len(cfg2.LibDefaults.DefaultTGSEnctypes) != 3 {
		t.Errorf("DefaultTGSEnctypes = %v, want full preference (3)", cfg2.LibDefaults.DefaultTGSEnctypes)
	}
}

func TestKeytabKVNOMismatch(t *testing.T) {
	err := errPlain("Decrypting_Error: error decrypting AS_REP encrypted part: matching key not found in keytab. Looking for \"test1\" realm: CS.ORG kvno: 5 etype: 23")
	kvno, ok := keytabKVNOMismatch(err)
	if !ok || kvno != 5 {
		t.Errorf("keytabKVNOMismatch = %d, %v; want 5, true", kvno, ok)
	}
	// etype-only mismatch (kvno 0) is not a kvno issue
	err = errPlain("matching key not found in keytab. Looking for \"test1\" realm: CS.ORG kvno: 0 etype: 18")
	if _, ok := keytabKVNOMismatch(err); ok {
		t.Error("kvno 0 must not be treated as a kvno mismatch")
	}
	if _, ok := keytabKVNOMismatch(errPlain("unrelated")); ok {
		t.Error("unrelated error must not match")
	}
}

func TestParseEtypeList(t *testing.T) {
	ets, err := parseEtypeList("aes256, rc4")
	if err != nil {
		t.Fatalf("parseEtypeList: %v", err)
	}
	want := []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
	if len(ets) != 2 || ets[0] != want[0] || ets[1] != want[1] {
		t.Errorf("got %v, want %v", ets, want)
	}

	if _, err := parseEtypeList("bogus"); err == nil {
		t.Error("expected error for unknown etype")
	}
	if got, err := parseEtypeList(""); err != nil || got != nil {
		t.Errorf("empty list = %v, %v; want nil, nil", got, err)
	}
}

func TestAuthHint(t *testing.T) {
	krbErr := messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED}
	if got := AuthHint(krbErr); got == "" || !strings.Contains(got, "pre-authentication") {
		t.Errorf("AuthHint(typed KRBError) = %q", got)
	}
	if got := AuthHint(krbErr); got == "" {
		t.Error("expected hint")
	}
	// flattened into a string (krberror path)
	if got := AuthHint(errPlain("KDC_Error: KDC_ERR_PREAUTH_FAILED")); got == "" {
		t.Error("expected hint for string-form KRBError")
	}
	if got := AuthHint(errPlain("matching key not found in keytab")); !strings.Contains(got, "--aes-key") {
		t.Errorf("keytab hint = %q", got)
	}
	if got := AuthHint(errPlain("something else")); got != "" {
		t.Errorf("unexpected hint %q", got)
	}
}

func TestResolveKDCExplicit(t *testing.T) {
	got, err := ResolveKDC(context.Background(), "10.0.0.1", "", "", "")
	if err != nil || got != "10.0.0.1:88" {
		t.Errorf("ResolveKDC(kdc) = %q, %v", got, err)
	}
	got, err = ResolveKDC(context.Background(), "", "10.0.0.2", "", "")
	if err != nil || got != "10.0.0.2:88" {
		t.Errorf("ResolveKDC(dc-ip) = %q, %v", got, err)
	}
	got, err = ResolveKDC(context.Background(), "kdc.corp.local", "", "", "")
	if err != nil || got != "kdc.corp.local:88" {
		t.Errorf("ResolveKDC(host) = %q, %v", got, err)
	}
	// already has a port
	got, err = ResolveKDC(context.Background(), "10.0.0.1:9999", "", "", "")
	if err != nil || got != "10.0.0.1:9999" {
		t.Errorf("ResolveKDC(host:port) = %q, %v", got, err)
	}
	// nothing to resolve with
	if _, err = ResolveKDC(context.Background(), "", "", "", ""); err == nil {
		t.Error("expected error with no KDC sources")
	}
}

func TestGetAuthParams(t *testing.T) {
	// password mode
	a, err := getAuth(msdsn.Config{
		User:     "test1",
		Password: "hunter2",
		Parameters: map[string]string{
			paramRealm: "cs.org",
			paramKDC:   "192.168.1.195:88",
		},
	})
	if err != nil {
		t.Fatalf("getAuth(password): %v", err)
	}
	ka := a.(*krbAuth)
	if ka.realm != "CS.ORG" || ka.user != "test1" {
		t.Errorf("realm/user = %q/%q", ka.realm, ka.user)
	}

	// hash mode: etype list collapses to RC4 only
	a, err = getAuth(msdsn.Config{
		User: "test1",
		Parameters: map[string]string{
			paramRealm: "cs.org",
			paramKDC:   "192.168.1.195:88",
			paramHash:  "aad3b435b51404eeaad3b435b51404ee",
		},
	})
	if err != nil {
		t.Fatalf("getAuth(hash): %v", err)
	}
	ka = a.(*krbAuth)
	if !ka.forced || len(ka.etypes) != 1 || ka.etypes[0] != etypeID.RC4_HMAC {
		t.Errorf("hash etypes = %v forced=%v, want [23] true", ka.etypes, ka.forced)
	}
	if ka.keytab == nil {
		t.Fatal("hash mode must build a keytab")
	}

	// aes-key mode: collapse to AES256
	a, err = getAuth(msdsn.Config{
		User: "test1",
		Parameters: map[string]string{
			paramRealm: "cs.org",
			paramKDC:   "192.168.1.195:88",
			paramKey:   strings.Repeat("ab", 32),
		},
	})
	if err != nil {
		t.Fatalf("getAuth(aes-key): %v", err)
	}
	ka = a.(*krbAuth)
	if len(ka.etypes) != 1 || ka.etypes[0] != etypeID.AES256_CTS_HMAC_SHA1_96 {
		t.Errorf("aes etypes = %v, want [18]", ka.etypes)
	}

	// no credentials
	if _, err = getAuth(msdsn.Config{
		User:       "test1",
		Parameters: map[string]string{paramRealm: "cs.org", paramKDC: "192.168.1.195:88"},
	}); err == nil {
		t.Error("expected error without credentials")
	}
	// no kdc
	if _, err = getAuth(msdsn.Config{
		User:       "test1",
		Password:   "x",
		Parameters: map[string]string{paramRealm: "cs.org"},
	}); err == nil {
		t.Error("expected error without KDC")
	}
}

func TestEtypeAttempts(t *testing.T) {
	a := &krbAuth{etypes: DefaultEtypePreference}
	attempts := a.etypeAttempts()
	if len(attempts) != 4 { // full list + 3 singles
		t.Fatalf("attempts = %d, want 4", len(attempts))
	}
	if len(attempts[0]) != 3 {
		t.Errorf("first attempt must be the full preference list, got %v", attempts[0])
	}
	for i, single := range attempts[1:] {
		if len(single) != 1 {
			t.Errorf("attempt %d must be single etype, got %v", i+1, single)
		}
	}
}

type errPlain string

func (e errPlain) Error() string { return string(e) }
