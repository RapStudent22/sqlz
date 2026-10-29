package mssql

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/RapStudent22/sqlz/internal/models"
)

func TestSPNForInstance(t *testing.T) {
	inst := models.SQLInstance{Hostname: "sql01.cs.org", Port: 1433}
	spn, err := SPNForInstance(inst)
	if err != nil || spn != "MSSQLSvc/sql01.cs.org:1433" {
		t.Errorf("SPNForInstance = %q, %v", spn, err)
	}

	inst = models.SQLInstance{Hostname: "sql01", Port: 0}
	spn, err = SPNForInstance(inst)
	if err != nil || spn != "MSSQLSvc/sql01:1433" {
		t.Errorf("default port SPN = %q, %v", spn, err)
	}

	if _, err = SPNForInstance(models.SQLInstance{Hostname: "192.168.1.195"}); err == nil {
		t.Error("expected error for IP hostname")
	}
}

func TestBuildConnectionStringKerberos(t *testing.T) {
	cfg := Config{
		Server:   "sql01.cs.org",
		Port:     1433,
		Domain:   "cs.org",
		Username: "test1",
		Password: "hunter2",
		Database: "master",
		AuthType: AuthKerberos,
		KDC:      "192.168.1.195:88",
		SPN:      "MSSQLSvc/sql01.cs.org:1433",
	}
	s, err := buildConnectionString(cfg)
	if err != nil {
		t.Fatalf("buildConnectionString: %v", err)
	}
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	for key, want := range map[string]string{
		"authenticator": "krb5",
		"krb5-realm":    "CS.ORG",
		"krb5-kdc":      "192.168.1.195:88",
		"serverspn":     "MSSQLSvc/sql01.cs.org:1433",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("param %s = %q, want %q", key, got, want)
		}
	}
	if u.User.Username() != "test1" {
		t.Errorf("username = %q", u.User.Username())
	}
}

func TestBuildConnectionStringKerberosRealmDefault(t *testing.T) {
	cfg := Config{
		Server: "h", Port: 1433, Domain: "cs.org", Username: "u",
		Password: "p", AuthType: AuthKerberos, KDC: "kdc:88",
	}
	s, err := buildConnectionString(cfg)
	if err != nil {
		t.Fatalf("buildConnectionString: %v", err)
	}
	u, _ := url.Parse(s)
	if got := u.Query().Get("krb5-realm"); got != "CS.ORG" {
		t.Errorf("default realm = %q, want CS.ORG", got)
	}
}

func TestBuildConnectionStringKerberosErrors(t *testing.T) {
	cases := []Config{
		{Server: "h", Port: 1433, Username: "u", Password: "p", AuthType: AuthKerberos},                   // no realm/domain
		{Server: "h", Port: 1433, Domain: "cs.org", Username: "u", Password: "p", AuthType: AuthKerberos}, // no KDC
		{Server: "h", Port: 1433, Domain: "cs.org", Username: "u", AuthType: AuthKerberos, KDC: "k:88"},   // no material
	}
	for i, cfg := range cases {
		if _, err := buildConnectionString(cfg); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestBuildConnectionStringSSPI(t *testing.T) {
	s, err := buildConnectionString(Config{
		Server: "h", Port: 1433, Domain: "cs.org", Username: "test1",
		Password: "p", AuthType: AuthSSPI,
	})
	if err != nil {
		t.Fatalf("buildConnectionString: %v", err)
	}
	u, _ := url.Parse(s)
	if got := u.Query().Get("authenticator"); got != "winsspi" {
		t.Errorf("authenticator = %q, want winsspi", got)
	}
	if u.User.Username() != `cs.org\test1` {
		t.Errorf("user = %q", u.User.Username())
	}

	// username without a password must NOT be attached: winsspi would build
	// a SEC_WINNT_AUTH_IDENTITY with an empty password and fail the
	// handshake. Without user info it uses the process token.
	s, err = buildConnectionString(Config{
		Server: "h", Port: 1433, Domain: "cs.org", Username: "test1",
		AuthType: AuthSSPI,
	})
	if err != nil {
		t.Fatalf("buildConnectionString (no password): %v", err)
	}
	u, _ = url.Parse(s)
	if u.User != nil {
		t.Errorf("user must be nil without a password, got %q", u.User.Username())
	}
}

func TestLoginHint(t *testing.T) {
	required, hint := LoginHint(AuthWindows, errors.New("Cannot generate SSPI context"))
	if !required || !strings.Contains(hint, "kerberos") {
		t.Errorf("ntlm blocked: required=%v hint=%q", required, hint)
	}
	required, hint = LoginHint(AuthWindows, errors.New("login error: Login failed for user 'test1'."))
	if required || hint == "" {
		t.Errorf("login failed: required=%v hint=%q", required, hint)
	}
	required, hint = LoginHint(AuthKerberos, errors.New("KDC_Error: KDC_ERR_PREAUTH_FAILED"))
	if required || !strings.Contains(hint, "pre-authentication") {
		t.Errorf("krb preauth: required=%v hint=%q", required, hint)
	}
	if required, hint := LoginHint(AuthSQL, nil); required || hint != "" {
		t.Errorf("nil error: %v %q", required, hint)
	}
}
