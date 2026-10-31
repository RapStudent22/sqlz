package connectiontest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSprayLine(t *testing.T) {
	aes64 := strings.Repeat("ab", 32) // 64 hex chars
	cases := []struct {
		line   string
		user   string
		method string
		secret string
	}{
		{"user1:Password123!", "user1", "password", "Password123!"},
		{"user2:0123456789abcdef0123456789abcdef", "user2", "hash", "0123456789abcdef0123456789abcdef"},
		{"user3:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef", "user3", "hash", "0123456789abcdef0123456789abcdef"},
		{"user4:" + aes64, "user4", "aes-key", aes64},
	}
	for _, c := range cases {
		got, err := parseSprayLine(c.line)
		if err != nil {
			t.Fatalf("parseSprayLine(%q): %v", c.line, err)
		}
		if got.Username != c.user || got.Method != c.method || got.Secret != c.secret {
			t.Errorf("parseSprayLine(%q) = %+v, want user=%s method=%s", c.line, got, c.user, c.method)
		}
	}

	// a 64-hex secret must be treated as an AES key, not lm:nt
	got, err := parseSprayLine("u:" + aes64)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	if got.Method != "aes-key" {
		t.Errorf("aes method = %q", got.Method)
	}

	// the "p:" prefix forces password interpretation: a 32/64-hex password
	// would otherwise be misdetected as a hash / AES key
	hexPassword := strings.Repeat("ab", 16) // 32 hex chars
	got, err = parseSprayLine("user5:p:" + hexPassword)
	if err != nil {
		t.Fatalf("p: prefix: %v", err)
	}
	if got.Method != "password" || got.Secret != hexPassword {
		t.Errorf("p: entry = %+v, want password %q", got, hexPassword)
	}

	if _, err := parseSprayLine("nocolon"); err == nil {
		t.Error("expected error for line without colon")
	}
}

func TestParseSprayFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.txt")
	content := "# comment\n" +
		"\n" +
		"user1:Password123!\n" +
		"user2:0123456789abcdef0123456789abcdef\n" +
		"user1:Password123!\n" + // duplicate — dropped
		"user3:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	creds, err := ParseSprayFile(path)
	if err != nil {
		t.Fatalf("ParseSprayFile: %v", err)
	}
	if len(creds) != 3 {
		t.Fatalf("got %d creds, want 3 (duplicate dropped)", len(creds))
	}
	if creds[0].Username != "user1" || creds[0].Method != "password" {
		t.Errorf("creds[0] = %+v", creds[0])
	}
	if creds[1].Method != "hash" || creds[2].Method != "hash" {
		t.Errorf("methods = %q, %q", creds[1].Method, creds[2].Method)
	}
	if creds[2].Secret != "0123456789abcdef0123456789abcdef" {
		t.Errorf("lm:nt pair must keep the nt part, got %q", creds[2].Secret)
	}

	if _, err := ParseSprayFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("expected error for missing file")
	}
}
