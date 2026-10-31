package connectiontest

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// SprayCred is a single credential pair for spray mode. Method is
// "password", "hash" or "aes-key" and Secret holds the raw material.
type SprayCred struct {
	Username string
	Secret   string
	Method   string
}

// ParseSprayFile reads a spray credentials file and detects the secret type
// by format:
//
//	user:password        → password
//	user:p:password      → password forced (for 32/64-hex passwords)
//	user:32-hex          → NT hash (pass-the-hash)
//	user:32-hex:32-hex   → lm:nt pair (nt part is used)
//	user:64-hex          → AES256 key (pass-the-key)
//
// Duplicate pairs are dropped, keeping the first occurrence.
func ParseSprayFile(path string) ([]SprayCred, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open spray file: %w", err)
	}
	defer f.Close()

	var out []SprayCred
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cred, err := parseSprayLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		key := cred.Username + "\x00" + cred.Method + "\x00" + cred.Secret
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, cred)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no credentials found in %s", path)
	}
	return out, nil
}

func parseSprayLine(line string) (SprayCred, error) {
	user, secret, ok := strings.Cut(line, ":")
	if !ok || strings.TrimSpace(user) == "" || secret == "" {
		return SprayCred{}, fmt.Errorf("invalid entry %q (expected user:secret)", line)
	}
	user = strings.TrimSpace(user)

	// "p:" prefix forces password interpretation: a legitimate 32/64-hex
	// password would otherwise be misdetected as an NT hash / AES key and
	// rejected in --auth sql mode.
	if strings.HasPrefix(secret, "p:") {
		return SprayCred{Username: user, Secret: strings.TrimPrefix(secret, "p:"), Method: "password"}, nil
	}
	// AES256 key: exactly 64 hex chars.
	if len(secret) == 64 && isHex(secret) {
		return SprayCred{Username: user, Secret: secret, Method: "aes-key"}, nil
	}
	// NT hash: exactly 32 hex chars (a full lm:nt pair also lands here).
	if len(secret) == 32 && isHex(secret) {
		return SprayCred{Username: user, Secret: secret, Method: "hash"}, nil
	}
	// lm:nt pair: 32-hex:32-hex.
	if parts := strings.Split(secret, ":"); len(parts) == 2 &&
		len(parts[0]) == 32 && isHex(parts[0]) &&
		len(parts[1]) == 32 && isHex(parts[1]) {
		return SprayCred{Username: user, Secret: parts[1], Method: "hash"}, nil
	}
	// everything else is a plain password
	return SprayCred{Username: user, Secret: secret, Method: "password"}, nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
