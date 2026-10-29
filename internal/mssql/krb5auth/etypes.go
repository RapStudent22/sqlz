package krb5auth

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
)

// DefaultEtypePreference is the encryption type preference order for
// Kerberos: AES256 → AES128 → RC4. RC4 is never the only offering, because
// AD Protected Users targets reject RC4 and require AES.
var DefaultEtypePreference = []int32{
	etypeID.AES256_CTS_HMAC_SHA1_96,
	etypeID.AES128_CTS_HMAC_SHA1_96,
	etypeID.RC4_HMAC,
}

// etypeIDToName maps etype IDs to the names accepted by the krb5.conf parser.
var etypeIDToName = map[int32]string{
	etypeID.AES256_CTS_HMAC_SHA1_96:    "aes256-cts-hmac-sha1-96",
	etypeID.AES128_CTS_HMAC_SHA1_96:    "aes128-cts-hmac-sha1-96",
	etypeID.RC4_HMAC:                   "rc4-hmac",
	etypeID.AES256_CTS_HMAC_SHA384_192: "aes256-cts-hmac-sha384-192",
	etypeID.AES128_CTS_HMAC_SHA256_128: "aes128-cts-hmac-sha256-128",
}

var etypeNameToID = map[string]int32{
	"aes256":                     etypeID.AES256_CTS_HMAC_SHA1_96,
	"aes256-cts-hmac-sha1-96":    etypeID.AES256_CTS_HMAC_SHA1_96,
	"aes128":                     etypeID.AES128_CTS_HMAC_SHA1_96,
	"aes128-cts-hmac-sha1-96":    etypeID.AES128_CTS_HMAC_SHA1_96,
	"rc4":                        etypeID.RC4_HMAC,
	"rc4-hmac":                   etypeID.RC4_HMAC,
	"aes256-cts-hmac-sha384-192": etypeID.AES256_CTS_HMAC_SHA384_192,
	"aes128-cts-hmac-sha256-128": etypeID.AES128_CTS_HMAC_SHA256_128,
}

// parseEtypeList parses a comma-separated list of etype names ("aes256",
// "aes128", "rc4", or the full krb5.conf names). An empty string returns nil.
func parseEtypeList(s string) ([]int32, error) {
	if s == "" {
		return nil, nil
	}
	var out []int32
	seen := make(map[int32]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		id, ok := etypeNameToID[part]
		if !ok {
			if n, err := strconv.Atoi(part); err == nil {
				if _, known := etypeIDToName[int32(n)]; known {
					id = int32(n)
					ok = true
				}
			}
		}
		if !ok {
			return nil, fmt.Errorf("unknown Kerberos etype %q (use aes256, aes128, rc4)", part)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty Kerberos etype list")
	}
	return out, nil
}

// etypeForAESKey returns the etype matching an AES key length in bytes.
func etypeForAESKeyLen(n int) (int32, bool) {
	switch n {
	case 16:
		return etypeID.AES128_CTS_HMAC_SHA1_96, true
	case 32:
		return etypeID.AES256_CTS_HMAC_SHA1_96, true
	}
	return 0, false
}
