package krb5auth

import (
	"errors"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// krbErrCode extracts the KDC error code from err, if any.
// gokrb5 sometimes returns the KRBError value directly and sometimes flattens
// it into a krberror.KrbError string, so both representations are checked.
func krbErrCode(err error) (int32, bool) {
	var krbErr messages.KRBError
	if errors.As(err, &krbErr) {
		return krbErr.ErrorCode, true
	}
	return 0, false
}

// isEtypeNoSupp reports whether err is a KDC_ERR_ETYPE_NOSUPP reply from the KDC.
func isEtypeNoSupp(err error) bool {
	if code, ok := krbErrCode(err); ok {
		return code == errorcode.KDC_ERR_ETYPE_NOSUPP
	}
	return strings.Contains(err.Error(), "KDC_ERR_ETYPE_NOSUPP")
}

// keytabKVNOMismatch extracts the account kvno from a gokrb5 "matching key
// not found in keytab ... kvno: N etype: M" error. The bool is false when
// the error is not a kvno mismatch (or when kvno is 0 / absent — that case
// is an etype mismatch, not a key-version issue).
func keytabKVNOMismatch(err error) (int, bool) {
	s := err.Error()
	idx := strings.Index(s, "matching key not found in keytab")
	if idx < 0 {
		return 0, false
	}
	rest := s[idx:]
	kvIdx := strings.Index(rest, "kvno: ")
	if kvIdx < 0 {
		return 0, false
	}
	field := rest[kvIdx+len("kvno: "):]
	end := strings.IndexAny(field, " \n\t")
	if end > 0 {
		field = field[:end]
	}
	n, err := strconv.Atoi(strings.TrimSpace(field))
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// AuthHint returns a human-readable explanation for a Kerberos auth failure,
// or "" when the error has no classification.
func AuthHint(err error) string {
	if code, ok := krbErrCode(err); ok {
		switch code {
		case errorcode.KDC_ERR_PREAUTH_FAILED:
			return "pre-authentication failed — wrong password, NT hash or AES key"
		case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
			return "username does not exist in the realm"
		case errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN:
			return "no MSSQLSvc SPN registered for the target host — Kerberos requires a registered SPN"
		case errorcode.KDC_ERR_CLIENT_REVOKED:
			return "account is disabled or expired"
		case errorcode.KDC_ERR_ETYPE_NOSUPP:
			return "KDC rejected all requested encryption types — force one with --krb-etype or provide an AES key (--aes-key)"
		case errorcode.KRB_AP_ERR_SKEW:
			return "clock skew with the domain exceeds tolerance — sync time via NTP"
		}
		return ""
	}

	s := err.Error()
	switch {
	case strings.Contains(s, "KDC_ERR_PREAUTH_FAILED"):
		return "pre-authentication failed — wrong password, NT hash or AES key"
	case strings.Contains(s, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		return "username does not exist in the realm"
	case strings.Contains(s, "KDC_ERR_S_PRINCIPAL_UNKNOWN"):
		return "no MSSQLSvc SPN registered for the target host — Kerberos requires a registered SPN"
	case strings.Contains(s, "KDC_ERR_CLIENT_REVOKED"):
		return "account is disabled or expired"
	case strings.Contains(s, "KDC_ERR_ETYPE_NOSUPP"):
		return "KDC rejected all requested encryption types — force one with --krb-etype or provide an AES key (--aes-key)"
	case strings.Contains(s, "KRB_AP_ERR_SKEW"):
		return "clock skew with the domain exceeds tolerance — sync time via NTP"
	case strings.Contains(s, "matching key not found in keytab"):
		// The KDC asked for an etype we have no key for, e.g. an AES-only
		// (Protected Users) target while only an RC4/NT-hash key was given.
		return "KDC requires an encryption type for which no key was provided — supply an AES key with --aes-key"
	}
	return ""
}
