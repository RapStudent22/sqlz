package krb5auth

import (
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"
)

// newKrb5Config builds a gokrb5 config entirely at runtime (impacket-style).
// It never touches /etc/krb5.conf or any other system file: the realm, the
// KDC address and the encryption types all come from explicit parameters.
//
// The AS side (tktEtypes) may be collapsed to the etype of the key a keytab
// client holds, while the TGS side (tgsEtypes) keeps the full preference
// list: the session key for a service ticket is negotiated with the target
// service, which may not support the client's key etype (e.g. a service
// that only accepts RC4 session keys while the client holds an AES key).
//
// preauthEType, when non-zero, pins preferred_preauth_types to that single
// etype (numeric, as the parser expects). Used for keytab modes so the
// client picks the etype of the key it actually holds instead of the first
// etype the KDC advertises.
func newKrb5Config(realm, kdc string, tktEtypes, tgsEtypes []int32, preauthEType int32) (*config.Config, error) {
	if realm == "" {
		return nil, fmt.Errorf("krb5: empty realm")
	}
	if kdc == "" {
		return nil, fmt.Errorf("krb5: empty KDC address")
	}

	names := func(etypes []int32) ([]string, error) {
		out := make([]string, len(etypes))
		for i, id := range etypes {
			name, ok := etypeIDToName[id]
			if !ok {
				return nil, fmt.Errorf("krb5: unsupported etype id %d", id)
			}
			out[i] = name
		}
		return out, nil
	}

	var b strings.Builder
	b.WriteString("[libdefaults]\n")
	b.WriteString("  default_realm = " + realm + "\n")
	b.WriteString("  dns_lookup_kdc = false\n")
	b.WriteString("  dns_lookup_realm = false\n")
	b.WriteString("  udp_preference_limit = 1\n") // TCP only: avoids UDP truncation on busy links
	b.WriteString("  rdns = false\n")
	b.WriteString("  clockskew = 300\n")
	if len(tktEtypes) > 0 {
		ns, err := names(tktEtypes)
		if err != nil {
			return nil, err
		}
		b.WriteString("  default_tkt_enctypes = " + strings.Join(ns, " ") + "\n")
	}
	if len(tgsEtypes) > 0 {
		ns, err := names(tgsEtypes)
		if err != nil {
			return nil, err
		}
		b.WriteString("  default_tgs_enctypes = " + strings.Join(ns, " ") + "\n")
		b.WriteString("  permitted_enctypes = " + strings.Join(ns, " ") + "\n")
	}
	if preauthEType != 0 {
		b.WriteString(fmt.Sprintf("  preferred_preauth_types = %d\n", preauthEType))
	}
	b.WriteString("\n[realms]\n")
	b.WriteString("  " + realm + " = {\n")
	b.WriteString("    kdc = " + kdc + "\n")
	b.WriteString("  }\n")

	cfg, err := config.NewFromReader(strings.NewReader(b.String()))
	if err != nil {
		return nil, fmt.Errorf("krb5: build runtime config: %w", err)
	}
	return cfg, nil
}
