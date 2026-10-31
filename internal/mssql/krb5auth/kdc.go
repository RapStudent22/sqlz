package krb5auth

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ResolveKDC determines the KDC address (host:port) for a domain.
// Priority order (never reads /etc/krb5.conf):
//
//	explicit --kdc value → --dc-ip → DNS SRV via the configured nameserver → error
//
// The SRV lookups respect the existing --nameserver flag: queries are sent
// to that server instead of the system resolver. With a SOCKS5 dialer all
// of those DNS queries go over TCP through the proxy.
func ResolveKDC(ctx context.Context, kdcFlag, dcIP, domain, nameserver string, d Dialer) (string, error) {
	if kdcFlag != "" {
		return withDefaultPort(resolveOrSelf(ctx, kdcFlag, nameserver, d), 88), nil
	}
	if dcIP != "" {
		return withDefaultPort(resolveOrSelf(ctx, dcIP, nameserver, d), 88), nil
	}
	if domain == "" {
		return "", fmt.Errorf(
			"cannot determine KDC: specify --kdc, --dc-ip or --domain for DNS SRV discovery")
	}

	realm := strings.ToUpper(domain)
	// AD forest root DCs, then the realm fallback.
	srvNames := []string{"dc._msdcs." + domain, realm}
	for _, name := range srvNames {
		target, port, err := LookupSRV(ctx, nameserver, name, d)
		if err != nil || target == "" {
			continue
		}
		// Resolve the KDC hostname to an IP with the same nameserver so the
		// KDC config never depends on the system resolver (stock-Kali
		// guarantee: the lab domain is often not in /etc/resolv.conf).
		// gokrb5 dials whatever address we hand it; an IP skips its own
		// hostname resolution entirely.
		if ip, err := LookupHostIP(ctx, nameserver, target, d); err == nil && ip != "" {
			return net.JoinHostPort(ip, strconv.Itoa(int(port))), nil
		}
		return net.JoinHostPort(target, strconv.Itoa(int(port))), nil
	}

	return "", fmt.Errorf(
		"cannot resolve KDC for domain %q via DNS SRV (lookups respect --nameserver); specify --kdc or --dc-ip explicitly", domain)
}

// resolveOrSelf resolves a KDC/DC hostname to an IP via the nameserver so
// the krb5 config never depends on the system resolver. IP literals and
// unresolvable names pass through unchanged (the dial error will name the
// host clearly).
func resolveOrSelf(ctx context.Context, host, nameserver string, d Dialer) string {
	if net.ParseIP(host) != nil || nameserver == "" {
		return host
	}
	// Already "host:port" (e.g. --kdc dc1.cs.org:88): nothing to resolve,
	// and sending "dc1.cs.org:88" to the DNS client would just waste up to
	// the lookup timeout.
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if ip, err := LookupHostIP(cctx, nameserver, host, d); err == nil && ip != "" {
		return ip
	}
	return host
}

func withDefaultPort(host string, port int) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if net.ParseIP(host) != nil {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	// IPv6 literals without port come through SplitHostPort's error path too,
	// but JoinHostPort handles them correctly.
	return net.JoinHostPort(host, strconv.Itoa(port))
}
