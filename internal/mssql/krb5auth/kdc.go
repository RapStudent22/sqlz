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

	r := NameserverResolver(nameserver, d)

	realm := strings.ToUpper(domain)
	// AD forest root DCs, then the realm fallback.
	srvNames := []string{"dc._msdcs." + domain, realm}
	for _, name := range srvNames {
		_, addrs, err := r.LookupSRV(ctx, "kerberos", "tcp", name)
		if err != nil || len(addrs) == 0 {
			continue
		}
		target := strings.TrimSuffix(addrs[0].Target, ".")
		// Resolve the KDC hostname to an IP with the same resolver so the
		// KDC config never depends on the system resolver (stock-Kali
		// guarantee: the lab domain is often not in /etc/resolv.conf).
		// gokrb5 dials whatever address we hand it; an IP skips its own
		// hostname resolution entirely.
		if ip := resolveHost(ctx, r, target); ip != "" {
			return net.JoinHostPort(ip, strconv.Itoa(int(addrs[0].Port))), nil
		}
		return net.JoinHostPort(target, strconv.Itoa(int(addrs[0].Port))), nil
	}

	return "", fmt.Errorf(
		"cannot resolve KDC for domain %q via DNS SRV (lookups respect --nameserver); specify --kdc or --dc-ip explicitly", domain)
}

// resolveHost resolves a hostname with the given resolver and returns the
// first IPv4 address, or "" on failure.
func resolveHost(ctx context.Context, r *net.Resolver, host string) string {
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			return addr
		}
	}
	return ""
}

// resolveOrSelf resolves a KDC/DC hostname to an IP via the nameserver so
// the krb5 config never depends on the system resolver. IP literals and
// unresolvable names pass through unchanged (the dial error will name the
// host clearly).
func resolveOrSelf(ctx context.Context, host, nameserver string, d Dialer) string {
	if net.ParseIP(host) != nil || nameserver == "" {
		return host
	}
	r := NameserverResolver(nameserver, d)
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if ip := resolveHost(cctx, r, host); ip != "" {
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
