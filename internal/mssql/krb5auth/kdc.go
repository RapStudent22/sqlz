package krb5auth

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ResolveKDC determines the KDC address (host:port) for a domain.
// Priority order (never reads /etc/krb5.conf):
//
//	explicit --kdc value → --dc-ip → DNS SRV via the configured nameserver → error
//
// The SRV lookups respect the existing --nameserver flag: queries are sent
// to that server instead of the system resolver.
func ResolveKDC(ctx context.Context, kdcFlag, dcIP, domain, nameserver string) (string, error) {
	if kdcFlag != "" {
		return withDefaultPort(kdcFlag, 88), nil
	}
	if dcIP != "" {
		return withDefaultPort(dcIP, 88), nil
	}
	if domain == "" {
		return "", fmt.Errorf(
			"cannot determine KDC: specify --kdc, --dc-ip or --domain for DNS SRV discovery")
	}

	r := &net.Resolver{PreferGo: true}
	if nameserver != "" {
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{}
			return d.DialContext(ctx, network, net.JoinHostPort(nameserver, "53"))
		}
	}

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
