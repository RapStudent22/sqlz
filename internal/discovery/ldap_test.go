package discovery

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/RapStudent22/sqlz/internal/socks5"
)

// TestDiscoverSQLInstancesProxyDialTimeout: a proxy that accepts TCP but
// never completes the SOCKS5 handshake must make discovery fail with an
// error instead of hanging forever (the dial is wrapped in a timeout).
func TestDiscoverSQLInstancesProxyDialTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Silent proxy: accept, read whatever arrives, never respond.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	old := ldapDialTimeout
	ldapDialTimeout = 300 * time.Millisecond
	defer func() { ldapDialTimeout = old }()

	d, err := socks5.Parse(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = DiscoverSQLInstances(LDAPConfig{
		Server:   "192.168.1.195",
		Username: "u",
		Password: "p",
		Dialer:   d,
	})
	if err == nil || !strings.Contains(err.Error(), "ldap connect") {
		t.Fatalf("err = %v, want an ldap connect error", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("discovery took %v, want ~300ms (dial timeout)", elapsed)
	}
}
