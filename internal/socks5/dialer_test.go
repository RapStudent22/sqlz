package socks5

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestDialContextDeadlineHonored: a proxy that accepts TCP but never answers
// the SOCKS5 greeting must not hang the dial past the context deadline.
// (The LDAP discovery paths rely on this: they wrap the dial in a
// context.WithTimeout.)
func TestDialContextDeadlineHonored(t *testing.T) {
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

	d, err := Parse(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.DialContext(ctx, "tcp", "10.0.0.5:1433"); err == nil {
		t.Fatal("dial must fail against a silent proxy")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("dial took %v, want ~300ms (context deadline)", elapsed)
	}
}
