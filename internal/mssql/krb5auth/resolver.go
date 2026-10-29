package krb5auth

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// NameserverResolver builds a *net.Resolver that queries the given
// nameserver. With a SOCKS5 dialer, DNS goes over TCP through the proxy:
// the CONNECT dialer cannot tunnel UDP, and the Go resolver does not fall
// back to TCP when the UDP dial itself fails — so the "udp" path is
// emulated with a TCP connection that adds the DNS-over-TCP length framing.
func NameserverResolver(ns string, d Dialer) *net.Resolver {
	r := &net.Resolver{PreferGo: true}
	r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if d == nil {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ns, "53"))
		}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ns, "53"))
		if err != nil {
			return nil, err
		}
		if network == "tcp" {
			// the resolver frames DNS-over-TCP itself
			return c, nil
		}
		// emulate a datagram exchange over the TCP stream
		return &dnsTCPConn{Conn: c}, nil
	}
	return r
}

// dnsTCPConn adapts a TCP stream to the datagram-style reads and writes the
// Go resolver uses for the "udp" network: writes are length-prefixed and
// reads return one full DNS message at a time (RFC 1035 4.2.2).
type dnsTCPConn struct {
	net.Conn
	left int
}

func (c *dnsTCPConn) Write(p []byte) (int, error) {
	if len(p) > 0xFFFF {
		return 0, fmt.Errorf("dns: message too large (%d bytes)", len(p))
	}
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(p)))
	if _, err := c.Conn.Write(hdr); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *dnsTCPConn) Read(p []byte) (int, error) {
	if c.left == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		c.left = int(binary.BigEndian.Uint16(hdr[:]))
	}
	n := len(p)
	if n > c.left {
		n = c.left
	}
	m, err := c.Conn.Read(p[:n])
	c.left -= m
	return m, err
}

// ReadFrom and WriteTo make dnsTCPConn a net.PacketConn: the Go resolver
// then takes its datagram path (unframed write + framed read) instead of
// the stream path, which would add its own TCP framing on top of ours.
func (c *dnsTCPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, nil, err
}

func (c *dnsTCPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}
