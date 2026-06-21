package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Dialer routes TCP connections through a SOCKS5 proxy.
// It implements the DialContext interface required by mssql.Connector.Dialer
// and can be used to pre-establish connections for LDAP.
type Dialer struct {
	proxyAddr string
	username  string
	password  string
}

// Parse creates a Dialer from a URL string.
// Accepted formats:
//
//	socks5://host:port
//	socks5://user:pass@host:port
//	host:port  (assumes socks5://)
func Parse(rawURL string) (*Dialer, error) {
	if !strings.HasPrefix(rawURL, "socks5://") && !strings.HasPrefix(rawURL, "socks5h://") {
		rawURL = "socks5://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", rawURL, err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme %q (want socks5)", u.Scheme)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "1080"
	}

	d := &Dialer{proxyAddr: net.JoinHostPort(host, port)}
	if u.User != nil {
		d.username = u.User.Username()
		d.password, _ = u.User.Password()
	}
	return d, nil
}

// DialContext connects to addr via the SOCKS5 proxy, honoring ctx for cancellation.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy %s: %w", d.proxyAddr, err)
	}
	if err := negotiate(conn, addr, d.username, d.password); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func negotiate(conn net.Conn, addr, username, password string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("socks5: invalid target address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("socks5: invalid target port %q: %w", portStr, err)
	}

	// Greeting: offer auth methods
	var greeting []byte
	if username != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02} // no-auth + user/pass
	} else {
		greeting = []byte{0x05, 0x01, 0x00} // no-auth only
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5: greeting write: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: greeting response: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5: unexpected version %d in server response", resp[0])
	}

	switch resp[1] {
	case 0x00: // no authentication required
	case 0x02: // username/password (RFC 1929)
		if username == "" {
			return fmt.Errorf("socks5: proxy requires auth but no credentials provided")
		}
		auth := make([]byte, 0, 3+len(username)+len(password))
		auth = append(auth, 0x01, byte(len(username)))
		auth = append(auth, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if _, err := conn.Write(auth); err != nil {
			return fmt.Errorf("socks5: auth write: %w", err)
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			return fmt.Errorf("socks5: auth response: %w", err)
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("socks5: authentication failed")
		}
	case 0xFF:
		return fmt.Errorf("socks5: no acceptable auth methods")
	default:
		return fmt.Errorf("socks5: unsupported auth method 0x%02x", resp[1])
	}

	// CONNECT request (ATYP=DOMAINNAME)
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port&0xFF))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: CONNECT write: %w", err)
	}

	// Response header: VER REP RSV ATYP
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5: CONNECT response: %w", err)
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5: CONNECT rejected: %s", connectError(hdr[1]))
	}

	// Drain BND.ADDR + BND.PORT
	switch hdr[3] {
	case 0x01: // IPv4 (4 bytes) + port (2 bytes)
		io.ReadFull(conn, make([]byte, 6))
	case 0x03: // domain: 1-byte length + N bytes + 2-byte port
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		io.ReadFull(conn, make([]byte, int(lb[0])+2))
	case 0x04: // IPv6 (16 bytes) + port (2 bytes)
		io.ReadFull(conn, make([]byte, 18))
	default:
		return fmt.Errorf("socks5: unknown ATYP 0x%02x in response", hdr[3])
	}

	return nil
}

func connectError(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error 0x%02x", code)
	}
}
