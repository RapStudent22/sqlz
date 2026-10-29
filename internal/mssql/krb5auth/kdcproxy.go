package krb5auth

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Dialer is the minimal dialing interface accepted by ProxyKDC (implemented
// by the SOCKS5 dialer).
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// kdcProxy relays KDC TCP traffic through a SOCKS5 dialer. gokrb5 dials the
// KDC itself with no injection point, so instead a local listener is
// started and the runtime krb5 config points the KDC at it; every accepted
// connection is tunneled to the real KDC through the dialer.
type kdcProxy struct {
	ln     net.Listener
	kdc    string
	dialer Dialer
}

// kdcProxyCache shares one relay per KDC address for the whole process (a
// CLI run uses a single --proxy anyway). The relays live until exit.
var kdcProxyCache sync.Map // kdcAddr -> *kdcProxy

// ProxyKDC returns the address the krb5 config should use for the KDC.
// With a nil dialer the real address passes through unchanged; otherwise a
// local relay is started (once per KDC address) and its 127.0.0.1:port is
// returned, so all KDC traffic flows through the dialer.
func ProxyKDC(kdcAddr string, d Dialer) (string, error) {
	if d == nil {
		return kdcAddr, nil
	}
	if v, ok := kdcProxyCache.Load(kdcAddr); ok {
		return v.(*kdcProxy).addr(), nil
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("kerberos: start KDC relay: %w", err)
	}
	p := &kdcProxy{ln: ln, kdc: kdcAddr, dialer: d}
	go p.serve()
	kdcProxyCache.Store(kdcAddr, p)
	return p.addr(), nil
}

func (p *kdcProxy) addr() string {
	return p.ln.Addr().String()
}

func (p *kdcProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go p.handle(c)
	}
}

// handle tunnels one client connection to the real KDC through the dialer.
func (p *kdcProxy) handle(client net.Conn) {
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	upstream, err := p.dialer.DialContext(ctx, "tcp", p.kdc)
	if err != nil {
		return // client gets EOF/RST: gokrb5 reports the KDC as unreachable
	}
	defer upstream.Close()

	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, client)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(client, upstream)
	<-done
}
