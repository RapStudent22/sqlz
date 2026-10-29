package krb5auth

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// fakeDialer routes every dial to a fixed address, recording the dials.
type fakeDialer struct {
	target string
	dials  chan string
}

func (f *fakeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	select {
	case f.dials <- network + ":" + addr:
	default:
	}
	return (&net.Dialer{}).DialContext(ctx, network, f.target)
}

func TestKDCProxyRelay(t *testing.T) {
	// fake KDC: echoes whatever it reads back
	kdcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer kdcLn.Close()
	go func() {
		for {
			c, err := kdcLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	d := &fakeDialer{target: kdcLn.Addr().String(), dials: make(chan string, 16)}
	local, err := ProxyKDC("192.168.1.195:88", d)
	if err != nil {
		t.Fatalf("ProxyKDC: %v", err)
	}
	if local == "192.168.1.195:88" {
		t.Fatalf("ProxyKDC must return a local address, got the real one")
	}

	// the relay is shared per KDC address
	local2, err := ProxyKDC("192.168.1.195:88", d)
	if err != nil || local2 != local {
		t.Errorf("second ProxyKDC = %q, %v; want the same %q", local2, err, local)
	}

	// send data through the relay and expect the echo
	conn, err := net.DialTimeout("tcp", local, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}

	// the upstream dial must have targeted the real KDC address
	select {
	case d := <-d.dials:
		if d != "tcp:192.168.1.195:88" {
			t.Errorf("upstream dial = %q, want tcp:192.168.1.195:88", d)
		}
	case <-time.After(2 * time.Second):
		t.Error("no upstream dial recorded")
	}
}

func TestProxyKDCNoDialer(t *testing.T) {
	got, err := ProxyKDC("kdc.corp.local:88", nil)
	if err != nil || got != "kdc.corp.local:88" {
		t.Errorf("ProxyKDC(nil) = %q, %v; want passthrough", got, err)
	}
}
