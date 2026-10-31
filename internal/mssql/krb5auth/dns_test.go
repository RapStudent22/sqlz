package krb5auth

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// cannedA builds a DNS response with one A record for the queried name,
// reusing the query's question section (compression pointer 0xC00C).
func cannedA(query []byte, ip net.IP) []byte {
	resp := make([]byte, 12)
	copy(resp, query[:2])                    // same ID
	resp[2] = 0x81                           // QR + RD
	resp[3] = 0x80                           // RA
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT

	// question copied verbatim (name + qtype + qclass)
	qd := query[12:]
	for len(qd) > 0 && qd[0] != 0 {
		qd = qd[1+int(qd[0]):]
	}
	resp = append(resp, query[12:12+len(query)-12-len(qd)+1+4]...) // name + 0 + qtype + qclass

	// answer: pointer to name, type A, class IN, ttl, rdlen 4, addr
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, ip.To4()...)
	return resp
}

func startFakeDNS(t *testing.T, udp bool, tcp bool, respondFn func(query []byte) []byte) (addr string, stop func()) {
	t.Helper()
	var udpConn net.PacketConn
	var tcpLn net.Listener
	var err error
	respond := respondFn
	if respond == nil {
		respond = func(query []byte) []byte {
			return cannedA(query, net.IPv4(192, 168, 1, 195))
		}
	}
	stopFns := []func(){}
	if udp {
		udpConn, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 512)
			for {
				n, addr, err := udpConn.ReadFrom(buf)
				if err != nil {
					return
				}
				udpConn.WriteTo(respond(buf[:n]), addr)
			}
		}()
		stopFns = append(stopFns, func() { udpConn.Close() })
		addr = udpConn.LocalAddr().String()
	}
	if tcp {
		tcpLn, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := tcpLn.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					hdr := make([]byte, 2)
					if _, err := readFull(c, hdr); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(hdr))
					if _, err := readFull(c, q); err != nil {
						return
					}
					r := respond(q)
					binary.BigEndian.PutUint16(hdr, uint16(len(r)))
					c.Write(append(hdr, r...))
				}(c)
			}
		}()
		stopFns = append(stopFns, func() { tcpLn.Close() })
		addr = tcpLn.Addr().String()
	}
	return addr, func() {
		for _, f := range stopFns {
			f()
		}
	}
}

func readFull(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestLookupHostIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// UDP
	addr, stop := startFakeDNS(t, true, false, nil)
	ip, err := LookupHostIP(ctx, addr, "DC1.cs.org", nil)
	stop()
	if err != nil || ip != "192.168.1.195" {
		t.Fatalf("udp lookup = %q, %v", ip, err)
	}

	// TCP only (proxy-style path via a fake dialer)
	addr2, stop2 := startFakeDNS(t, false, true, nil)
	d := &fakeDialer{target: addr2, dials: make(chan string, 16)}
	ip, err = LookupHostIP(ctx, addr2, "DC1.cs.org", d)
	stop2()
	if err != nil || ip != "192.168.1.195" {
		t.Fatalf("tcp lookup = %q, %v", ip, err)
	}
	select {
	case dd := <-d.dials:
		want := "tcp:" + addr2
		if dd != want {
			t.Errorf("dial = %q, want %q", dd, want)
		}
	default:
		t.Error("no dial recorded")
	}
}

func TestLookupHostIPUDPFallbackToTCP(t *testing.T) {
	// UDP closed, TCP open: must fall back
	udpAddr, stopU := startFakeDNS(t, true, false, nil)
	stopU() // kill UDP
	_, port, _ := net.SplitHostPort(udpAddr)
	tcpAddr := net.JoinHostPort("127.0.0.1", port)
	ln, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 2)
				if _, err := readFull(c, hdr); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(hdr))
				if _, err := readFull(c, q); err != nil {
					return
				}
				r := cannedA(q, net.IPv4(10, 0, 0, 9))
				binary.BigEndian.PutUint16(hdr, uint16(len(r)))
				c.Write(append(hdr, r...))
			}(c)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ip, err := LookupHostIP(ctx, "127.0.0.1:"+port, "DC1.cs.org", nil)
	if err != nil || ip != "10.0.0.9" {
		t.Fatalf("tcp fallback lookup = %q, %v", ip, err)
	}
}

func TestBuildDNSQuery(t *testing.T) {
	q, err := buildDNSQuery("cs.org", 1)
	if err != nil {
		t.Fatal(err)
	}
	// header(12) + 1+2(cs) + 1+3(org) + 0 + type(2) + class(2) = 24
	if len(q) != 24 {
		t.Errorf("query len = %d, want 24 (%x)", len(q), q)
	}
}

// TestLookupHostIPTruncatedUDP checks the TC-bit fallback: the UDP server
// answers with a truncated response (TC=1, no answers), the TCP server has
// the full answer — the lookup must return the IP from the TCP exchange.
func TestLookupHostIPTruncatedUDP(t *testing.T) {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	_, portStr, _ := net.SplitHostPort(udpConn.LocalAddr().String())

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, 12)
			copy(resp, buf[:2])                      // same ID
			resp[2] = 0x83                           // QR + RD + TC
			binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT
			resp = append(resp, buf[12:n]...)        // question section only
			udpConn.WriteTo(resp, addr)
		}
	}()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:"+portStr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 2)
				if _, err := readFull(c, hdr); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(hdr))
				if _, err := readFull(c, q); err != nil {
					return
				}
				r := cannedA(q, net.IPv4(10, 9, 8, 7))
				binary.BigEndian.PutUint16(hdr, uint16(len(r)))
				c.Write(append(hdr, r...))
			}(c)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ip, err := LookupHostIP(ctx, "127.0.0.1:"+portStr, "DC1.cs.org", nil)
	if err != nil || ip != "10.9.8.7" {
		t.Fatalf("truncated-udp lookup = %q, %v; want 10.9.8.7 via TCP", ip, err)
	}
}

// TestLookupHostIPResponseValidation checks the response-vs-query checks:
// a mismatched transaction ID and a non-zero RCODE must surface as errors
// instead of being parsed as answers.
func TestLookupHostIPResponseValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("id mismatch", func(t *testing.T) {
		addr, stop := startFakeDNS(t, true, false, func(query []byte) []byte {
			resp := cannedA(query, net.IPv4(192, 168, 1, 195))
			id := binary.BigEndian.Uint16(resp[:2])
			binary.BigEndian.PutUint16(resp[:2], id+1)
			return resp
		})
		defer stop()
		_, err := LookupHostIP(ctx, addr, "DC1.cs.org", nil)
		if err == nil || !strings.Contains(err.Error(), "ID mismatch") {
			t.Fatalf("err = %v, want ID mismatch error", err)
		}
	})

	t.Run("nxdomain rcode", func(t *testing.T) {
		addr, stop := startFakeDNS(t, true, false, func(query []byte) []byte {
			resp := cannedA(query, net.IPv4(192, 168, 1, 195))
			resp[3] = 0x83 // QR|RD|RA flags + rcode 3 (NXDOMAIN)
			return resp
		})
		defer stop()
		_, err := LookupHostIP(ctx, addr, "DC1.cs.org", nil)
		if err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
			t.Fatalf("err = %v, want NXDOMAIN error", err)
		}
	})
}
