package krb5auth

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Self-contained DNS wire client: lookups against a fixed nameserver, with
// zero dependence on the system resolver (net.Resolver with PreferGo
// behaves inconsistently across platforms — on Windows it reads the local
// DNS configuration, not the requested nameserver). UDP is tried first,
// then TCP; with a SOCKS5 dialer only TCP is possible and is used directly.

const dnsTimeout = 3 * time.Second

// LookupHostIP resolves host via the nameserver and returns the first IPv4
// address from the A record. Empty nameserver uses the system resolver.
func LookupHostIP(ctx context.Context, ns, host string, d Dialer) (string, error) {
	if ns == "" {
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return "", err
		}
		return addrs[0], nil
	}
	msg, err := dnsQuery(ctx, ns, host, 1, d) // type A
	if err != nil {
		return "", err
	}
	for _, a := range parseDNSAnswers(msg, 1) {
		if ip := net.ParseIP(a.text); ip != nil && ip.To4() != nil {
			return a.text, nil
		}
	}
	return "", fmt.Errorf("dns: no A record for %s", host)
}

// LookupSRV resolves _kerberos._tcp.<name> via the nameserver and returns
// the first target and port.
func LookupSRV(ctx context.Context, ns, name string, d Dialer) (string, uint16, error) {
	if ns == "" {
		_, addrs, err := net.DefaultResolver.LookupSRV(ctx, "kerberos", "tcp", name)
		if err != nil || len(addrs) == 0 {
			return "", 0, err
		}
		return strings.TrimSuffix(addrs[0].Target, "."), addrs[0].Port, nil
	}
	msg, err := dnsQuery(ctx, ns, "_kerberos._tcp."+name, 33, d) // type SRV
	if err != nil {
		return "", 0, err
	}
	for _, a := range parseDNSAnswers(msg, 33) {
		return strings.TrimSuffix(a.text, "."), a.port, nil
	}
	return "", 0, fmt.Errorf("dns: no SRV record for %s", name)
}

// LookupPTR resolves an IP back to a hostname via the nameserver.
func LookupPTR(ctx context.Context, ns, ip string, d Dialer) (string, error) {
	if ns == "" {
		names, err := net.DefaultResolver.LookupAddr(ctx, ip)
		if err != nil || len(names) == 0 {
			return "", err
		}
		return strings.TrimSuffix(names[0], "."), nil
	}
	// reverse name: 1.2.3.4 -> 4.3.2.1.in-addr.arpa
	parts := strings.Split(ip, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	name := strings.Join(parts, ".") + ".in-addr.arpa"
	msg, err := dnsQuery(ctx, ns, name, 12, d) // type PTR
	if err != nil {
		return "", err
	}
	for _, a := range parseDNSAnswers(msg, 12) {
		return strings.TrimSuffix(a.text, "."), nil
	}
	return "", fmt.Errorf("dns: no PTR record for %s", ip)
}

// nsAddr returns the nameserver address, appending the DNS port when the
// caller passed a bare host or IP.
func nsAddr(ns string) string {
	if _, _, err := net.SplitHostPort(ns); err == nil {
		return ns
	}
	return net.JoinHostPort(ns, "53")
}

// errTruncated signals a UDP response with the TC bit set: without EDNS0
// the server truncates answers at 512 bytes, and the full answer must be
// re-queried over TCP.
var errTruncated = errors.New("dns: truncated response")

// checkDNSResponse validates a response packet against the query:
// transaction ID, QR bit, RCODE and the TC (truncation) bit.
func checkDNSResponse(query, resp []byte) error {
	if len(resp) < 12 {
		return fmt.Errorf("dns: short response (%d bytes)", len(resp))
	}
	if !bytes.Equal(resp[:2], query[:2]) {
		return fmt.Errorf("dns: response ID mismatch (got 0x%04x, want 0x%04x)",
			binary.BigEndian.Uint16(resp[:2]), binary.BigEndian.Uint16(query[:2]))
	}
	if resp[2]&0x80 == 0 {
		return fmt.Errorf("dns: packet is not a response (QR=0)")
	}
	if code := resp[3] & 0x0F; code != 0 {
		return fmt.Errorf("dns: server error %s (rcode %d)", rcodeName(code), code)
	}
	if resp[2]&0x02 != 0 {
		return errTruncated
	}
	return nil
}

// rcodeName maps a DNS response code to its mnemonic.
func rcodeName(code byte) string {
	switch code {
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return "UNKNOWN"
}

// dnsQuery builds a query for qname/qtype, sends it over UDP first and
// falls back to TCP, and returns the response message.
func dnsQuery(ctx context.Context, ns, qname string, qtype uint16, d Dialer) ([]byte, error) {
	q, err := buildDNSQuery(qname, qtype)
	if err != nil {
		return nil, err
	}

	if d != nil {
		return dnsTCPExchange(ctx, ns, q, d)
	}

	// UDP first; a truncated (TC) answer is re-queried over TCP.
	if resp, err := dnsUDPExchange(ctx, ns, q); err == nil {
		if verr := checkDNSResponse(q, resp); verr == nil {
			return resp, nil
		} else if verr != errTruncated {
			return nil, verr
		}
	}
	return dnsTCPExchange(ctx, ns, q, nil)
}

func buildDNSQuery(qname string, qtype uint16) ([]byte, error) {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], uint16(rand.Intn(0xFFFF)))
	q[2] = 0x01 // RD
	q[3] = 0x00
	binary.BigEndian.PutUint16(q[4:6], 1) // QDCOUNT
	for _, label := range strings.Split(qname, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("dns: label too long in %q", qname)
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	q = append(q, byte(qtype>>8), byte(qtype&0xFF))
	q = append(q, 0, 1) // IN
	return q, nil
}

func dnsUDPExchange(ctx context.Context, ns string, q []byte) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(cctx, "udp", nsAddr(ns))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dnsTimeout))
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func dnsTCPExchange(ctx context.Context, ns string, q []byte, d Dialer) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	var conn net.Conn
	var err error
	if d != nil {
		conn, err = d.DialContext(cctx, "tcp", nsAddr(ns))
	} else {
		conn, err = (&net.Dialer{}).DialContext(cctx, "tcp", nsAddr(ns))
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dnsTimeout))

	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(q)))
	if _, err := conn.Write(append(hdr, q...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if err := checkDNSResponse(q, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// dnsAnswer is one parsed answer record.
type dnsAnswer struct {
	text string // A: dotted-quad, PTR/SRV: hostname
	port uint16 // SRV only
}

// parseDNSAnswers extracts the answers of the wanted type from a response.
func parseDNSAnswers(msg []byte, wantType uint16) []dnsAnswer {
	if len(msg) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	// skip questions
	for i := 0; i < qd; i++ {
		_, next := readDNSName(msg, off)
		off = next + 4 // name + qtype + qclass
	}

	var out []dnsAnswer
	for i := 0; i < an && off+10 <= len(msg); i++ {
		_, next := readDNSName(msg, off)
		off = next
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		rdataStart := off + 10
		if rdataStart+rdlen > len(msg) {
			break
		}
		rdata := msg[rdataStart : rdataStart+rdlen]
		off = rdataStart + rdlen
		if rtype != wantType {
			continue
		}
		switch wantType {
		case 1: // A
			if len(rdata) == 4 {
				out = append(out, dnsAnswer{text: net.IPv4(rdata[0], rdata[1], rdata[2], rdata[3]).String()})
			}
		case 12: // PTR
			name, _ := readDNSName(msg, rdataStart)
			out = append(out, dnsAnswer{text: name})
		case 33: // SRV
			if len(rdata) >= 7 {
				target, _ := readDNSName(msg, rdataStart+6)
				out = append(out, dnsAnswer{text: target, port: binary.BigEndian.Uint16(rdata[4:6])})
			}
		}
	}
	return out
}

// readDNSName decodes a (possibly compressed) domain name from the packet
// and returns it with the offset after the name in the linear stream.
func readDNSName(pkt []byte, off int) (string, int) {
	var sb strings.Builder
	next := off
	jumped := false
	hops := 0
	for hops < 10 {
		if off >= len(pkt) {
			break
		}
		b := pkt[off]
		if b == 0 {
			if !jumped {
				next = off + 1
			}
			break
		}
		if b&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				break
			}
			if !jumped {
				next = off + 2
				jumped = true
			}
			off = int(b&0x3F)<<8 | int(pkt[off+1])
			hops++
			continue
		}
		if off+1+int(b) > len(pkt) {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(pkt[off+1 : off+1+int(b)])
		off += 1 + int(b)
	}
	return sb.String(), next
}
