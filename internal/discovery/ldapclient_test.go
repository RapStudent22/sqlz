package discovery

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// fakeLDAPConn pairs an ldapConn with a scripted server side of a pipe:
// every request the client writes is answered with respond(request), or
// left unanswered when respond returns nil.
func fakeLDAPConn(t *testing.T, respond func(request []byte) []byte) *ldapConn {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	go func() {
		defer serverSide.Close()
		buf := make([]byte, 65536)
		for {
			n, err := serverSide.Read(buf)
			if err != nil {
				return
			}
			if resp := respond(buf[:n]); resp != nil {
				if _, err := serverSide.Write(resp); err != nil {
					return
				}
			}
		}
	}()
	return &ldapConn{c: clientSide, br: bufio.NewReader(clientSide)}
}

// ldapResponse wraps a protocolOp into a full LDAPMessage (message ID 1).
func ldapResponse(op *ber.Packet) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))
	env.AppendChild(op)
	return env.Bytes()
}

// The DC rejects paged searches when the Controls field of the LDAPMessage
// is a universal SEQUENCE instead of the RFC 4511 context tag 0, and when
// the paging cookie element is absent — these tests pin both.
func TestPagingControlEncoding(t *testing.T) {
	ctrl := pagingControl(1000, nil)

	// control itself: SEQUENCE { OID, OCTET STRING value }
	if ctrl.Tag != ber.TagSequence {
		t.Fatalf("control tag = %x, want 0x30", ctrl.Tag)
	}
	if len(ctrl.Children) != 2 {
		t.Fatalf("control children = %d, want 2", len(ctrl.Children))
	}
	// its value must carry the inner sequence:
	// SEQUENCE { INTEGER 1000, OCTET STRING "" } — cookie always present
	inner := ctrl.Children[1].Data.Bytes()
	wantInner := []byte{0x30, 0x06, 0x02, 0x02, 0x03, 0xe8, 0x04, 0x00}
	if !bytes.Equal(inner, wantInner) {
		t.Errorf("control value = %x, want %x", inner, wantInner)
	}

	// the controls wrapper must be context-specific tag 0, not a universal
	// SEQUENCE: asn1-ber reports the class separately from the tag number
	seq := encodeControlsSeq([]*ber.Packet{ctrl})
	if seq.ClassType != ber.ClassContext || seq.Tag != 0 {
		t.Errorf("controls wrapper = class %d tag %d, want ClassContext/0", seq.ClassType, seq.Tag)
	}
}

// TestSearchSPNsResultCode: a SearchResultDone with a non-zero result code
// (here 4 = sizeLimitExceeded) must surface as an error instead of silently
// returning a partial/empty SPN list.
func TestSearchSPNsResultCode(t *testing.T) {
	conn := fakeLDAPConn(t, func(request []byte) []byte {
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "SearchResultDone")
		op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 4, "resultCode"))
		return ldapResponse(op)
	})

	_, err := conn.searchSPNs("DC=cs,DC=org", "(servicePrincipalName=MSSQLSvc/*)")
	if err == nil || !strings.Contains(err.Error(), "result 4") {
		t.Fatalf("err = %v, want ldap search failed: result 4", err)
	}
}

// TestBindSASLMalformedResponse: a BindResponse without children must yield
// an error, never a panic.
func TestBindSASLMalformedResponse(t *testing.T) {
	conn := fakeLDAPConn(t, func(request []byte) []byte {
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 1, nil, "BindResponse")
		return ldapResponse(op)
	})

	err := conn.bindSASL([]byte("token"), "user")
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("err = %v, want malformed BindResponse error", err)
	}
}

// TestBindSASLSuccess: result code 0 must be accepted.
func TestBindSASLSuccess(t *testing.T) {
	conn := fakeLDAPConn(t, func(request []byte) []byte {
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 1, nil, "BindResponse")
		op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
		return ldapResponse(op)
	})

	if err := conn.bindSASL([]byte("token"), "user"); err != nil {
		t.Fatalf("bindSASL = %v, want success", err)
	}
}

// TestInstancesFromSPNs: hosts dedupe case-insensitively, and an SPN with an
// instance name instead of a port keeps that name on the instance.
func TestInstancesFromSPNs(t *testing.T) {
	spns := []string{
		"MSSQLSvc/SQL01.cs.org:1433",
		"MSSQLSvc/sql01.cs.org:1433", // case-only duplicate
		"MSSQLSvc/SQL01.cs.org:1444",
		"MSSQLSvc/SQL02.cs.org:NAMED",
	}
	instances := instancesFromSPNs(spns)

	if len(instances) != 3 {
		t.Fatalf("got %d instances, want 3: %+v", len(instances), instances)
	}
	if instances[0].Hostname != "SQL01.cs.org" || instances[0].Port != 1433 {
		t.Errorf("instances[0] = %+v", instances[0])
	}
	if instances[1].Port != 1444 {
		t.Errorf("instances[1] = %+v, want port 1444", instances[1])
	}
	if instances[2].Instance != "NAMED" || instances[2].Port != 1433 {
		t.Errorf("instances[2] = %+v, want named instance NAMED on port 1433", instances[2])
	}
}
