package discovery

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

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
