package krb5auth

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// KeyEntry is one raw key for the in-memory keytab.
type KeyEntry struct {
	EType int32
	Key   []byte
	KVNO  uint8
}

// keytabFromKeys builds an in-memory keytab holding raw key material
// (AES128/AES256/RC4), the same way impacket does for pass-the-key and
// pass-the-hash. No file is ever written to disk.
func keytabFromKeys(username, realm string, keys []KeyEntry) (*keytab.Keytab, error) {
	if username == "" || realm == "" {
		return nil, fmt.Errorf("krb5: keytab requires username and realm")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("krb5: keytab requires at least one key")
	}

	data := []byte{0x05, 0x02} // file format version 2, big-endian

	for _, k := range keys {
		if k.KVNO == 0 {
			k.KVNO = 1
		}
		eb := marshalKeytabEntry(username, realm, k)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(len(eb)))
		data = append(data, buf...)
		data = append(data, eb...)
	}

	data = append(data, 0, 0, 0, 0) // entry count terminator

	kt := keytab.New()
	if err := kt.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("krb5: build in-memory keytab: %w", err)
	}
	return kt, nil
}

// marshalKeytabEntry encodes one keytab entry in the MIT keytab v2 format
// (big-endian), mirroring gokrb5's own marshal code so Unmarshal round-trips.
func marshalKeytabEntry(username, realm string, k KeyEntry) []byte {
	var b []byte

	put16 := func(v uint16) {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, v)
		b = append(b, buf...)
	}
	put32 := func(v uint32) {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, v)
		b = append(b, buf...)
	}
	putStr := func(s string) {
		put16(uint16(len(s)))
		b = append(b, s...)
	}

	// principal
	put16(1) // number of components (plain user principal)
	putStr(realm)
	putStr(username)
	put32(uint32(nametype.KRB_NT_PRINCIPAL))

	put32(uint32(time.Now().Unix())) // timestamp
	b = append(b, k.KVNO)            // 8-bit key version number
	put16(uint16(k.EType))           // encryption type
	put16(uint16(len(k.Key)))        // key length
	b = append(b, k.Key...)

	return b
}
