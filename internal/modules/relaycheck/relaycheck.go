package relaycheck

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/RapStudent22/sqlz/internal/models"
)

type EncryptMode byte

const (
	EncryptOff    EncryptMode = 0x00
	EncryptOn     EncryptMode = 0x01
	EncryptNotSup EncryptMode = 0x02
	EncryptReq    EncryptMode = 0x03
)

func (e EncryptMode) String() string {
	switch e {
	case EncryptOff:
		return "ENCRYPT_OFF"
	case EncryptOn:
		return "ENCRYPT_ON"
	case EncryptNotSup:
		return "ENCRYPT_NOT_SUP"
	case EncryptReq:
		return "ENCRYPT_REQ"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", byte(e))
	}
}

type Result struct {
	Instance     models.SQLInstance
	Encrypt      EncryptMode
	ForceEncrypt bool
	Relayable    bool
	Error        string
}

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Options struct {
	Workers int
	Timeout time.Duration
	Dialer  Dialer
}

// Minimal TDS pre-login packet asking the server for its encryption preference.
// Header (8 bytes) + option list (VERSION + ENCRYPT + terminator) + data.
var preLoginPacket = []byte{
	// TDS header: type=0x12 (pre-login), status=0x01 (EOM), length=26
	0x12, 0x01, 0x00, 0x1A, 0x00, 0x00, 0x01, 0x00,
	// VERSION option: token=0x00, data offset=11, data length=6
	0x00, 0x00, 0x0B, 0x00, 0x06,
	// ENCRYPT option: token=0x01, data offset=17, data length=1
	0x01, 0x00, 0x11, 0x00, 0x01,
	// TERMINATOR
	0xFF,
	// VERSION data (6 bytes, all zeros)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// ENCRYPT data: 0x00 = client says ENCRYPT_OFF
	0x00,
}

func Check(instance models.SQLInstance, opts Options) Result {
	result := Result{Instance: instance}

	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}

	addr := fmt.Sprintf("%s:%d", instance.ConnectionHost(), instance.Port)

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	var conn net.Conn
	var err error
	if opts.Dialer != nil {
		conn, err = opts.Dialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(opts.Timeout))

	if _, err := conn.Write(preLoginPacket); err != nil {
		result.Error = fmt.Sprintf("send pre-login: %v", err)
		return result
	}

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		result.Error = fmt.Sprintf("read header: %v", err)
		return result
	}

	// Server responds to pre-login with packet type 0x04 (TABULAR_RESULT / packReply),
	// not 0x12 (pre-login request type).
	if hdr[0] != 0x04 {
		result.Error = fmt.Sprintf("unexpected packet type 0x%02X (not a SQL Server?)", hdr[0])
		return result
	}

	pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if pktLen < 8 {
		result.Error = fmt.Sprintf("invalid packet length %d", pktLen)
		return result
	}

	body := make([]byte, pktLen-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		result.Error = fmt.Sprintf("read body: %v", err)
		return result
	}

	enc, err := parseEncrypt(body)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Encrypt = enc
	result.ForceEncrypt = enc == EncryptReq
	result.Relayable = enc != EncryptReq
	return result
}

// parseEncrypt walks the pre-login option list and returns the server's ENCRYPT value.
func parseEncrypt(body []byte) (EncryptMode, error) {
	i := 0
	for i < len(body) {
		if body[i] == 0xFF {
			break
		}
		if i+5 > len(body) {
			return 0, fmt.Errorf("truncated option list at byte %d", i)
		}
		token := body[i]
		offset := int(binary.BigEndian.Uint16(body[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(body[i+3 : i+5]))
		i += 5

		if token == 0x01 { // ENCRYPT
			if length < 1 || offset >= len(body) || offset+length > len(body) {
				return 0, fmt.Errorf("ENCRYPT option out of bounds (offset=%d len=%d body=%d)", offset, length, len(body))
			}
			return EncryptMode(body[offset]), nil
		}
	}
	return EncryptOff, nil
}

func Run(instances []models.SQLInstance, opts Options, cb func(Result)) {
	if opts.Workers <= 0 {
		opts.Workers = 50
	}

	sem := make(chan struct{}, opts.Workers)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, inst := range instances {
		wg.Add(1)
		sem <- struct{}{}
		go func(i models.SQLInstance) {
			defer wg.Done()
			defer func() { <-sem }()
			r := Check(i, opts)
			mu.Lock()
			cb(r)
			mu.Unlock()
		}(inst)
	}
	wg.Wait()
}
