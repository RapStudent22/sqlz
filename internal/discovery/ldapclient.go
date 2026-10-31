package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"

	"github.com/RapStudent22/sqlz/internal/models"
	"github.com/RapStudent22/sqlz/internal/mssql/krb5auth"
)

// ldapConn is a minimal LDAPv3 client — just enough for a SASL bind and a
// paged search. go-ldap's SASL bind hardcodes the GSSAPI mechanism, which
// Active Directory rejects for Kerberos; AD expects GSS-SPNEGO (what
// impacket sends), so the bind is implemented here.
type ldapConn struct {
	c     net.Conn
	br    *bufio.Reader
	msgID int
}

func (l *ldapConn) nextID() int {
	l.msgID++
	return l.msgID
}

// send encodes one LDAPMessage (protocolOp already wrapped in its
// APPLICATION tag) and writes it to the connection.
func (l *ldapConn) send(protocolOp *ber.Packet, controls ...*ber.Packet) error {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextID(), "MessageID"))
	env.AppendChild(protocolOp)
	if len(controls) > 0 {
		env.AppendChild(encodeControlsSeq(controls))
	}
	_, err := l.c.Write(env.Bytes())
	return err
}

// read reads one LDAPMessage and returns its protocolOp packet plus the
// optional controls sequence.
func (l *ldapConn) read() (protocolOp, controls *ber.Packet, err error) {
	pkt, err := ber.ReadPacket(l.br)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap read: %w", err)
	}
	// envelope: [0] message id, [1] protocol op, [2] optional controls
	if len(pkt.Children) < 2 {
		return nil, nil, fmt.Errorf("ldap: short message")
	}
	protocolOp = pkt.Children[1]
	if len(pkt.Children) > 2 {
		controls = pkt.Children[2]
	}
	return protocolOp, controls, nil
}

// encodeControlsSeq wraps request controls into the SEQUENCE of controls.
// encodeControlsSeq wraps request controls into the [0] Controls field of
// an LDAPMessage — RFC 4511 uses context-specific tag 0 here, not a
// universal SEQUENCE (AD rejects the latter with "unable to decode the
// controls").
func encodeControlsSeq(controls []*ber.Packet) *ber.Packet {
	seq := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, c := range controls {
		seq.AppendChild(c)
	}
	return seq
}

// pagingControl builds the Microsoft paged results control request. The
// cookie element must ALWAYS be present (empty on the first page) — AD
// rejects the control outright otherwise.
func pagingControl(pageSize int, cookie []byte) *ber.Packet {
	ctrl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	ctrl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		ldap.ControlTypePaging, "Control Type"))

	val := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value")
	val.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, pageSize, "Paging Size"))
	val.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(cookie), "Cookie"))
	ctrl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(val.Bytes()), "Control Value"))
	return ctrl
}

// pagingCookie extracts the paging cookie from a SearchResultDone response
// control, if present.
func pagingCookie(controls *ber.Packet) []byte {
	if controls == nil {
		return nil
	}
	for _, c := range controls.Children {
		// control: [0] OID, [1] optional criticality, [2] value
		if len(c.Children) < 3 || c.Children[0].Value == nil {
			continue
		}
		if c.Children[0].Value.(string) != ldap.ControlTypePaging {
			continue
		}
		val := ber.DecodePacket(c.Children[2].ByteValue)
		if val == nil || len(val.Children) == 0 {
			continue
		}
		return val.Children[0].ByteValue
	}
	return nil
}

// resultCode extracts the Enumerated result code from a BindResponse /
// SearchResultDone packet. ok is false when the packet has no Enumerated
// child (malformed or truncated response).
func resultCode(op *ber.Packet) (code int64, ok bool) {
	if len(op.Children) == 0 || op.Children[0].Tag != ber.TagEnumerated {
		return 0, false
	}
	code, ok = op.Children[0].Value.(int64)
	return code, ok
}

// bind performs the SASL GSS-SPNEGO bind with the SPNEGO token built from
// the Kerberos client.
func (l *ldapConn) bindSASL(spnegoToken []byte, username string) error {
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, username, "Name"))

	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "authentication")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSS-SPNEGO", "SASL Mech"))
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(spnegoToken), "SASL Creds"))
	req.AppendChild(auth)

	if err := l.send(req); err != nil {
		return err
	}
	op, _, err := l.read()
	if err != nil {
		return err
	}
	// BindResponse: [0] result code, [1] matched DN, [2] diagnostic message
	code, ok := resultCode(op)
	if ok && code == 0 {
		return nil
	}
	diag := ""
	if len(op.Children) > 2 && op.Children[2].Value != nil {
		diag = fmt.Sprintf(": %v", op.Children[2].Value)
	}
	if ok {
		return fmt.Errorf("ldap bind failed: result %d%s", code, diag)
	}
	return fmt.Errorf("ldap bind failed: malformed BindResponse%s", diag)
}

// search runs a paged subtree search for SPNs and returns the collected
// servicePrincipalName values (deduplicated).
func (l *ldapConn) searchSPNs(baseDN, filter string) ([]string, error) {
	compiled, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("ldap filter: %w", err)
	}

	var spns []string
	seen := make(map[string]bool)
	cookie := []byte(nil)

	for {
		req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
		req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "Base DN"))
		req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "Scope")) // whole subtree
		req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Deref"))
		req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
		req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
		req.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
		req.AppendChild(compiled)

		attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
		attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "servicePrincipalName", "Attr"))
		req.AppendChild(attrs)

		if err := l.send(req, pagingControl(1000, cookie)); err != nil {
			return nil, err
		}

		done := false
		for !done {
			op, controls, err := l.read()
			if err != nil {
				return nil, err
			}
			switch op.Tag {
			case 4: // SearchResultEntry
				for _, a := range op.Children[1].Children { // attribute sequence
					// [0] type, [1] set of values
					if len(a.Children) < 2 {
						continue
					}
					attrName := a.Children[0].Value.(string)
					if attrName != "servicePrincipalName" {
						continue
					}
					for _, v := range a.Children[1].Children {
						s := string(v.ByteValue)
						if seen[s] {
							continue
						}
						seen[s] = true
						spns = append(spns, s)
					}
				}
			case 19: // SearchResultReference — ignore
			case 5: // SearchResultDone
				// A non-zero result code (sizeLimitExceeded=4,
				// adminLimitExceeded=11, insufficientAccessRights=50, ...)
				// means the search was cut short — report it instead of
				// silently returning a partial/empty result.
				if code, ok := resultCode(op); ok && code != 0 {
					return nil, fmt.Errorf("ldap search failed: result %d", code)
				}
				cookie = pagingCookie(controls)
				done = true
			default:
				return nil, fmt.Errorf("ldap: unexpected search response tag %d", op.Tag)
			}
		}

		if len(cookie) == 0 {
			break
		}
	}

	return spns, nil
}

// kerberosDiscover runs the LDAP SPN discovery with a Kerberos SASL bind
// (GSS-SPNEGO, impacket-style) over the minimal built-in client.
func kerberosDiscover(cfg LDAPConfig) ([]models.SQLInstance, error) {
	spn, err := ldapSPNFor(cfg.Server, cfg.Nameserver, cfg.Dialer)
	if err != nil {
		return nil, err
	}

	kdc := cfg.KDC
	if cfg.Dialer != nil {
		if local, err := krb5auth.ProxyKDC(kdc, cfg.Dialer); err != nil {
			return nil, err
		} else {
			kdc = local
		}
	}

	cl, err := krb5auth.Login(krb5auth.Params{
		Username: cfg.Username,
		Password: cfg.Password,
		Realm:    cfg.Realm,
		KDC:      kdc,
		AESKey:   cfg.AESKey,
		Hash:     cfg.Hash,
		CCache:   cfg.CCache,
		KrbEType: cfg.KrbEType,
		KVNO:     cfg.KVNO,
	})
	if err != nil {
		return nil, err
	}
	defer cl.Destroy()

	token, err := krb5auth.ADNegTokenInit(cl, spn)
	if err != nil {
		return nil, err
	}

	port := cfg.Port
	if port == 0 {
		port = 389
	}
	// Resolve the DC hostname (when -dc is not an IP) through the
	// nameserver so the dial does not depend on system DNS.
	host := cfg.Server
	if net.ParseIP(host) == nil {
		if ip := resolveHostIP(context.Background(), cfg.Nameserver, host, cfg.Dialer); ip != "" {
			host = ip
		}
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var raw net.Conn
	if cfg.Dialer != nil {
		dctx, cancel := context.WithTimeout(context.Background(), ldapDialTimeout)
		raw, err = cfg.Dialer.DialContext(dctx, "tcp", address)
		cancel()
	} else {
		raw, err = (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "tcp", address)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap connect failed: %w", err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(30 * time.Second))

	conn := &ldapConn{c: raw, br: bufio.NewReader(raw)}
	if err := conn.bindSASL(token, cfg.Username); err != nil {
		return nil, fmt.Errorf("ldap kerberos bind failed: %w", err)
	}

	baseDN := cfg.BaseDN
	if baseDN == "" && cfg.Domain != "" {
		baseDN = domainToBaseDN(cfg.Domain)
	}
	if baseDN == "" {
		baseDN, err = conn.rootDSE()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve baseDN (try --base-dn or --domain): %w", err)
		}
	}

	spns, err := conn.searchSPNs(baseDN, "(servicePrincipalName=MSSQLSvc/*)")
	if err != nil {
		return nil, fmt.Errorf("ldap search failed: %w", err)
	}
	return instancesFromSPNs(spns), nil
}

// rootDSE queries the defaultNamingContext.
func (l *ldapConn) rootDSE() (string, error) {
	compiled, err := ldap.CompileFilter("(objectClass=*)")
	if err != nil {
		return "", err
	}
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Deref"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
	req.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
	req.AppendChild(compiled)
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "defaultNamingContext", "Attr"))
	req.AppendChild(attrs)

	if err := l.send(req); err != nil {
		return "", err
	}
	for {
		op, _, err := l.read()
		if err != nil {
			return "", err
		}
		switch op.Tag {
		case 4:
			for _, a := range op.Children[1].Children {
				if len(a.Children) < 2 || a.Children[0].Value.(string) != "defaultNamingContext" {
					continue
				}
				if len(a.Children[1].Children) > 0 {
					return string(a.Children[1].Children[0].ByteValue), nil
				}
			}
		case 5:
			return "", fmt.Errorf("rootDSE empty")
		}
	}
}

// instancesFromSPNs converts MSSQLSvc/* SPN values into SQL instances.
func instancesFromSPNs(spns []string) []models.SQLInstance {
	var results []models.SQLInstance
	seen := make(map[string]bool)

	for _, spn := range spns {
		if !strings.HasPrefix(spn, "MSSQLSvc/") {
			continue
		}
		host := strings.TrimPrefix(spn, "MSSQLSvc/")
		parts := strings.Split(host, ":")

		instance := models.SQLInstance{
			Hostname: parts[0],
			SPN:      spn,
			Port:     1433,
		}
		if len(parts) == 2 {
			if p, err := strconv.Atoi(parts[1]); err == nil && p > 0 {
				instance.Port = p
			} else if parts[1] != "" {
				// MSSQLSvc/host:InstanceName — a named instance: its port
				// is only known via the SQL Browser, so the instance name
				// is kept and the port stays 1433.
				instance.Instance = parts[1]
			}
		}
		key := strings.ToLower(instance.Hostname) + ":" + fmt.Sprint(instance.Port)
		if !seen[key] {
			seen[key] = true
			results = append(results, instance)
		}
	}
	return results
}

// keep gokrb5's client import referenced for future extensions
var _ *client.Client
