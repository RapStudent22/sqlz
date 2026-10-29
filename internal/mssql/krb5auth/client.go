package krb5auth

import (
	"fmt"
	"strconv"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/microsoft/go-mssqldb/msdsn"
)

// Params are explicit Kerberos login parameters for non-MSSQL consumers
// (e.g. LDAP discovery). The same provider machinery is reused: runtime
// config, in-memory keytab, etype fallback and kvno auto-recovery.
type Params struct {
	Username string
	Password string
	Realm    string
	KDC      string
	AESKey   string
	Hash     string
	CCache   string
	KrbEType string
	KVNO     int
}

// Login builds a logged-in gokrb5 client from explicit parameters.
func Login(p Params) (*client.Client, error) {
	params := map[string]string{
		paramRealm:  p.Realm,
		paramKDC:    p.KDC,
		paramKey:    p.AESKey,
		paramHash:   p.Hash,
		paramCCache: p.CCache,
		paramEType:  p.KrbEType,
	}
	if p.KVNO > 0 {
		params[paramKVNO] = strconv.Itoa(p.KVNO)
	}

	auth, err := getAuth(msdsn.Config{
		User:       p.Username,
		Password:   p.Password,
		ServerSPN:  "unused", // SPNEGO is not used by this API
		Parameters: params,
	})
	if err != nil {
		return nil, err
	}
	return auth.(*krbAuth).login()
}

// SPNEGOToken builds the SPNEGO NegTokenInit for the given SPN — the same
// token used for MSSQL integrated auth.
func SPNEGOToken(cl *client.Client, spn string) ([]byte, error) {
	tkn, err := spnego.SPNEGOClient(cl, spn).InitSecContext()
	if err != nil {
		return nil, fmt.Errorf("kerberos: SPNEGO to %s: %w", spn, err)
	}
	return tkn.Marshal()
}

// ADNegTokenInit builds the SPNEGO NegTokenInit the way impacket does for
// AD LDAP SASL binds: a plain AP-REQ (no GSS checksum, no subkey, no
// context flags) as the mech token, Microsoft's legacy Kerberos OID as the
// mechanism. With this token the GSS-SPNEGO bind completes in a single
// round and the DC accepts further operations right away. (A GSS-flagged
// token would start an RFC 4752 security layer negotiation; until the
// client finishes it, AD silently drops subsequent requests.)
func ADNegTokenInit(cl *client.Client, spn string) ([]byte, error) {
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("kerberos: TGS for %s: %w", spn, err)
	}
	auth, err := types.NewAuthenticator(cl.Credentials.Realm(), cl.Credentials.CName())
	if err != nil {
		return nil, fmt.Errorf("kerberos: authenticator for %s: %w", spn, err)
	}
	apReq, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return nil, fmt.Errorf("kerberos: AP-REQ for %s: %w", spn, err)
	}
	mechToken, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("kerberos: AP-REQ for %s: %w", spn, err)
	}

	tok := spnego.NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDMSLegacyKRB5.OID()},
		MechTokenBytes: mechToken,
	}
	return tok.Marshal()
}
