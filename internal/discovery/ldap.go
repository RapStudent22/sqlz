package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/RapStudent22/sqlz/internal/models"
	"github.com/RapStudent22/sqlz/internal/mssql"
	"github.com/RapStudent22/sqlz/internal/mssql/krb5auth"
)

// Dialer is the same interface as mssql.Dialer — anything with DialContext.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// ldapDialTimeout bounds the proxy dial. Without a deadline, a dead SOCKS5
// proxy hangs the run: the OS SYN timeouts take ~2 minutes and the SOCKS
// handshake itself would wait forever (the dialer only honors ctx deadlines).
var ldapDialTimeout = 10 * time.Second

type LDAPConfig struct {
	Server string
	Port   int

	Domain   string
	Username string
	Password string
	BaseDN   string

	// Nameserver resolves the LDAP server hostname when -dc is not an IP.
	Nameserver string

	// Kerberos (GSSAPI SASL bind) options. AuthType == mssql.AuthKerberos
	// switches the bind from simple password to Kerberos; KDC must already
	// be resolved by the caller.
	AuthType mssql.AuthType
	Realm    string
	KDC      string
	AESKey   string
	Hash     string
	CCache   string
	KrbEType string
	KVNO     int

	// Dialer, when non-nil, routes the LDAP connection through it (e.g. SOCKS5).
	Dialer Dialer
}

func getBaseDN(conn *ldap.Conn) (string, error) {

	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	sr, err := conn.Search(req)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("rootDSE empty")
	}

	return sr.Entries[0].GetAttributeValue("defaultNamingContext"), nil
}

func tryBind(conn *ldap.Conn, username, password, domain string) error {

	candidates := []string{username}

	if !strings.Contains(username, "@") && !strings.Contains(username, "\\") {
		if domain != "" {
			candidates = append(candidates,
				username+"@"+domain,
				domain+"\\"+username,
			)
		}
	}

	var lastErr error

	for _, u := range candidates {
		err := conn.Bind(u, password)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("all bind formats failed: %w", lastErr)
}

func DiscoverSQLInstances(cfg LDAPConfig) ([]models.SQLInstance, error) {

	// Kerberos uses its own minimal LDAP client: go-ldap's SASL bind
	// hardcodes the GSSAPI mechanism, which AD rejects — it expects
	// GSS-SPNEGO (impacket-style).
	if cfg.AuthType == mssql.AuthKerberos {
		return kerberosDiscover(cfg)
	}

	port := cfg.Port
	if port == 0 {
		port = 389
	}

	// Resolve the LDAP server hostname (when -dc is not an IP) through the
	// configured nameserver so the dial does not depend on system DNS.
	host := cfg.Server
	if net.ParseIP(host) == nil {
		if ip := resolveHostIP(context.Background(), cfg.Nameserver, host, cfg.Dialer); ip != "" {
			host = ip
		}
	}

	address := fmt.Sprintf("%s:%d", host, port)

	var conn *ldap.Conn
	var err error

	if cfg.Dialer != nil {
		dctx, cancel := context.WithTimeout(context.Background(), ldapDialTimeout)
		netConn, dialErr := cfg.Dialer.DialContext(dctx, "tcp", address)
		cancel()
		if dialErr != nil {
			return nil, fmt.Errorf("ldap connect via proxy failed: %w", dialErr)
		}
		conn = ldap.NewConn(netConn, false)
		conn.Start()
	} else {
		conn, err = ldap.DialURL("ldap://" + address)
		if err != nil {
			return nil, fmt.Errorf("ldap connect failed: %w", err)
		}
	}
	defer conn.Close()

	conn.SetTimeout(10 * time.Second)

	// --- BIND ---
	if err := tryBind(conn, cfg.Username, cfg.Password, cfg.Domain); err != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}

	// --- AUTO BaseDN ---
	// Priority: explicit → derived from domain → rootDSE query
	baseDN := cfg.BaseDN
	if baseDN == "" && cfg.Domain != "" {
		baseDN = domainToBaseDN(cfg.Domain)
	}
	if baseDN == "" {
		b, err := getBaseDN(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve baseDN (try --base-dn or --domain): %w", err)
		}
		baseDN = b
	}

	// --- PAGING (FIX SIZE LIMIT 4) ---
	paging := ldap.NewControlPaging(1000)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(servicePrincipalName=MSSQLSvc/*)",
		[]string{"servicePrincipalName"},
		[]ldap.Control{paging},
	)

	var results []models.SQLInstance
	seen := make(map[string]bool)

	for {

		sr, err := conn.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("ldap search failed: %w", err)
		}

		for _, entry := range sr.Entries {

			for _, spn := range entry.GetAttributeValues("servicePrincipalName") {

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
						// MSSQLSvc/host:InstanceName — a named instance: its
						// port is only known via the SQL Browser, so the
						// instance name is kept and the port stays 1433.
						instance.Instance = parts[1]
					}
				}

				key := strings.ToLower(instance.Hostname) + ":" + fmt.Sprint(instance.Port)

				if !seen[key] {
					seen[key] = true
					results = append(results, instance)
				}
			}
		}

		// paging control update
		pc := ldap.FindControl(sr.Controls, ldap.ControlTypePaging)
		if pc == nil {
			break
		}

		cookie := pc.(*ldap.ControlPaging).Cookie
		if len(cookie) == 0 {
			break
		}

		paging.SetCookie(cookie)
	}

	return results, nil
}

// domainToBaseDN converts "corp.local" → "DC=corp,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			dcs = append(dcs, "DC="+p)
		}
	}
	return strings.Join(dcs, ",")
}

// ldapSPNFor builds the ldap/<hostname> SPN for the Kerberos bind. The DC
// must be addressed by name for Kerberos: if an IP was passed, a reverse
// lookup through the nameserver is attempted.
func ldapSPNFor(server, nameserver string, d krb5auth.Dialer) (string, error) {
	host := server
	if net.ParseIP(host) != nil {
		name, err := reverseLookup(context.Background(), nameserver, host, d)
		if err != nil || name == "" {
			return "", fmt.Errorf(
				"kerberos discovery needs the DC hostname to build the ldap/ SPN — pass -dc DC1.cs.org instead of an IP (or fix the PTR record)")
		}
		host = name
	}
	return "ldap/" + strings.TrimSuffix(host, "."), nil
}

// resolveHostIP resolves a hostname through the configured nameserver and
// returns the first IPv4 address, or "" when it can't be resolved. With a
// SOCKS5 dialer the DNS queries go over TCP through the proxy.
func resolveHostIP(ctx context.Context, nameserver, host string, d krb5auth.Dialer) string {
	if nameserver == "" {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ip, err := krb5auth.LookupHostIP(cctx, nameserver, host, d)
	if err != nil {
		return ""
	}
	return ip
}

// reverseLookup resolves an IP back to a hostname through the configured
// nameserver (PTR), returning "" on failure.
func reverseLookup(ctx context.Context, nameserver, ip string, d krb5auth.Dialer) (string, error) {
	if nameserver == "" {
		return "", nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return krb5auth.LookupPTR(cctx, nameserver, ip, d)
}
