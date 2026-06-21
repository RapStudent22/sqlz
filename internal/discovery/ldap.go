package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"sqlz/internal/models"
)

// Dialer is the same interface as mssql.Dialer — anything with DialContext.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type LDAPConfig struct {
	Server   string
	Port     int

	Domain   string
	Username string
	Password string
	BaseDN   string

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

	port := cfg.Port
	if port == 0 {
		port = 389
	}

	address := fmt.Sprintf("%s:%d", cfg.Server, port)

	var conn *ldap.Conn
	var err error

	if cfg.Dialer != nil {
		netConn, dialErr := cfg.Dialer.DialContext(context.Background(), "tcp", address)
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
					var p int
					fmt.Sscanf(parts[1], "%d", &p)
					if p > 0 {
						instance.Port = p
					}
				}

				key := instance.Hostname + ":" + fmt.Sprint(instance.Port)

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
