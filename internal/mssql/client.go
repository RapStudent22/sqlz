package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"
	"time"

	mssqldrv "github.com/microsoft/go-mssqldb"
)

type AuthType int

const (
	AuthSQL AuthType = iota
	AuthWindows
	AuthKerberos
	AuthSSPI
)

func (a AuthType) String() string {
	switch a {
	case AuthSQL:
		return "sql"
	case AuthWindows:
		return "windows"
	case AuthKerberos:
		return "kerberos"
	case AuthSSPI:
		return "sspi"
	}
	return "unknown"
}

// Dialer is implemented by anything that can dial a TCP connection,
// e.g. a SOCKS5 proxy dialer.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Config struct {
	Server string
	Port   int

	Domain   string
	Username string
	Password string

	Database string

	AuthType AuthType

	// Kerberos options (AuthKerberos). Realm defaults to upper(Domain),
	// KDC is resolved via --kdc / --dc-ip / DNS SRV before connecting.
	Realm    string
	KDC      string
	SPN      string // MSSQLSvc/<hostname>:<port>; auto-built per instance
	AESKey   string // hex AES key for pass-the-key
	Hash     string // NT hash (32 hex) or lm:nt pair for pass-the-hash
	CCache   string // credential cache file path (explicit only)
	KrbEType string // comma-separated forced etype list
	KVNO     int    // key version number for the in-memory keytab

	ConnectionTimeout time.Duration
	QueryTimeout      time.Duration

	// Dialer, when non-nil, routes all SQL Server connections through it.
	// NOTE: it does not apply to Kerberos traffic — KDC (port 88) dials
	// go direct through the system network stack.
	Dialer Dialer
}

type Client struct {
	db     *sql.DB
	config Config
}

func New(config Config) (*Client, error) {

	if config.Port == 0 {
		config.Port = 1433
	}

	if config.Database == "" {
		config.Database = "master"
	}

	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 5 * time.Second
	}

	if config.QueryTimeout == 0 {
		config.QueryTimeout = 30 * time.Second
	}

	connString, err := buildConnectionString(config)
	if err != nil {
		return nil, err
	}

	var db *sql.DB

	if config.Dialer != nil {
		connector, err := mssqldrv.NewConnector(connString)
		if err != nil {
			return nil, err
		}
		connector.Dialer = config.Dialer
		db = sql.OpenDB(connector)
	} else {
		db, err = sql.Open("sqlserver", connString)
		if err != nil {
			return nil, err
		}
	}

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(25)
	db.SetConnMaxLifetime(30 * time.Minute)

	return &Client{
		db:     db,
		config: config,
	}, nil
}

func (c *Client) Ping() error {
	return c.db.Ping()
}

func (c *Client) DB() *sql.DB {
	return c.db
}

func (c *Client) Close() error {
	return c.db.Close()
}

func buildConnectionString(config Config) (string, error) {

	query := url.Values{}

	query.Add("database", config.Database)

	query.Add(
		"connection timeout",
		fmt.Sprintf(
			"%d",
			int(config.ConnectionTimeout.Seconds()),
		),
	)

	host := fmt.Sprintf("%s:%d", config.Server, config.Port)

	switch config.AuthType {

	case AuthSQL:

		u := &url.URL{
			Scheme: "sqlserver",
			User: url.UserPassword(
				config.Username,
				config.Password,
			),
			Host:     host,
			RawQuery: query.Encode(),
		}

		return u.String(), nil

	case AuthWindows:

		winUser := config.Username
		if config.Domain != "" {
			winUser = config.Domain + `\` + config.Username
		}

		u := &url.URL{
			Scheme:   "sqlserver",
			User:     url.UserPassword(winUser, config.Password),
			Host:     host,
			RawQuery: query.Encode(),
		}

		return u.String(), nil

	case AuthKerberos:

		realm := config.Realm
		if realm == "" {
			realm = strings.ToUpper(config.Domain)
		}
		if realm == "" {
			return "", fmt.Errorf("kerberos auth requires --realm or --domain")
		}
		if config.KDC == "" {
			return "", fmt.Errorf("kerberos auth requires a KDC: use --kdc, --dc-ip or --domain (DNS SRV)")
		}
		if config.Username == "" && config.CCache == "" {
			return "", fmt.Errorf("kerberos auth requires --username (or --ccache)")
		}
		if config.Password == "" && config.AESKey == "" && config.Hash == "" && config.CCache == "" {
			// Windows without explicit credentials: use the native SSPI
			// stack (Kerberos via the domain session token, secur32).
			// The gokrb5 path cannot work without credentials.
			if runtime.GOOS == "windows" {
				query.Add("authenticator", "winsspi")
				u := &url.URL{
					Scheme:   "sqlserver",
					Host:     host,
					RawQuery: query.Encode(),
				}
				// Explicit credentials only when a password is present:
				// winsspi builds a SEC_WINNT_AUTH_IDENTITY from them, and an
				// empty password would break the SSPI handshake. Without a
				// password, leave the user info out so the provider uses the
				// process token (domain session / runas /netonly creds).
				if config.Username != "" && config.Password != "" {
					u.User = url.UserPassword(config.Username, config.Password)
				}
				return u.String(), nil
			}
			return "", fmt.Errorf("kerberos auth requires --password, --aes-key, --hash or --ccache")
		}

		// Our self-contained provider: runtime config + in-memory keytab,
		// no system krb5.conf.
		query.Add("authenticator", "krb5")
		query.Add("krb5-realm", realm)
		query.Add("krb5-kdc", config.KDC)
		query.Add("krb5-timeout", fmt.Sprintf("%d", int(config.ConnectionTimeout.Seconds())))
		if config.SPN != "" {
			query.Add("serverspn", config.SPN)
		}
		if config.AESKey != "" {
			query.Add("krb5-key", config.AESKey)
		}
		if config.Hash != "" {
			query.Add("krb5-hash", config.Hash)
		}
		if config.CCache != "" {
			query.Add("krb5-ccache", config.CCache)
		}
		if config.KrbEType != "" {
			query.Add("krb5-etype", config.KrbEType)
		}
		if config.KVNO > 0 {
			query.Add("krb5-kvno", fmt.Sprintf("%d", config.KVNO))
		}

		u := &url.URL{
			Scheme:   "sqlserver",
			User:     url.UserPassword(config.Username, config.Password),
			Host:     host,
			RawQuery: query.Encode(),
		}

		return u.String(), nil

	case AuthSSPI:

		// Native Windows auth via the driver's winsspi provider (secur32).
		// Registered only on Windows; the CLI validates the platform.
		query.Add("authenticator", "winsspi")

		u := &url.URL{
			Scheme:   "sqlserver",
			Host:     host,
			RawQuery: query.Encode(),
		}
		// Same rule as the kerberos SSPI fallback: explicit identity only
		// with a password, otherwise use the process token.
		if config.Username != "" && config.Password != "" {
			if config.Domain != "" {
				u.User = url.UserPassword(config.Domain+`\`+config.Username, config.Password)
			} else {
				u.User = url.UserPassword(config.Username, config.Password)
			}
		}

		return u.String(), nil
	}

	return "", fmt.Errorf("unsupported auth type")
}
