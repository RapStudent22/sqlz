package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"time"

	mssqldrv "github.com/microsoft/go-mssqldb"
)

type AuthType int

const (
	AuthSQL AuthType = iota
	AuthWindows
	AuthKerberos
)

// Dialer is implemented by anything that can dial a TCP connection,
// e.g. a SOCKS5 proxy dialer.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Config struct {
	Server   string
	Port     int

	Domain   string
	Username string
	Password string

	Database string

	AuthType AuthType

	ConnectionTimeout time.Duration
	QueryTimeout      time.Duration

	// Dialer, when non-nil, routes all SQL Server connections through it.
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

	switch config.AuthType {

	case AuthSQL:

		u := &url.URL{
			Scheme: "sqlserver",
			User: url.UserPassword(
				config.Username,
				config.Password,
			),
			Host: fmt.Sprintf(
				"%s:%d",
				config.Server,
				config.Port,
			),
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
			Host:     fmt.Sprintf("%s:%d", config.Server, config.Port),
			RawQuery: query.Encode(),
		}

		return u.String(), nil
	}

	return "", fmt.Errorf("unsupported auth type")
}
