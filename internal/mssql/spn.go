package mssql

import (
	"fmt"
	"net"
	"strings"

	"github.com/RapStudent22/sqlz/internal/models"
	"github.com/RapStudent22/sqlz/internal/mssql/krb5auth"
)

// SPNForInstance builds the Kerberos SPN for a SQL instance. Kerberos
// requires an SPN registered in AD (MSSQLSvc/<hostname>:<port>), so the
// target must be a hostname — a bare IP can never form a valid SPN.
func SPNForInstance(inst models.SQLInstance) (string, error) {
	host := inst.Hostname
	if host == "" {
		return "", fmt.Errorf("empty hostname: cannot build Kerberos SPN")
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf(
			"kerberos auth needs the target hostname to build the MSSQLSvc SPN, got IP %q — connect by hostname/FQDN (discovery provides hostnames automatically)", host)
	}
	port := inst.Port
	if port == 0 {
		port = 1433
	}
	return fmt.Sprintf("MSSQLSvc/%s:%d", host, port), nil
}

// LoginHint classifies an authentication failure for scan output.
// kerberosRequired is true when the failure indicates NTLM was blocked at
// the protocol level (e.g. Protected Users / account restrictions), which
// makes Kerberos the only option. hint is a human-readable suggestion.
func LoginHint(authType AuthType, err error) (kerberosRequired bool, hint string) {
	if err == nil {
		return false, ""
	}
	if authType == AuthKerberos {
		return false, krb5auth.AuthHint(err)
	}

	s := err.Error()
	switch {
	case strings.Contains(s, "Cannot generate SSPI context"),
		strings.Contains(s, "not been granted the requested logon type"),
		strings.Contains(s, "account restriction"):
		return true, "NTLM blocked for this account (Protected Users / Restricted NTLM?) — Kerberos is required, retry with --auth kerberos"
	case strings.Contains(s, "Login failed"),
		strings.Contains(s, "login error"):
		return false, "NTLM login rejected — wrong password, or the account blocks NTLM (Protected Users); retry with --auth kerberos"
	}
	return false, ""
}
