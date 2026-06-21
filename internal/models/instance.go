package models

import "fmt"

// SQLInstance представляет MSSQL-инстанс.
type SQLInstance struct {
	Hostname string `json:"hostname"`
	Instance string `json:"instance,omitempty"`
	Port     int    `json:"port,omitempty"`
	SPN      string `json:"spn,omitempty"`

	// ConnHost is the actual IP/host used for TCP connection.
	// Set when the SPN hostname can't be resolved but a DC IP is known.
	// Not serialized — display always uses Hostname.
	ConnHost string `json:"-"`
}

// ConnectionHost returns the host to actually connect to.
// Falls back to Hostname if no override is set.
func (s SQLInstance) ConnectionHost() string {
	if s.ConnHost != "" {
		return s.ConnHost
	}
	return s.Hostname
}

func (s SQLInstance) Address() string {
	if s.Port > 0 {
		return fmt.Sprintf("%s:%d", s.Hostname, s.Port)
	}
	return s.Hostname
}

func (s SQLInstance) DisplayName() string {
	if s.Instance != "" {
		return s.Hostname + `\` + s.Instance
	}
	return s.Hostname
}
