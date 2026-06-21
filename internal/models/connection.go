package models

import "time"

// ConnectionResult содержит результат проверки подключения.
type ConnectionResult struct {
	Instance SQLInstance `json:"instance"`

	Reachable     bool          `json:"reachable"`
	Authenticated bool          `json:"authenticated"`
	ResponseTime  time.Duration `json:"response_time"`

	ServerName string `json:"server_name,omitempty"`
	Version    string `json:"version,omitempty"`

	Error string `json:"error,omitempty"`
}

func (r ConnectionResult) IsAlive() bool {
	return r.Reachable
}

func (r ConnectionResult) IsAuthenticated() bool {
	return r.Authenticated
}
