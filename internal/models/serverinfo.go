package models

// ServerInfo содержит информацию о SQL Server.
type ServerInfo struct {
	Instance SQLInstance `json:"instance"`

	ServerName string `json:"server_name"`
	Version    string `json:"version"`
	Edition    string `json:"edition"`

	ProductVersion string `json:"product_version"`
	ProductLevel   string `json:"product_level"`

	EngineEdition int `json:"engine_edition"`

	IsClustered bool `json:"is_clustered"`

	ServiceAccount string `json:"service_account,omitempty"`

	IsSysadmin bool `json:"is_sysadmin"`

	Error string `json:"error,omitempty"`
}

func (s ServerInfo) HasError() bool {
	return s.Error != ""
}

func (s ServerInfo) DisplayName() string {
	return s.Instance.DisplayName()
}
