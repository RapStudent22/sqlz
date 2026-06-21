package links

import (
	"context"
	"time"

	"github.com/RapStudent22/sqlz/internal/mssql"
)

type LinkedServer struct {
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	DataSource string `json:"data_source"`
	Catalog    string `json:"catalog"`
	IsRPCOut   bool   `json:"is_rpc_out"`
	IsRemote   bool   `json:"is_remote_login_enabled"`
}

func Get(client *mssql.Client) ([]LinkedServer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := client.Query(ctx, `
		SELECT
			name,
			provider,
			data_source,
			ISNULL(catalog, '') AS catalog,
			is_rpc_out_enabled,
			is_remote_login_enabled
		FROM sys.servers
		WHERE server_id != 0
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}

	var servers []LinkedServer
	for _, row := range rows {
		ls := LinkedServer{
			Name:       strVal(row, "name"),
			Provider:   strVal(row, "provider"),
			DataSource: strVal(row, "data_source"),
			Catalog:    strVal(row, "catalog"),
			IsRPCOut:   boolVal(row, "is_rpc_out_enabled"),
			IsRemote:   boolVal(row, "is_remote_login_enabled"),
		}
		servers = append(servers, ls)
	}
	return servers, nil
}

func strVal(row map[string]any, key string) string {
	v, _ := row[key].(string)
	return v
}

func boolVal(row map[string]any, key string) bool {
	switch v := row[key].(type) {
	case bool:
		return v
	case int64:
		return v == 1
	}
	return false
}
