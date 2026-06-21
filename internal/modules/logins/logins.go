package logins

import (
	"context"
	"time"

	"sqlz/internal/mssql"
)

type Login struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Disabled bool   `json:"disabled"`
	Created  string `json:"created"`
}

func Get(client *mssql.Client) ([]Login, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := client.Query(ctx, `
		SELECT
			name,
			type_desc,
			is_disabled,
			CONVERT(varchar(20), create_date, 120) AS create_date
		FROM sys.server_principals
		WHERE type IN ('S','U','G','E','X')
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}

	var result []Login
	for _, row := range rows {
		l := Login{
			Name:     strVal(row, "name"),
			Type:     strVal(row, "type_desc"),
			Created:  strVal(row, "create_date"),
			Disabled: boolVal(row, "is_disabled"),
		}
		result = append(result, l)
	}
	return result, nil
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
