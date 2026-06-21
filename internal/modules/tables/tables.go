package tables

import (
	"context"
	"time"

	"github.com/RapStudent22/sqlz/internal/mssql"
)

type Table struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}

func Get(client *mssql.Client) ([]Table, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := client.Query(ctx, `
		SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE
		FROM INFORMATION_SCHEMA.TABLES
		ORDER BY TABLE_SCHEMA, TABLE_NAME
	`)
	if err != nil {
		return nil, err
	}

	var result []Table
	for _, row := range rows {
		result = append(result, Table{
			Schema: strVal(row, "TABLE_SCHEMA"),
			Name:   strVal(row, "TABLE_NAME"),
			Type:   strVal(row, "TABLE_TYPE"),
		})
	}
	return result, nil
}

func strVal(row map[string]any, key string) string {
	v, _ := row[key].(string)
	return v
}
