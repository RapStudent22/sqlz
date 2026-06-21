package databases

import (
	"context"
	"time"

	"github.com/RapStudent22/sqlz/internal/mssql"
)

type Database struct {
	Name       string `json:"name"`
	ID         int    `json:"id"`
	State      string `json:"state"`
	Owner      string `json:"owner"`
	IsReadOnly bool   `json:"is_read_only"`
}

func Get(client *mssql.Client) ([]Database, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := client.Query(ctx, `
		SELECT
			name,
			database_id,
			state_desc,
			ISNULL(SUSER_SNAME(owner_sid), '') AS owner,
			is_read_only
		FROM sys.databases
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}

	var dbs []Database
	for _, row := range rows {
		db := Database{
			Name:  strVal(row, "name"),
			ID:    intVal(row, "database_id"),
			State: strVal(row, "state_desc"),
			Owner: strVal(row, "owner"),
		}
		switch v := row["is_read_only"].(type) {
		case bool:
			db.IsReadOnly = v
		case int64:
			db.IsReadOnly = v == 1
		}
		dbs = append(dbs, db)
	}
	return dbs, nil
}

func strVal(row map[string]any, key string) string {
	v, _ := row[key].(string)
	return v
}

func intVal(row map[string]any, key string) int {
	switch v := row[key].(type) {
	case int64:
		return int(v)
	case int32:
		return int(v)
	}
	return 0
}
