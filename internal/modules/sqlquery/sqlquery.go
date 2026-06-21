package sqlquery

import (
	"context"
	"time"

	"sqlz/internal/mssql"
)

func Run(client *mssql.Client, query string) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return client.Query(ctx, query)
}
