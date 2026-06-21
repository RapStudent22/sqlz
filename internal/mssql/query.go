package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (c *Client) Query(
	ctx context.Context,
	query string,
	args ...any,
) ([]map[string]any, error) {

	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]any

	values := make([]any, len(columns))
	pointers := make([]any, len(columns))

	for i := range values {
		pointers[i] = &values[i]
	}

	for rows.Next() {

		if err := rows.Scan(pointers...); err != nil {
			return nil, err
		}

		row := make(map[string]any)

		for i, col := range columns {

			val := values[i]

			switch v := val.(type) {

			case nil:
				row[col] = nil

			case []byte:
				row[col] = string(v)

			case time.Time:
				row[col] = v.Format(time.RFC3339)

			default:
				row[col] = v
			}
		}

		results = append(results, row)
	}

	return results, nil
}

func (c *Client) QuerySimple(
	query string,
	args ...any,
) ([]map[string]any, error) {

	ctx, cancel := context.WithTimeout(
		context.Background(),
		c.config.QueryTimeout,
	)

	defer cancel()

	return c.Query(ctx, query, args...)
}

func (c *Client) QueryRow(
	query string,
	args ...any,
) *sql.Row {

	return c.db.QueryRow(query, args...)
}

func (c *Client) Exec(
	query string,
	args ...any,
) error {

	ctx, cancel := context.WithTimeout(
		context.Background(),
		c.config.QueryTimeout,
	)

	defer cancel()

	_, err := c.db.ExecContext(ctx, query, args...)
	return err
}

func (c *Client) QueryValue(
	query string,
	args ...any,
) (string, error) {

	var value sql.NullString

	err := c.db.QueryRow(query, args...).Scan(&value)
	if err != nil {
		return "", err
	}

	if !value.Valid {
		return "", fmt.Errorf("null value")
	}

	return value.String, nil
}
