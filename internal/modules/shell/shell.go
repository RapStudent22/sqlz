package shell

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/RapStudent22/sqlz/internal/mssql"
)

func IsEnabled(client *mssql.Client) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := client.Query(ctx,
		`SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'`)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, fmt.Errorf("xp_cmdshell not found in sys.configurations")
	}
	switch v := rows[0]["value_in_use"].(type) {
	case int64:
		return v == 1, nil
	case bool:
		return v, nil
	}
	return false, nil
}

func Enable(client *mssql.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stmts := []string{
		`EXEC sp_configure 'show advanced options', 1`,
		`RECONFIGURE`,
		`EXEC sp_configure 'xp_cmdshell', 1`,
		`RECONFIGURE`,
	}
	for _, q := range stmts {
		if _, err := client.DB().ExecContext(ctx, q); err != nil {
			return fmt.Errorf("failed enabling xp_cmdshell (%s): %w", q, err)
		}
	}
	return nil
}

func Disable(client *mssql.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stmts := []string{
		`EXEC sp_configure 'xp_cmdshell', 0`,
		`RECONFIGURE`,
		`EXEC sp_configure 'show advanced options', 0`,
		`RECONFIGURE`,
	}
	for _, q := range stmts {
		if _, err := client.DB().ExecContext(ctx, q); err != nil {
			return fmt.Errorf("failed disabling xp_cmdshell (%s): %w", q, err)
		}
	}
	return nil
}

func Run(client *mssql.Client, cmd string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	safe := strings.ReplaceAll(cmd, "'", "''")
	rows, err := client.Query(ctx, fmt.Sprintf(`EXEC xp_cmdshell '%s'`, safe))
	if err != nil {
		return nil, err
	}

	var lines []string
	for _, row := range rows {
		if v, ok := row["output"].(string); ok {
			lines = append(lines, v)
		} else {
			lines = append(lines, "")
		}
	}
	return lines, nil
}
