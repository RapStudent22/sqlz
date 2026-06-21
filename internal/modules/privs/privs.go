package privs

import (
	"context"
	"fmt"
	"time"

	"sqlz/internal/mssql"
)

type ServerPrivs struct {
	Login           string   `json:"login"`
	DBUser          string   `json:"db_user"`
	IsSysadmin      bool     `json:"sysadmin"`
	IsSecurityAdmin bool     `json:"securityadmin"`
	IsServerAdmin   bool     `json:"serveradmin"`
	IsSetupAdmin    bool     `json:"setupadmin"`
	IsProcessAdmin  bool     `json:"processadmin"`
	IsDiskAdmin     bool     `json:"diskadmin"`
	IsDBCreator     bool     `json:"dbcreator"`
	IsBulkAdmin     bool     `json:"bulkadmin"`
	Permissions     []string `json:"permissions,omitempty"`
}

func Get(client *mssql.Client) (*ServerPrivs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := client.Query(ctx, `
		SELECT
			SYSTEM_USER                          AS login,
			USER_NAME()                          AS db_user,
			IS_SRVROLEMEMBER('sysadmin')         AS sysadmin,
			IS_SRVROLEMEMBER('securityadmin')    AS securityadmin,
			IS_SRVROLEMEMBER('serveradmin')      AS serveradmin,
			IS_SRVROLEMEMBER('setupadmin')       AS setupadmin,
			IS_SRVROLEMEMBER('processadmin')     AS processadmin,
			IS_SRVROLEMEMBER('diskadmin')        AS diskadmin,
			IS_SRVROLEMEMBER('dbcreator')        AS dbcreator,
			IS_SRVROLEMEMBER('bulkadmin')        AS bulkadmin
	`)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no results")
	}

	row := rows[0]
	p := &ServerPrivs{
		Login:           strVal(row, "login"),
		DBUser:          strVal(row, "db_user"),
		IsSysadmin:      boolVal(row, "sysadmin"),
		IsSecurityAdmin: boolVal(row, "securityadmin"),
		IsServerAdmin:   boolVal(row, "serveradmin"),
		IsSetupAdmin:    boolVal(row, "setupadmin"),
		IsProcessAdmin:  boolVal(row, "processadmin"),
		IsDiskAdmin:     boolVal(row, "diskadmin"),
		IsDBCreator:     boolVal(row, "dbcreator"),
		IsBulkAdmin:     boolVal(row, "bulkadmin"),
	}

	permRows, err := client.Query(ctx, `
		SELECT permission_name
		FROM fn_my_permissions(NULL, 'SERVER')
		ORDER BY permission_name
	`)
	if err == nil {
		for _, r := range permRows {
			if v, ok := r["permission_name"].(string); ok {
				p.Permissions = append(p.Permissions, v)
			}
		}
	}

	return p, nil
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
	case int32:
		return v == 1
	}
	return false
}
