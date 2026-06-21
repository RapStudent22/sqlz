package connectiontest

import (
	"context"
	"errors"
	"sync"
	"time"

	"sqlz/internal/models"
	"sqlz/internal/mssql"
)

type Options struct {
	Workers  int
	Username string
	Password string
	Domain   string
	AuthType mssql.AuthType
	Dialer   mssql.Dialer
}

type Result struct {
	Instance      models.SQLInstance
	Authenticated bool
	Version       string
	Login         string
	Roles         []string // active server roles, e.g. ["sysadmin", "dbcreator"]
	Error         error
}

type ResultCallback func(Result)

// roleOrder defines which roles to check and in what display order.
var roleOrder = []struct{ key, label string }{
	{"sysadmin", "sysadmin"},
	{"serveradmin", "serveradmin"},
	{"securityadmin", "securityadmin"},
	{"dbcreator", "dbcreator"},
	{"bulkadmin", "bulkadmin"},
}

func testOne(inst models.SQLInstance, opts Options) Result {
	authType := opts.AuthType
	if authType == 0 {
		authType = mssql.AuthSQL
	}

	client, err := mssql.New(mssql.Config{
		Server:   inst.ConnectionHost(),
		Port:     inst.Port,
		Username: opts.Username,
		Password: opts.Password,
		Domain:   opts.Domain,
		AuthType: authType,
		Dialer:   opts.Dialer,
	})
	if err != nil {
		return Result{Instance: inst, Error: err}
	}
	defer client.Close()

	cr := client.TestConnectionWithVersion(inst)
	if !cr.Authenticated {
		var connErr error
		if cr.Error != "" {
			connErr = errors.New(cr.Error)
		}
		return Result{Instance: inst, Error: connErr}
	}

	result := Result{
		Instance:      inst,
		Authenticated: true,
		Version:       cr.Version,
	}

	// query login name + key server roles
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := client.Query(ctx, `
		SELECT
			SYSTEM_USER                          AS login,
			IS_SRVROLEMEMBER('sysadmin')         AS sysadmin,
			IS_SRVROLEMEMBER('serveradmin')      AS serveradmin,
			IS_SRVROLEMEMBER('securityadmin')    AS securityadmin,
			IS_SRVROLEMEMBER('dbcreator')        AS dbcreator,
			IS_SRVROLEMEMBER('bulkadmin')        AS bulkadmin
	`)
	if err == nil && len(rows) > 0 {
		row := rows[0]
		result.Login, _ = row["login"].(string)
		for _, r := range roleOrder {
			if intVal(row, r.key) == 1 {
				result.Roles = append(result.Roles, r.label)
			}
		}
	}

	return result
}

func Run(instances []models.SQLInstance, opts Options, cb ResultCallback) []Result {
	workers := opts.Workers
	if workers <= 0 {
		workers = 50
	}

	jobs := make(chan models.SQLInstance)
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for inst := range jobs {
			r := testOne(inst, opts)
			cb(r)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for _, inst := range instances {
			jobs <- inst
		}
		close(jobs)
	}()

	wg.Wait()
	return results
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
