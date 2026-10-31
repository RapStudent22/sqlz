package connectiontest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/RapStudent22/sqlz/internal/models"
	"github.com/RapStudent22/sqlz/internal/modules/relaycheck"
	"github.com/RapStudent22/sqlz/internal/mssql"
)

type Options struct {
	Workers  int
	Username string
	Password string
	Domain   string
	AuthType mssql.AuthType
	Dialer   mssql.Dialer

	// Kerberos options.
	Realm    string
	KDC      string
	AESKey   string
	Hash     string
	CCache   string
	KrbEType string
	KVNO     int

	// Spray, when non-empty, tries each credential in order per host and
	// stops on first success (stop-on-success).
	Spray []SprayCred
}

type Result struct {
	Instance      models.SQLInstance
	Authenticated bool
	Version       string
	Login         string
	AuthMethod    string // "password" | "hash" | "aes-key" when sprayed
	Roles         []string
	Error         error
	// Hint explains the failure, e.g. "NTLM blocked — retry with --auth kerberos".
	Hint string
	// KerberosRequired is true when NTLM is blocked and Kerberos is the only
	// auth option for the account.
	KerberosRequired bool
	// ForceEncrypt is nil when the TDS pre-login check failed, otherwise true/false.
	ForceEncrypt *bool
	Encrypt      relaycheck.EncryptMode
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

	rc := relaycheck.Check(inst, relaycheck.Options{Dialer: opts.Dialer})
	var forceEncrypt *bool
	if rc.Error == "" {
		fe := rc.ForceEncrypt
		forceEncrypt = &fe
	}

	// Kerberos needs an SPN: build it once per host.
	spn := ""
	if authType == mssql.AuthKerberos {
		var err error
		spn, err = mssql.SPNForInstance(inst)
		if err != nil {
			return Result{Instance: inst, Error: err, ForceEncrypt: forceEncrypt, Encrypt: rc.Encrypt}
		}
	}

	base := mssql.Config{
		Server:   inst.ConnectionHost(),
		Port:     inst.Port,
		Domain:   opts.Domain,
		AuthType: authType,
		Dialer:   opts.Dialer,
		Realm:    opts.Realm,
		KDC:      opts.KDC,
		SPN:      spn,
		KrbEType: opts.KrbEType,
		KVNO:     opts.KVNO,
	}

	// credential set: spray list or the single set of flags
	type cred struct {
		method string
		cfg    mssql.Config
	}
	var creds []cred
	if len(opts.Spray) > 0 {
		for _, sc := range opts.Spray {
			cfg := base
			cfg.Username = sc.Username
			cfg.Password, cfg.AESKey, cfg.Hash = "", "", ""
			switch sc.Method {
			case "password":
				cfg.Password = sc.Secret
			case "hash":
				cfg.Hash = sc.Secret
			case "aes-key":
				cfg.AESKey = sc.Secret
			}
			creds = append(creds, cred{method: sc.Method, cfg: cfg})
		}
	} else {
		cfg := base
		cfg.Username, cfg.Password = opts.Username, opts.Password
		cfg.AESKey, cfg.Hash, cfg.CCache = opts.AESKey, opts.Hash, opts.CCache
		creds = append(creds, cred{cfg: cfg})
	}

	var lastErr error
	for _, c := range creds {
		// hash / AES-key pairs only work over Kerberos
		if authType != mssql.AuthKerberos && c.method != "" && c.method != "password" {
			lastErr = fmt.Errorf("spray entry %q requires --auth kerberos", c.method)
			continue
		}

		client, err := mssql.New(c.cfg)
		if err != nil {
			lastErr = err
			continue
		}

		cr := client.TestConnectionWithVersion(inst)
		if !cr.Authenticated {
			client.Close()
			if cr.Error != "" {
				lastErr = errors.New(cr.Error)
			}
			continue
		}

		result := Result{
			Instance:      inst,
			Authenticated: true,
			Version:       cr.Version,
			ForceEncrypt:  forceEncrypt,
			Encrypt:       rc.Encrypt,
		}
		if c.method != "" {
			result.AuthMethod = c.method
		}

		// query login name + key server roles
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		rows, err := client.Query(ctx, `
			SELECT
				SYSTEM_USER                          AS login,
				IS_SRVROLEMEMBER('sysadmin')         AS sysadmin,
				IS_SRVROLEMEMBER('serveradmin')      AS serveradmin,
				IS_SRVROLEMEMBER('securityadmin')    AS securityadmin,
				IS_SRVROLEMEMBER('dbcreator')        AS dbcreator,
				IS_SRVROLEMEMBER('bulkadmin')        AS bulkadmin
		`)
		cancel()
		client.Close()

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

	res := Result{
		Instance:     inst,
		Error:        lastErr,
		ForceEncrypt: forceEncrypt,
		Encrypt:      rc.Encrypt,
	}
	res.KerberosRequired, res.Hint = mssql.LoginHint(authType, lastErr)
	return res
}

func Run(instances []models.SQLInstance, opts Options, cb ResultCallback) []Result {
	workers := opts.Workers
	if workers <= 0 {
		workers = 50
	}

	type job struct {
		idx  int
		inst models.SQLInstance
	}
	jobs := make(chan job)
	// Results are collected by input index so the returned slice (used for
	// JSON output) is deterministic; the callback still fires live, in
	// completion order, for the text output.
	results := make([]Result, len(instances))
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			r := testOne(j.inst, opts)
			mu.Lock()
			results[j.idx] = r
			cb(r)
			mu.Unlock()
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for i, inst := range instances {
			jobs <- job{idx: i, inst: inst}
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
