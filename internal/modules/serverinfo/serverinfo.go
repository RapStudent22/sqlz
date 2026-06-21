package serverinfo

import (
	"sync"

	"github.com/RapStudent22/sqlz/internal/mssql"
	"github.com/RapStudent22/sqlz/internal/models"
)

type Options struct {
	Workers int

	Domain   string
	Username string
	Password string
}

func Run(
	connections []models.ConnectionResult,
	opts Options,
) []models.ServerInfo {

	if opts.Workers <= 0 {
		opts.Workers = 20
	}

	jobs := make(chan models.ConnectionResult)
	results := make(chan models.ServerInfo)

	var wg sync.WaitGroup

	worker := func() {

		defer wg.Done()

		for conn := range jobs {

			if !conn.Authenticated {
				continue
			}

			client, err := mssql.New(mssql.Config{
				Server:   conn.Instance.Hostname,
				Port:     conn.Instance.Port,
				Username: opts.Username,
				Password: opts.Password,
				Domain:   opts.Domain,
				AuthType: mssql.AuthSQL,
			})

			if err != nil {
				continue
			}

			info := models.ServerInfo{
				Instance: conn.Instance,
			}

			_ = client.QueryRow(`SELECT @@SERVERNAME`).Scan(&info.ServerName)

			_ = client.QueryRow(`SELECT @@VERSION`).Scan(&info.Version)

			_ = client.QueryRow(`
				SELECT 
					SERVERPROPERTY('Edition'),
					SERVERPROPERTY('ProductVersion'),
					SERVERPROPERTY('ProductLevel'),
					SERVERPROPERTY('EngineEdition'),
					SERVERPROPERTY('IsClustered')
			`).Scan(
				&info.Edition,
				&info.ProductVersion,
				&info.ProductLevel,
				&info.EngineEdition,
				&info.IsClustered,
			)

			var sysadmin int
			_ = client.QueryRow(`SELECT IS_SRVROLEMEMBER('sysadmin')`).Scan(&sysadmin)
			info.IsSysadmin = sysadmin == 1

			_ = client.QueryRow(`
				SELECT TOP 1 service_account
				FROM sys.dm_server_services
			`).Scan(&info.ServiceAccount)

			results <- info
		}
	}

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for _, c := range connections {
			jobs <- c
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var output []models.ServerInfo

	for r := range results {
		output = append(output, r)
	}

	return output
}
