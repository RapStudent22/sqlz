package runner

import (
	"sync"

	"sqlz/internal/models"
	"sqlz/internal/mssql"
)

type Config struct {
	Workers  int
	Username string
	Password string
	Domain   string
	AuthType mssql.AuthType
	Database string
	Dialer   mssql.Dialer
}

type Result[T any] struct {
	Instance models.SQLInstance `json:"instance"`
	Value    T                  `json:"value,omitempty"`
	Error    string             `json:"error,omitempty"`
}

func Run[T any](
	instances []models.SQLInstance,
	cfg Config,
	fn func(*mssql.Client) (T, error),
) []Result[T] {
	if cfg.Workers <= 0 {
		cfg.Workers = 10
	}

	jobs := make(chan models.SQLInstance)
	out := make(chan Result[T])
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for inst := range jobs {
			r := Result[T]{Instance: inst}

			client, err := mssql.New(mssql.Config{
				Server:   inst.ConnectionHost(),
				Port:     inst.Port,
				Username: cfg.Username,
				Password: cfg.Password,
				Domain:   cfg.Domain,
				Database: cfg.Database,
				AuthType: cfg.AuthType,
				Dialer:   cfg.Dialer,
			})
			if err != nil {
				r.Error = err.Error()
				out <- r
				continue
			}

			val, err := fn(client)
			client.Close()

			if err != nil {
				r.Error = err.Error()
			} else {
				r.Value = val
			}

			out <- r
		}
	}

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for _, inst := range instances {
			jobs <- inst
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var results []Result[T]
	for r := range out {
		results = append(results, r)
	}
	return results
}
