package connectiontest

import (
	"testing"

	"github.com/RapStudent22/sqlz/internal/models"
	"github.com/RapStudent22/sqlz/internal/mssql"
)

// TestRunResultsInInputOrder pins the deterministic-output fix: results are
// collected by input index, so the returned slice order never depends on
// worker completion order. Closed local ports fail fast, keeping the test
// quick.
func TestRunResultsInInputOrder(t *testing.T) {
	instances := []models.SQLInstance{
		{Hostname: "127.0.0.1", Port: 1},
		{Hostname: "127.0.0.1", Port: 2},
		{Hostname: "127.0.0.1", Port: 3},
		{Hostname: "127.0.0.1", Port: 4},
	}

	results := Run(instances, Options{
		Workers:  4,
		Username: "sa",
		Password: "Password1",
		AuthType: mssql.AuthSQL,
	}, func(Result) {})

	if len(results) != len(instances) {
		t.Fatalf("got %d results, want %d", len(results), len(instances))
	}
	for i, r := range results {
		if r.Instance.Port != instances[i].Port {
			t.Errorf("results[%d] = port %d, want %d (input order must be preserved)",
				i, r.Instance.Port, instances[i].Port)
		}
	}
}
