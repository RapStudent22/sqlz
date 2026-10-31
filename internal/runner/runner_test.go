package runner

import (
	"strings"
	"testing"

	"github.com/RapStudent22/sqlz/internal/models"
	"github.com/RapStudent22/sqlz/internal/mssql"
)

// TestSPNErrorSkipsConnection: with Kerberos auth and an IP target the SPN
// cannot be built — the worker must report exactly one Result with the SPN
// error and never attempt a connection (fn must not be called).
func TestSPNErrorSkipsConnection(t *testing.T) {
	instances := []models.SQLInstance{{Hostname: "10.0.0.5", Port: 1433}}

	calls := 0
	results := Run(instances, Config{
		Workers:  2,
		AuthType: mssql.AuthKerberos,
	}, func(c *mssql.Client) (int, error) {
		calls++
		return 0, nil
	})

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !strings.Contains(results[0].Error, "kerberos auth needs the target hostname") {
		t.Errorf("result error = %q, want the SPN build error", results[0].Error)
	}
	if calls != 0 {
		t.Errorf("fn called %d times, want 0", calls)
	}
}

// TestRunPreservesInputOrder: results must come back in input order
// (deterministic JSON), not worker completion order.
func TestRunPreservesInputOrder(t *testing.T) {
	instances := []models.SQLInstance{
		{Hostname: "a", Port: 1},
		{Hostname: "b", Port: 1},
		{Hostname: "c", Port: 1},
		{Hostname: "d", Port: 1},
	}

	results := Run(instances, Config{
		Workers:  4,
		AuthType: mssql.AuthSQL,
	}, func(c *mssql.Client) (string, error) {
		return "ok", nil
	})

	if len(results) != len(instances) {
		t.Fatalf("got %d results, want %d", len(results), len(instances))
	}
	for i, r := range results {
		if r.Instance.Hostname != instances[i].Hostname {
			t.Errorf("results[%d] = %q, want %q (input order must be preserved)",
				i, r.Instance.Hostname, instances[i].Hostname)
		}
		if r.Error != "" || r.Value != "ok" {
			t.Errorf("results[%d] = {err=%q value=%q}, want value ok", i, r.Error, r.Value)
		}
	}
}
