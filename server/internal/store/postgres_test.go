package store

import (
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/server/internal/testpostgres"
)

var postgresHarness testpostgres.Harness

func TestMain(m *testing.M) {
	os.Exit(postgresHarness.Run(m))
}

func testPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return postgresHarness.Database(t, Migrate)
}
