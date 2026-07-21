package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	templateDatabase    = "power_manage_test"
	maintenanceDatabase = "postgres"
)

var (
	postgresOnce      sync.Once
	postgresContainer *postgres.PostgresContainer
	postgresAdmin     *pgxpool.Pool
	postgresBaseURL   *url.URL
	postgresInitErr   error
	databaseSequence  atomic.Uint64
	databaseMu        sync.Mutex
)

func TestMain(m *testing.M) {
	code := m.Run()
	if postgresAdmin != nil {
		postgresAdmin.Close()
	}
	if postgresContainer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := postgresContainer.Terminate(ctx)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "terminate postgres testcontainer: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

func initPostgres() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	container, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase(templateDatabase),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		postgresInitErr = fmt.Errorf("start shared postgres: %w", err)
		return
	}
	postgresContainer = container

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		postgresInitErr = fmt.Errorf("postgres connection string: %w", err)
		return
	}
	if err := Migrate(ctx, dsn); err != nil {
		postgresInitErr = fmt.Errorf("migrate postgres template: %w", err)
		return
	}

	base, err := url.Parse(dsn)
	if err != nil {
		postgresInitErr = fmt.Errorf("parse postgres connection string: %w", err)
		return
	}
	postgresBaseURL = base

	admin, err := pgxpool.New(ctx, databaseURL(base, maintenanceDatabase))
	if err != nil {
		postgresInitErr = fmt.Errorf("open postgres maintenance pool: %w", err)
		return
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		postgresInitErr = fmt.Errorf("ping postgres maintenance pool: %w", err)
		return
	}
	postgresAdmin = admin
}

func testPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	postgresOnce.Do(initPostgres)
	if postgresInitErr != nil {
		t.Fatalf("initialize shared postgres: %v", postgresInitErr)
	}

	// This numeric suffix names an ephemeral database inside the shared test
	// container; it is not a domain or entity ID.
	database := fmt.Sprintf("pm_test_%d", databaseSequence.Add(1))
	create := fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s",
		pgx.Identifier{database}.Sanitize(), pgx.Identifier{templateDatabase}.Sanitize())

	createCtx, cancelCreate := context.WithTimeout(context.Background(), 30*time.Second)
	databaseMu.Lock()
	_, err := postgresAdmin.Exec(createCtx, create)
	databaseMu.Unlock()
	cancelCreate()
	if err != nil {
		t.Fatalf("create test database: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		drop := fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)",
			pgx.Identifier{database}.Sanitize())
		databaseMu.Lock()
		_, err := postgresAdmin.Exec(ctx, drop)
		databaseMu.Unlock()
		if err != nil {
			t.Errorf("drop test database: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL(postgresBaseURL, database))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func databaseURL(base *url.URL, database string) string {
	copy := *base
	copy.Path = "/" + database
	return copy.String()
}
