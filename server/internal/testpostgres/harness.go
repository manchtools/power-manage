// Package testpostgres provides shared real-Postgres test infrastructure for
// server packages whose acceptance tests must not mock persistence.
package testpostgres

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

// MigrateFunc prepares the template database cloned for every test.
type MigrateFunc func(context.Context, string) error

// Harness owns one package-scoped Postgres container and template database.
type Harness struct {
	once      sync.Once
	container *postgres.PostgresContainer
	admin     *pgxpool.Pool
	baseURL   *url.URL
	initErr   error
	sequence  atomic.Uint64
	database  sync.Mutex
}

// Run executes a package test suite and closes its shared Postgres resources.
func (h *Harness) Run(m *testing.M) int {
	if h == nil || m == nil {
		return 1
	}
	code := m.Run()
	if err := h.close(); err != nil {
		fmt.Fprintf(os.Stderr, "close shared Postgres test harness: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// Database returns an isolated template-cloned database for one test.
func (h *Harness) Database(t *testing.T, migrate MigrateFunc) *pgxpool.Pool {
	t.Helper()
	if h == nil {
		t.Fatal("initialize shared Postgres: nil harness")
	}
	if migrate == nil {
		t.Fatal("initialize shared Postgres: nil migration function")
	}
	h.once.Do(func() { h.init(migrate) })
	if h.initErr != nil {
		t.Fatalf("initialize shared Postgres: %v", h.initErr)
	}

	// This numeric suffix names an ephemeral database inside the shared test
	// container; it is not a domain or entity ID.
	database := fmt.Sprintf("pm_test_%d", h.sequence.Add(1))
	create := fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s",
		pgx.Identifier{database}.Sanitize(), pgx.Identifier{templateDatabase}.Sanitize())

	createCtx, cancelCreate := context.WithTimeout(context.Background(), 30*time.Second)
	h.database.Lock()
	_, err := h.admin.Exec(createCtx, create)
	h.database.Unlock()
	cancelCreate()
	if err != nil {
		t.Fatalf("create test database: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		drop := fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)",
			pgx.Identifier{database}.Sanitize())
		h.database.Lock()
		_, err := h.admin.Exec(ctx, drop)
		h.database.Unlock()
		if err != nil {
			t.Errorf("drop test database: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL(h.baseURL, database))
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

func (h *Harness) init(migrate MigrateFunc) {
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
		h.initErr = fmt.Errorf("start shared Postgres: %w", err)
		return
	}
	h.container = container

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		h.initErr = fmt.Errorf("postgres connection string: %w", err)
		return
	}
	if err := migrate(ctx, dsn); err != nil {
		h.initErr = fmt.Errorf("migrate Postgres template: %w", err)
		return
	}

	base, err := url.Parse(dsn)
	if err != nil {
		h.initErr = fmt.Errorf("parse Postgres connection string: %w", err)
		return
	}
	h.baseURL = base

	admin, err := pgxpool.New(ctx, databaseURL(base, maintenanceDatabase))
	if err != nil {
		h.initErr = fmt.Errorf("open Postgres maintenance pool: %w", err)
		return
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		h.initErr = fmt.Errorf("ping Postgres maintenance pool: %w", err)
		return
	}
	h.admin = admin
}

func (h *Harness) close() error {
	if h == nil {
		return nil
	}
	if h.admin != nil {
		h.admin.Close()
	}
	if h.container == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.container.Terminate(ctx); err != nil {
		return fmt.Errorf("terminate Postgres testcontainer: %w", err)
	}
	return nil
}

func databaseURL(base *url.URL, database string) string {
	copy := *base
	copy.Path = "/" + database
	return copy.String()
}
