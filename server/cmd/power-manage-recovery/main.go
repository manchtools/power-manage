package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/sdk/config"
	"github.com/manchtools/power-manage/server/internal/store"
)

const maxDSNFileBytes = 16 << 10

type rebuildFunc func(context.Context, string, string) error

type recoveryConfig struct {
	Database recoveryDatabaseConfig
	Rebuild  recoveryRebuildConfig
}

type recoveryDatabaseConfig struct {
	DSNFile string `doc:"Path to an owner-only regular file containing the Postgres connection string."`
}

type recoveryRebuildConfig struct {
	Target string `doc:"Registered production projection target to rebuild."`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], rebuildProduction); err != nil {
		log.Printf("recovery failed: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, rebuild rebuildFunc) error {
	if ctx == nil {
		return errors.New("recovery: nil context")
	}
	if rebuild == nil {
		return errors.New("recovery: nil rebuild function")
	}
	if len(args) == 0 || args[0] != "rebuild" {
		return errors.New("recovery: expected rebuild subcommand")
	}
	flags := flag.NewFlagSet("rebuild", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to the recovery configuration file")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("recovery: parse rebuild arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("recovery: rebuild accepts no positional arguments")
	}
	if strings.TrimSpace(*configPath) == "" {
		return errors.New("recovery: --config is required")
	}
	settings := recoveryConfig{Rebuild: recoveryRebuildConfig{Target: store.InventoryRebuildTarget}}
	if err := config.Load(*configPath, &settings); err != nil {
		return fmt.Errorf("recovery: load configuration: %w", err)
	}
	if !slices.Contains(store.ProductionRebuildTargetNames(), settings.Rebuild.Target) {
		return fmt.Errorf("recovery: target %q is not registered", settings.Rebuild.Target)
	}
	if strings.TrimSpace(settings.Database.DSNFile) == "" {
		return errors.New("recovery: database.dsn_file is required")
	}
	dsn, err := readDSNFile(settings.Database.DSNFile)
	if err != nil {
		return err
	}
	return rebuild(ctx, dsn, settings.Rebuild.Target)
}

func readDSNFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("recovery: open DSN file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("recovery: inspect DSN file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("recovery: DSN file is not regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("recovery: DSN file permissions allow group or other access")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxDSNFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("recovery: read DSN file: %w", err)
	}
	if len(contents) > maxDSNFileBytes {
		return "", fmt.Errorf("recovery: DSN file is too large (maximum %d bytes)", maxDSNFileBytes)
	}
	dsn := strings.TrimSpace(string(contents))
	if dsn == "" {
		return "", errors.New("recovery: DSN file is empty")
	}
	if strings.ContainsAny(dsn, "\x00\r\n") {
		return "", errors.New("recovery: DSN file contains invalid control characters")
	}
	return dsn, nil
}

func rebuildProduction(ctx context.Context, dsn, target string) error {
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("recovery: invalid database configuration")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("recovery: connect to database failed")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("recovery: database health check failed")
	}
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		return fmt.Errorf("recovery: construct production event store: %w", err)
	}
	if err := eventStore.RebuildAll(ctx, target); err != nil {
		return fmt.Errorf("recovery: rebuild target %q: %w", target, err)
	}
	return nil
}
