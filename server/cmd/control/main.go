package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/sdk/config"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	maxDSNFileBytes          = 16 << 10
	bootstrapDatabaseTimeout = 10 * time.Second
)

type bootstrapMintFunc func(context.Context, string, string, string) (string, error)

type controlConfig struct {
	Database       controlDatabaseConfig       `doc:"Control database connection settings."`
	BootstrapAdmin controlBootstrapAdminConfig `doc:"Host-authorized break-glass settings."`
}

type controlDatabaseConfig struct {
	DSNFile string `doc:"Path to an owner-only regular file containing the Postgres connection string."`
}

type controlBootstrapAdminConfig struct {
	Email    string `doc:"Named administrator identity to create or reuse."`
	LoginURL string `doc:"HTTPS web UI URL that receives the one-time token in its fragment."`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, bootstrapProduction); err != nil {
		log.Printf("control command failed: %v", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	mint bootstrapMintFunc,
) error {
	if ctx == nil {
		return errors.New("control: nil context")
	}
	if stdout == nil {
		return errors.New("control: nil output")
	}
	if mint == nil {
		return errors.New("control: bootstrap mint function is not wired")
	}
	if len(args) == 0 || args[0] != "bootstrap-admin" {
		return errors.New("control: expected bootstrap-admin subcommand")
	}
	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to the control configuration file")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("control: parse bootstrap-admin arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("control: bootstrap-admin accepts no positional arguments")
	}
	if strings.TrimSpace(*configPath) == "" {
		return errors.New("control: --config is required")
	}
	var settings controlConfig
	if err := config.Load(*configPath, &settings); err != nil {
		return fmt.Errorf("control: load configuration: %w", err)
	}
	if strings.TrimSpace(settings.Database.DSNFile) == "" {
		return errors.New("control: database.dsn_file is required")
	}
	if strings.TrimSpace(settings.BootstrapAdmin.Email) == "" {
		return errors.New("control: bootstrap_admin.email is required")
	}
	if strings.TrimSpace(settings.BootstrapAdmin.LoginURL) == "" {
		return errors.New("control: bootstrap_admin.login_url is required")
	}
	dsn, err := readDSNFile(settings.Database.DSNFile)
	if err != nil {
		return err
	}
	loginURL, err := mint(
		ctx,
		dsn,
		settings.BootstrapAdmin.Email,
		settings.BootstrapAdmin.LoginURL,
	)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, loginURL); err != nil {
		return fmt.Errorf("control: write bootstrap login URL: %w", err)
	}
	return nil
}

func readDSNFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("control: open DSN file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("control: inspect DSN file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("control: DSN file is not regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("control: DSN file permissions allow group or other access")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxDSNFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("control: read DSN file: %w", err)
	}
	if len(contents) > maxDSNFileBytes {
		return "", fmt.Errorf(
			"control: DSN file is too large (maximum %d bytes)",
			maxDSNFileBytes,
		)
	}
	dsn := strings.TrimSpace(string(contents))
	if dsn == "" {
		return "", errors.New("control: DSN file is empty")
	}
	if strings.ContainsAny(dsn, "\x00\r\n") {
		return "", errors.New("control: DSN file contains invalid control characters")
	}
	return dsn, nil
}

func bootstrapProduction(
	ctx context.Context,
	dsn string,
	email string,
	loginURL string,
) (string, error) {
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return "", errors.New("control: invalid database configuration")
	}
	connectCtx, cancelConnect := context.WithTimeout(ctx, bootstrapDatabaseTimeout)
	defer cancelConnect()
	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		return "", errors.New("control: connect to database failed")
	}
	defer pool.Close()
	if err := pool.Ping(connectCtx); err != nil {
		return "", errors.New("control: database health check failed")
	}
	cancelConnect()
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		return "", fmt.Errorf("control: construct production event store: %w", err)
	}
	minter, err := auth.NewBootstrapAdminMinter(eventStore, rand.Reader, time.Now)
	if err != nil {
		return "", fmt.Errorf("control: construct bootstrap admin minter: %w", err)
	}
	return minter.Mint(ctx, email, loginURL)
}
