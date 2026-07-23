package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/config"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestRecoveryCLI_RebuildsRegisteredInventoryTarget(t *testing.T) {
	testRecoveryCLIRegisteredTarget(t, store.InventoryRebuildTarget)
}

func TestRecoveryCLI_RebuildsRegisteredTokenTarget(t *testing.T) {
	testRecoveryCLIRegisteredTarget(t, store.RegistrationTokenRebuildTarget)
}

func TestRecoveryCLI_RebuildsRegisteredPersonalAccessTokenTarget(t *testing.T) {
	testRecoveryCLIRegisteredTarget(t, store.PersonalAccessTokenRebuildTarget)
}

func TestRecoveryCLI_RebuildsRegisteredRefreshFamilyTarget(t *testing.T) {
	testRecoveryCLIRegisteredTarget(t, store.RefreshFamilyRebuildTarget)
}

func TestRecoveryCLI_RebuildsRegisteredDeviceTarget(t *testing.T) {
	testRecoveryCLIRegisteredTarget(t, store.DeviceRebuildTarget)
}

func testRecoveryCLIRegisteredTarget(t *testing.T, target string) {
	t.Helper()
	dsnPath := filepath.Join(t.TempDir(), "database.dsn")
	const wantDSN = "postgres://operator:secret@database.example/power_manage"
	if err := os.WriteFile(dsnPath, []byte(wantDSN+"\n"), 0o600); err != nil {
		t.Fatalf("write DSN file: %v", err)
	}
	configPath := writeRecoveryConfig(t, dsnPath, target)
	var gotDSN, gotTarget string
	err := run(context.Background(), []string{
		"rebuild",
		"--config", configPath,
	}, func(_ context.Context, dsn, target string) error {
		gotDSN = dsn
		gotTarget = target
		return nil
	})
	if err != nil {
		t.Fatalf("run %s recovery: %v", target, err)
	}
	if gotDSN != wantDSN || gotTarget != target {
		t.Fatalf("rebuild call = (%q, %q); want (%q, %q)", gotDSN, gotTarget, wantDSN, target)
	}
}

func TestRecoveryCLI_RejectsUnsupportedTarget(t *testing.T) {
	dsnPath := filepath.Join(t.TempDir(), "database.dsn")
	if err := os.WriteFile(dsnPath, []byte("postgres://database.example/power_manage"), 0o600); err != nil {
		t.Fatalf("write DSN file: %v", err)
	}
	configPath := writeRecoveryConfig(t, dsnPath, "events")
	called := false
	err := run(context.Background(), []string{
		"rebuild",
		"--config", configPath,
	}, func(context.Context, string, string) error {
		called = true
		return nil
	})
	const wantError = `recovery: target "events" is not registered`
	if err == nil || err.Error() != wantError {
		t.Fatalf("unsupported-target error = %v; want %q", err, wantError)
	}
	if called {
		t.Fatal("unsupported recovery target reached the database rebuild")
	}
}

func TestRecoveryCLI_DSNFileIsBounded(t *testing.T) {
	dsnPath := filepath.Join(t.TempDir(), "database.dsn")
	if err := os.WriteFile(dsnPath, []byte(strings.Repeat("x", maxDSNFileBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized DSN file: %v", err)
	}
	configPath := writeRecoveryConfig(t, dsnPath, "inventory")
	called := false
	err := run(context.Background(), []string{
		"rebuild",
		"--config", configPath,
	}, func(context.Context, string, string) error {
		called = true
		return nil
	})
	wantError := fmt.Sprintf(
		"recovery: DSN file is too large (maximum %d bytes)",
		maxDSNFileBytes,
	)
	if err == nil || err.Error() != wantError {
		t.Fatalf("oversized-DSN error = %v; want %q", err, wantError)
	}
	if called {
		t.Fatal("oversized DSN file reached the database rebuild")
	}
}

func TestRecoveryCLI_RejectsInsecureDSNFilePermissions(t *testing.T) {
	dsnPath := filepath.Join(t.TempDir(), "database.dsn")
	if err := os.WriteFile(
		dsnPath,
		[]byte("postgres://database.example/power_manage"),
		0o644,
	); err != nil {
		t.Fatalf("write insecure DSN file: %v", err)
	}
	configPath := writeRecoveryConfig(t, dsnPath, "inventory")
	called := false
	err := run(context.Background(), []string{
		"rebuild",
		"--config", configPath,
	}, func(context.Context, string, string) error {
		called = true
		return nil
	})
	const wantError = "recovery: DSN file permissions allow group or other access"
	if err == nil || err.Error() != wantError {
		t.Fatalf("insecure-DSN error = %v; want %q", err, wantError)
	}
	if called {
		t.Fatal("insecure DSN file reached the database rebuild")
	}
}

func TestConfigDocs(t *testing.T) {
	settings := recoveryConfig{Rebuild: recoveryRebuildConfig{Target: store.InventoryRebuildTarget}}
	documentation, err := config.Doc(&settings)
	if err != nil {
		t.Fatalf("render recovery configuration docs: %v", err)
	}
	if !strings.Contains(documentation, "dsn_file") || !strings.Contains(documentation, "target") {
		t.Fatalf("recovery configuration docs omit a key:\n%s", documentation)
	}
}

func writeRecoveryConfig(t *testing.T, dsnPath, target string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "recovery.conf")
	contents := fmt.Sprintf("[database]\ndsn_file = %s\n[rebuild]\ntarget = %s\n", dsnPath, target)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write recovery configuration: %v", err)
	}
	return path
}
