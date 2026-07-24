package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/config"
)

func TestBootstrapAdminCLI_LoadsTypedConfigAndPrintsOnlyURL(t *testing.T) {
	directory := t.TempDir()
	dsnPath := filepath.Join(directory, "database.dsn")
	if err := os.WriteFile(dsnPath, []byte("postgres://control:test@localhost/control\n"), 0o600); err != nil {
		t.Fatalf("write DSN file: %v", err)
	}
	configPath := writeBootstrapConfig(
		t,
		dsnPath,
		"Admin@Example.Test",
		"https://control.example.test/break-glass",
	)
	var gotDSN, gotEmail, gotLoginURL string
	mint := func(_ context.Context, dsn, email, loginURL string) (string, error) {
		gotDSN, gotEmail, gotLoginURL = dsn, email, loginURL
		return "https://control.example.test/break-glass#bootstrap_token=secret", nil
	}
	var stdout bytes.Buffer
	if err := run(
		t.Context(),
		[]string{"bootstrap-admin", "--config", configPath},
		&stdout,
		mint,
	); err != nil {
		t.Fatalf("run bootstrap-admin: %v", err)
	}
	if gotDSN != "postgres://control:test@localhost/control" ||
		gotEmail != "Admin@Example.Test" ||
		gotLoginURL != "https://control.example.test/break-glass" {
		t.Fatalf(
			"mint arguments = (%q, %q, %q); want typed config values",
			gotDSN,
			gotEmail,
			gotLoginURL,
		)
	}
	if stdout.String() != "https://control.example.test/break-glass#bootstrap_token=secret\n" {
		t.Fatalf("bootstrap stdout = %q; want URL and newline only", stdout.String())
	}
}

func TestBootstrapAdminCLI_RejectsInsecureOrOversizedDSNFile(t *testing.T) {
	for _, test := range []struct {
		name        string
		contents    []byte
		mode        os.FileMode
		wantErrText string
	}{
		{
			name:        "insecure permissions",
			contents:    []byte("postgres://localhost/control"),
			mode:        0o644,
			wantErrText: "DSN file permissions allow group or other access",
		},
		{
			name:        "oversized",
			contents:    bytes.Repeat([]byte{'x'}, maxDSNFileBytes+1),
			mode:        0o600,
			wantErrText: "DSN file is too large",
		},
		{
			name:        "control character",
			contents:    []byte("postgres://localhost/control\nsecond"),
			mode:        0o600,
			wantErrText: "DSN file contains invalid control characters",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			dsnPath := filepath.Join(directory, "database.dsn")
			if err := os.WriteFile(dsnPath, test.contents, test.mode); err != nil {
				t.Fatalf("write DSN fixture: %v", err)
			}
			configPath := writeBootstrapConfig(
				t,
				dsnPath,
				"admin@example.test",
				"https://control.example.test/break-glass",
			)
			called := false
			err := run(
				t.Context(),
				[]string{"bootstrap-admin", "--config", configPath},
				&bytes.Buffer{},
				func(context.Context, string, string, string) (string, error) {
					called = true
					return "", nil
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.wantErrText) {
				t.Fatalf("unsafe DSN file error = %v; want %q", err, test.wantErrText)
			}
			if called {
				t.Fatal("unsafe DSN file reached bootstrap minting")
			}
		})
	}
}

func TestBootstrapAdminCLI_HasNoCredentialValuedFlags(t *testing.T) {
	called := false
	err := run(
		t.Context(),
		[]string{
			"bootstrap-admin",
			"--config", "unused.yaml",
			"--password", "argv-secret",
		},
		&bytes.Buffer{},
		func(context.Context, string, string, string) (string, error) {
			called = true
			return "", nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("credential flag error = %v; want unknown flag", err)
	}
	if called {
		t.Fatal("credential-valued flag reached bootstrap minting")
	}
}

func TestConfigDocs(t *testing.T) {
	documentation, err := config.Doc(&controlConfig{})
	if err != nil {
		t.Fatalf("render control configuration docs: %v", err)
	}
	for _, key := range []string{"dsn_file", "email", "login_url"} {
		if !strings.Contains(documentation, key) {
			t.Fatalf("control configuration docs omit %q:\n%s", key, documentation)
		}
	}
}

func writeBootstrapConfig(t *testing.T, dsnPath, email, loginURL string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.conf")
	contents := "[database]\n" +
		"dsn_file = " + dsnPath + "\n" +
		"[bootstrap_admin]\n" +
		"email = " + email + "\n" +
		"login_url = " + loginURL + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write control config: %v", err)
	}
	return path
}
