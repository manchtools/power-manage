package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/agent/internal/enroll"
	"github.com/manchtools/power-manage/sdk/config"
)

const cliTestDeviceID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func TestRunEnroll_AcceptsOnlyStdinOrTokenFile(t *testing.T) {
	tests := []struct {
		name       string
		args       func(*testing.T) []string
		stdin      string
		terminal   terminalInput
		wantToken  string
		wantPrompt bool
	}{
		{name: "pipe stdin", args: func(*testing.T) []string { return []string{"enroll"} }, stdin: "pipe-token\n", wantToken: "pipe-token"},
		{name: "TTY stdin", args: func(*testing.T) []string { return []string{"enroll"} }, terminal: terminalInput{
			isTerminal:   func(int) bool { return true },
			readPassword: func(int) ([]byte, error) { return []byte("tty-token"), nil },
		}, wantToken: "tty-token", wantPrompt: true},
		{name: "token file", args: func(t *testing.T) []string {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
				t.Fatalf("write token file: %v", err)
			}
			return []string{"enroll", "--token-file", path}
		}, stdin: "ignored", wantToken: "file-token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			var gotToken, gotSocket, gotPin string
			submit := func(_ context.Context, socket, token, pin string) (string, error) {
				gotSocket, gotToken, gotPin = socket, token, pin
				return cliTestDeviceID, nil
			}
			terminal := test.terminal
			if terminal.isTerminal == nil {
				terminal.isTerminal = func(int) bool { return false }
			}
			if terminal.readPassword == nil {
				terminal.readPassword = func(int) ([]byte, error) { return nil, errors.New("unexpected password read") }
			}
			err := run(context.Background(), test.args(t), strings.NewReader(test.stdin), &stdout, &stderr, 0, terminal, submit, enroll.DefaultSocketPath)
			if err != nil {
				t.Fatalf("run enroll: %v", err)
			}
			if gotToken != test.wantToken || gotSocket != enroll.DefaultSocketPath || gotPin != "" {
				t.Fatalf("submit = (%q, %q, %q); want default socket, %q token, empty pin", gotSocket, gotToken, gotPin, test.wantToken)
			}
			if strings.Contains(stdout.String(), test.wantToken) || strings.Contains(stderr.String(), test.wantToken) {
				t.Fatal("token appeared in CLI output")
			}
			if strings.Contains(stderr.String(), "Registration token:") != test.wantPrompt {
				t.Fatalf("prompt presence = %v; want %v", strings.Contains(stderr.String(), "Registration token:"), test.wantPrompt)
			}
			if !strings.Contains(stdout.String(), cliTestDeviceID) {
				t.Fatalf("stdout = %q; want enrolled device ID", stdout.String())
			}
		})
	}
}

func TestRunEnroll_HasNoTokenValuedArgvFlag(t *testing.T) {
	called := false
	var stdout, stderr bytes.Buffer
	err := run(
		context.Background(),
		[]string{"enroll", "--token", "argv-secret"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		0,
		terminalInput{isTerminal: func(int) bool { return false }, readPassword: func(int) ([]byte, error) { return nil, nil }},
		func(context.Context, string, string, string) (string, error) { called = true; return "", nil },
		enroll.DefaultSocketPath,
	)
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("argv-token error = %v; want unknown flag", err)
	}
	if called {
		t.Fatal("unknown token flag reached local relay submission")
	}
	if strings.Contains(stderr.String(), "argv-secret") || strings.Contains(stdout.String(), "argv-secret") {
		t.Fatal("argv token value appeared in CLI output")
	}
}

func TestConfigDocs(t *testing.T) {
	settings := agentConfig{Enrollment: agentEnrollmentConfig{Socket: enroll.DefaultSocketPath}}
	documentation, err := config.Doc(&settings)
	if err != nil {
		t.Fatalf("render agent configuration docs: %v", err)
	}
	if !strings.Contains(documentation, "socket") || !strings.Contains(documentation, "PM_ENROLLMENT_SOCKET") {
		t.Fatalf("agent configuration docs omit the enrollment socket:\n%s", documentation)
	}
}

func TestReadTokenFile_RefusesUnsafeOrOversizedInputs(t *testing.T) {
	directory := t.TempDir()
	secure := filepath.Join(directory, "secure")
	if err := os.WriteFile(secure, []byte("token\n"), 0o600); err != nil {
		t.Fatalf("write secure token file: %v", err)
	}
	if token, err := readTokenFile(secure); err != nil || token != "token" {
		t.Fatalf("read secure token file = (%q, %v); want token", token, err)
	}
	tests := []struct {
		name   string
		create func(*testing.T, string)
		want   string
	}{
		{name: "symlink", create: func(t *testing.T, path string) {
			if err := os.Symlink(secure, path); err != nil {
				t.Fatalf("create token symlink: %v", err)
			}
		}, want: "token file"},
		{name: "insecure mode", create: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("token"), 0o644); err != nil {
				t.Fatalf("write insecure token file: %v", err)
			}
		}, want: "permissions"},
		{name: "oversized", create: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(strings.Repeat("x", 513)), 0o600); err != nil {
				t.Fatalf("write oversized token file: %v", err)
			}
		}, want: "too large"},
		{name: "directory", create: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatalf("create token directory: %v", err)
			}
		}, want: "regular"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, strings.ReplaceAll(test.name, " ", "-"))
			test.create(t, path)
			_, err := readTokenFile(path)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("readTokenFile error = %v; want category %q", err, test.want)
			}
		})
	}
}
