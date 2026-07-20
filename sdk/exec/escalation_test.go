package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeExecScript writes an executable shell script and returns its path.
func writeExecScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// When escalation is requested but the wrapper tool is not on PATH, the Runner
// fails closed with ErrEscalationUnavailable rather than running unescalated.
// A temp-dir PATH containing the payload but NOT sudo makes this deterministic.
// (t.Setenv here changes the PARENT's lookup PATH — binary resolution happens
// in the parent; the child env stays the curated baseline.)
func TestRunner_EscalationUnavailableWhenToolMissing(t *testing.T) {
	dir := t.TempDir()
	writeExecScript(t, dir, "payload", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir) // sudo is intentionally absent here

	r, err := NewRunner(Sudo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background(), Command{Name: "payload", Escalate: true}); !errors.Is(err, ErrEscalationUnavailable) {
		t.Errorf("err = %v, want ErrEscalationUnavailable", err)
	}
}

// When the wrapper runs but refuses (a `sudo -n` that would need a password),
// the Runner surfaces ErrEscalationDenied — distinct from the command's own
// non-zero exit. Exercised end-to-end with a fake `sudo` on PATH that emits the
// real diagnostic and exits 1.
func TestRunner_EscalationDeniedFromWrapper(t *testing.T) {
	dir := t.TempDir()
	writeExecScript(t, dir, "sudo", "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")
	writeExecScript(t, dir, "payload", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir)

	r, err := NewRunner(Sudo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background(), Command{Name: "payload", Escalate: true}); !errors.Is(err, ErrEscalationDenied) {
		t.Errorf("err = %v, want ErrEscalationDenied", err)
	}
}

// A successful escalated run through a fake `sudo` (exit 0) returns no error and
// reports the wrapped command's exit code — the happy escalation path.
func TestRunner_EscalatedRunSucceeds(t *testing.T) {
	dir := t.TempDir()
	// Fake sudo execs its remaining args ("-n <abs payload> …" → drops -n).
	writeExecScript(t, dir, "sudo", "#!/bin/sh\nshift\nexec \"$@\"\n")
	writeExecScript(t, dir, "payload", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir)

	r, err := NewRunner(Sudo)
	if err != nil {
		t.Fatalf("NewRunner err = %v, want nil", err)
	}
	res, err := r.Run(context.Background(), Command{Name: "payload", Escalate: true})
	if err != nil {
		t.Fatalf("escalated run err = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
}

// Detect lists exactly the escalation tools present on PATH — covered with fake
// sudo + doas so both branches run deterministically (a real host may lack doas).
func TestDetect_ListsFakeToolsOnPath(t *testing.T) {
	dir := t.TempDir()
	writeExecScript(t, dir, "sudo", "#!/bin/sh\n")
	writeExecScript(t, dir, "doas", "#!/bin/sh\n")
	t.Setenv("PATH", dir)

	got := Detect(context.Background())
	var hasSudo, hasDoas bool
	for _, b := range got {
		switch b {
		case Sudo:
			hasSudo = true
		case Doas:
			hasDoas = true
		default:
			t.Errorf("Detect returned unexpected backend %d", b)
		}
	}
	if !hasSudo || !hasDoas {
		t.Errorf("Detect = %v, want both Sudo and Doas", got)
	}
}

// Detect returns an empty slice when neither tool is on PATH (a root-only host
// that will use Direct).
func TestDetect_EmptyWhenNoToolsOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir
	if got := Detect(context.Background()); len(got) != 0 {
		t.Errorf("Detect = %v, want empty on a host with no sudo/doas", got)
	}
}

// CommandError.Error formats without a stderr suffix when stderr is empty.
func TestCommandError_ErrorWithoutStderr(t *testing.T) {
	ce := &CommandError{Name: "userdel", ExitCode: 1}
	if got, want := ce.Error(), "userdel: exit 1"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
