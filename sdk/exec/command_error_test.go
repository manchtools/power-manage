package exec

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// CommandError is the typed error the capability layer wraps a non-zero exit
// in. It must carry ExitCode + Stderr for callers that branch on them via
// errors.As, and Unwrap to the underlying cause so errors.Is chains.

func TestCommandError_CarriesExitCodeAndStderr(t *testing.T) {
	ce := &CommandError{Name: "useradd", ExitCode: 9, Stderr: "useradd: user 'deploy' already exists\n"}
	msg := ce.Error()
	if !strings.Contains(msg, "useradd") {
		t.Errorf("Error() = %q, want it to name the command", msg)
	}
	if !strings.Contains(msg, "9") {
		t.Errorf("Error() = %q, want it to include exit code 9", msg)
	}
	if !strings.Contains(msg, "already exists") {
		t.Errorf("Error() = %q, want it to include stderr", msg)
	}
	if strings.Contains(msg, "\n") {
		t.Errorf("Error() = %q, want trailing stderr newline trimmed", msg)
	}
}

func TestCommandError_ErrorsAsAndUnwrap(t *testing.T) {
	cause := errors.New("underlying")
	ce := &CommandError{Name: "cryptsetup", ExitCode: 2, Stderr: "wrong passphrase", Err: cause}
	wrapped := fmt.Errorf("add key: %w", ce)

	var got *CommandError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As did not unwrap to *CommandError")
	}
	if got.ExitCode != 2 {
		t.Errorf("recovered ExitCode = %d, want 2", got.ExitCode)
	}
	if !errors.Is(wrapped, cause) {
		t.Error("errors.Is did not reach the wrapped cause via Unwrap")
	}
}

// The Runner's construction/escalation sentinels must be distinct and
// errors.Is-matchable (fail-closed contract: a caller can tell "tool missing"
// from "needs a password" from "unknown backend").
func TestRunnerSentinels_AreDistinct(t *testing.T) {
	all := []error{ErrUnknownBackend, ErrEscalationUnavailable, ErrEscalationDenied, ErrRunnerRequired, ErrBackendUnavailable}
	for i := range all {
		for j := range all {
			if i != j && errors.Is(all[i], all[j]) {
				t.Errorf("sentinels %d and %d are not distinct", i, j)
			}
		}
	}
}
