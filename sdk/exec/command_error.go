package exec

import (
	"errors"
	"fmt"
	"strings"
)

// Construction- and escalation-failure sentinels. All are errors.Is-matchable
// so a caller can fail closed and distinguish the cases.
var (
	// ErrUnknownBackend is returned by NewRunner for the zero value or any
	// PrivilegeBackend the SDK does not implement (fail-closed, no silent
	// default escalation).
	ErrUnknownBackend = errors.New("unknown privilege backend")

	// ErrEscalationUnavailable is returned when the chosen escalation tool
	// (sudo/doas) is not installed on this host.
	ErrEscalationUnavailable = errors.New("escalation tool not installed")

	// ErrEscalationDenied is returned when `sudo -n` / `doas -n` would need a
	// password (no NOPASSWD rule) — the agent never has a terminal to type one,
	// so this fails closed rather than hanging.
	ErrEscalationDenied = errors.New("escalation requires a password")

	// ErrRunnerRequired is returned by a capability constructor (New) when the
	// caller passes a nil Runner. It is shared by every capability package so a
	// nil runner is rejected identically everywhere and callers can match it with
	// errors.Is regardless of which capability they constructed.
	ErrRunnerRequired = errors.New("runner is required")

	// ErrBackendUnavailable is returned when the command/tool a capability needs
	// is not available on this host — the Runner cannot resolve the binary on
	// PATH. It is errors.Is-matchable so a caller can treat "tool not installed"
	// distinctly from a real failure (e.g. IsRequired-style probes report a
	// missing tool as "no, and that's fine" rather than an error).
	ErrBackendUnavailable = errors.New("backend unavailable")
)

// CommandError is the typed error the capability layer wraps a failed command
// in. The Runner itself does NOT treat a non-zero exit as an error (callers
// branch on specific codes — cryptsetup 2 = wrong passphrase, etc.); the
// capability layer decides when a non-zero exit becomes a CommandError. It
// carries the exit code and captured stderr so callers can branch on them via
// errors.As without importing internals.
type CommandError struct {
	Name     string // the command that failed, e.g. "useradd"
	ExitCode int
	Stderr   string
	Err      error // underlying cause, if any
}

func (e *CommandError) Error() string {
	if s := strings.TrimSpace(e.Stderr); s != "" {
		return fmt.Sprintf("%s: exit %d: %s", e.Name, e.ExitCode, s)
	}
	return fmt.Sprintf("%s: exit %d", e.Name, e.ExitCode)
}

func (e *CommandError) Unwrap() error { return e.Err }
