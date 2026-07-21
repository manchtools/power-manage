package pkg

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/validate"
)

// runRead executes an unprivileged read-side query (Info / Search / List /
// Show / version + status probes) through the injected Runner. The Runner forces
// the C locale on every command, so the output parser always sees the stable
// English form regardless of the host locale. A non-zero exit is reported in
// Result.ExitCode (NOT as an error) — read callers branch on specific codes (e.g.
// dnf check-update's 100, dpkg -s's 1) — so the returned error is non-nil only
// when the command could not be executed at all.
func runRead(ctx context.Context, r pmexec.Runner, name string, args ...string) (pmexec.Result, error) {
	return r.Run(ctx, pmexec.Command{Name: name, Args: args})
}

// probe runs an unprivileged read whose non-zero exit is a benign domain signal
// — "not installed" / "not pinned" / "not in repo" / "no such subcommand" —
// rather than a failure, while a runner error (binary missing, blocked env,
// context cancellation) propagates. It returns (stdout, ok, err): ok is true
// only on a clean (exit 0) run. This is the seam that keeps tolerant lookups
// from masking cancellations and executor failures as a benign miss.
func probe(ctx context.Context, r pmexec.Runner, name string, absentExit int, args ...string) (string, bool, error) {
	res, err := runRead(ctx, r, name, args...)
	if err != nil {
		return "", false, err
	}
	if res.ExitCode == 0 {
		return res.Stdout, true, nil
	}
	if res.ExitCode == absentExit {
		return "", false, nil
	}
	return "", false, asCommandError(name, res)
}

// runPriv executes a privileged write-side command (Install / Remove / Update /
// …) through the Runner. escalate is true for every native-manager mutation and
// for system-scope flatpak; it is false for user-scope flatpak. env carries any
// backend-specific variables (e.g. apt's DEBIAN_FRONTEND=noninteractive) on top
// of the forced C locale. Like runRead, a non-zero exit is in Result.ExitCode,
// not the error; callers convert it via asCommandError when a non-zero exit
// means failure (most do; dnf check-update does not).
func runPriv(ctx context.Context, r pmexec.Runner, escalate bool, env []string, name string, args ...string) (pmexec.Result, error) {
	return r.Run(ctx, pmexec.Command{
		Name:     name,
		Args:     args,
		Env:      env,
		Escalate: escalate,
	})
}

// readOut runs an unprivileged read whose non-zero exit is itself a failure
// (List/Show/Version/… — a garbled or error exit means the parse can't proceed),
// returning stdout on a clean exit and an *exec.CommandError otherwise. Reads
// that branch on a specific exit code (dpkg -s's 1, dnf check-update's 100,
// search's "no matches" codes) call runRead directly and inspect Result.ExitCode.
func readOut(ctx context.Context, r pmexec.Runner, name string, args ...string) (string, error) {
	res, err := runRead(ctx, r, name, args...)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", &pmexec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res.Stdout, nil
}

// runPrivStdin is the stdin-bearing companion of runPriv (pacman.conf rewrite
// via tee). An empty stdin sends no input.
func runPrivStdin(ctx context.Context, r pmexec.Runner, escalate bool, env []string, stdin, name string, args ...string) (pmexec.Result, error) {
	var in io.Reader
	if stdin != "" {
		in = strings.NewReader(stdin)
	}
	return r.Run(ctx, pmexec.Command{
		Name:     name,
		Args:     args,
		Env:      env,
		Stdin:    in,
		Escalate: escalate,
	})
}

// asCommandError turns a completed command's Result into a typed error when its
// exit code is non-zero, mirroring the old "non-zero exit ⇒ failure" contract
// the mutating methods rely on. A clean exit returns nil. The exit code and
// stderr are preserved on *exec.CommandError so callers can branch via
// errors.As.
func asCommandError(name string, res pmexec.Result) error {
	if res.ExitCode == 0 {
		return nil
	}
	return &pmexec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
}

// rpmLocalPackageInfo reads NAME / VERSION-RELEASE / ARCH out of a local .rpm via
// `rpm -qp --qf` (an unprivileged read), shared by the dnf and zypper backends so
// their local-introspection cannot drift. The %{NAME} a crafted .rpm embeds is
// untrusted, so it is re-validated with validate.RpmPackageName before it is
// returned — a flag-shaped or metacharacter-bearing name is rejected here, not
// passed on to a later rpm -q/-e as an option.
func rpmLocalPackageInfo(ctx context.Context, r pmexec.Runner, path string) (*LocalPackage, error) {
	if err := validate.LocalPackagePath(path); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, r, "rpm", "-qp", "--qf", "%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}", path)
	if err != nil {
		return nil, err
	}
	fields := splitPositionalFields(out)
	if len(fields) == 0 {
		return nil, fmt.Errorf("pkg: rpm -qp reported no name for %q", path)
	}
	name := fields[0]
	if err := validate.RpmPackageName(name); err != nil {
		return nil, fmt.Errorf("pkg: local .rpm reports an unsafe package name: %w", err)
	}
	info := &LocalPackage{Name: name}
	if len(fields) > 1 {
		info.Version = fields[1]
	}
	if len(fields) > 2 {
		info.Arch = fields[2]
	}
	return info, nil
}

// parseColonValue returns the trimmed value after the first colon in a
// "Key: value" info line, or "" when the line has no colon. Shared by every
// rpm/pacman/flatpak info parser so the "split on first colon" rule cannot drift
// between backends.
func parseColonValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// sizeUnit pairs a trailing size suffix (with its leading space, e.g. " KiB")
// with the byte multiplier it denotes.
type sizeUnit struct {
	suffix string
	mult   int64
}

// parseSizeWithUnits parses a human-readable size string ("3.0 MiB", "512 k",
// "900 B") into bytes using the supplied ordered unit table. Units are tried in
// order, so a caller must list more specific suffixes before any that are a
// suffix of them. A matched suffix is stripped and its multiplier applied; a
// unit with mult == 1 is a no-op-multiplier suffix that is merely trimmed. The
// remaining text is parsed strictly: malformed, negative, NaN, infinite, and
// overflowing values are errors rather than silent zeroes ([SDK-15]).
func parseSizeWithUnits(s string, units []sizeUnit) (int64, error) {
	original := s
	s = strings.TrimSpace(s)
	multiplier := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			multiplier = u.mult
			s = strings.TrimSuffix(s, u.suffix)
			break
		}
	}
	size, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || size < 0 || math.IsNaN(size) || math.IsInf(size, 0) || size >= float64(math.MaxInt64)/float64(multiplier) {
		return 0, fmt.Errorf("%w: invalid size %q", ErrMalformedOutput, original)
	}
	return int64(size * float64(multiplier)), nil
}

// splitPositionalFields splits VALUE-ONLY one-field-per-line command output (rpm
// -qp --qf with "\n" separators) into its POSITIONAL fields, trimming each line
// but PRESERVING an empty leading/middle field so the name/version/arch positions
// never shift. NOTE: it is NOT for dpkg-deb -f with multiple fields, which emits
// a labeled "Field: value" stanza (use parseControlFields). A crafted file that
// emits an empty NAME must surface as an empty field[0]
// (rejected by the name validator) — NOT silently promote the version into the
// name slot. Only the trailing blank line the tool appends is dropped.
func splitPositionalFields(data string) []string {
	lines := strings.Split(strings.TrimRight(data, "\n"), "\n")
	fields := make([]string, len(lines))
	for i, line := range lines {
		fields[i] = strings.TrimSpace(line)
	}
	return fields
}

// countNonEmptyLines counts non-blank lines in command output.
func countNonEmptyLines(data string) int {
	count := 0
	for _, line := range bytes.Split([]byte(data), []byte("\n")) {
		if len(strings.TrimSpace(string(line))) > 0 {
			count++
		}
	}
	return count
}

// lineScanner provides Scanner's line iteration semantics for output that is
// already resident in memory. Using strings directly removes the artificial
// token-size/error surface of bufio.Scanner from package-manager parsers.
type lineScanner struct {
	lines []string
	next  int
}

func newLineScanner(data string) *lineScanner {
	if data == "" {
		return &lineScanner{}
	}
	return &lineScanner{lines: strings.Split(strings.TrimSuffix(data, "\n"), "\n")}
}

func (s *lineScanner) Scan() bool {
	if s.next >= len(s.lines) {
		return false
	}
	s.next++
	return true
}

func (s *lineScanner) Text() string {
	if s.next == 0 || s.next > len(s.lines) {
		return ""
	}
	return s.lines[s.next-1]
}
