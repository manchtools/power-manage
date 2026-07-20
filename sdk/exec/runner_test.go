package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// NewRunner is pure and fail-closed: it validates the backend is KNOWN and does
// not probe the host. The zero value and any unimplemented value are rejected
// with ErrUnknownBackend — no silent default escalation.

func TestNewRunner_RejectsZeroAndUnknown(t *testing.T) {
	for _, b := range []PrivilegeBackend{0, PrivilegeBackend(-1), PrivilegeBackend(99)} {
		r, err := NewRunner(b)
		if !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("NewRunner(%d) err = %v, want ErrUnknownBackend", b, err)
		}
		if r != nil {
			t.Errorf("NewRunner(%d) returned a non-nil runner on error", b)
		}
	}
}

func TestNewRunner_AcceptsImplementedBackends(t *testing.T) {
	for _, b := range []PrivilegeBackend{Sudo, Doas, Direct} {
		r, err := NewRunner(b)
		if err != nil {
			t.Fatalf("NewRunner(%d) err = %v, want nil", b, err)
		}
		if r.Backend() != b {
			t.Errorf("Backend() = %d, want %d", r.Backend(), b)
		}
	}
}

// The capability layer sets Command.Escalate and is escalation-method-agnostic;
// the Runner alone turns that into sudo -n / doas -n / bare. wrapEscalation is
// the pure seam that decides the final (name, argv) — unit-testable without a
// real sudo on PATH.
func TestWrapEscalation(t *testing.T) {
	const abs = "/usr/sbin/useradd"
	args := []string{"-m", "deploy"}

	tests := []struct {
		backend  PrivilegeBackend
		escalate bool
		wantName string
		wantArgv []string
	}{
		{Direct, true, abs, []string{"-m", "deploy"}},
		{Direct, false, abs, []string{"-m", "deploy"}},
		{Sudo, true, "sudo", []string{"-n", abs, "-m", "deploy"}},
		{Doas, true, "doas", []string{"-n", abs, "-m", "deploy"}},
		{Sudo, false, abs, []string{"-m", "deploy"}}, // no escalation requested → bare
		{Doas, false, abs, []string{"-m", "deploy"}},
	}
	for _, tc := range tests {
		name, argv := wrapEscalation(tc.backend, tc.escalate, abs, args)
		if name != tc.wantName {
			t.Errorf("backend=%d escalate=%v: name=%q, want %q", tc.backend, tc.escalate, name, tc.wantName)
		}
		if strings.Join(argv, " ") != strings.Join(tc.wantArgv, " ") {
			t.Errorf("backend=%d escalate=%v: argv=%v, want %v", tc.backend, tc.escalate, argv, tc.wantArgv)
		}
	}
}

// wrapEscalation must not alias/mutate the caller's args slice (a reused arg
// list must stay pristine across calls).
func TestWrapEscalation_DoesNotMutateCallerArgs(t *testing.T) {
	args := []string{"-m", "deploy"}
	_, _ = wrapEscalation(Sudo, true, "/usr/sbin/useradd", args)
	if args[0] != "-m" || args[1] != "deploy" || len(args) != 2 {
		t.Errorf("caller args mutated: %v", args)
	}
}

func directRunner(t *testing.T) Runner {
	t.Helper()
	r, err := NewRunner(Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	return r
}

// A non-zero exit is NOT an error — it is reported in Result.ExitCode, because
// callers branch on specific codes (cryptsetup 2 = wrong passphrase, etc.). The
// Runner returns a non-nil error only on FAILURE TO EXECUTE.
func TestRunner_NonZeroExitIsNotAnError(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "exit 3"}})
	if err != nil {
		t.Fatalf("Run err = %v, want nil for a clean non-zero exit", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.ExitCode)
	}
}

func TestRunner_CapturesStdout(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "printf hello"}})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(res.Stdout, "hello") {
		t.Errorf("Stdout = %q, want it to contain hello", res.Stdout)
	}
}

func TestRunner_RejectsEmptyNameAndUnknownBinary(t *testing.T) {
	if _, err := directRunner(t).Run(context.Background(), Command{Name: ""}); err == nil {
		t.Error("Run with empty Name returned nil error, want a failure-to-execute error")
	}
	if _, err := directRunner(t).Run(context.Background(), Command{Name: "definitely-not-a-real-binary-xyz"}); !errors.Is(err, ErrBackendUnavailable) {
		t.Errorf("Run with a nonexistent binary err = %v, want ErrBackendUnavailable (errors.Is-matchable)", err)
	}
}

// [SDK-4]: the child environment is composed from the curated allowlist
// baseline — NEVER from os.Environ(). With no ChildPath and no Env the result
// is EXACTLY baseline PATH + forced locale triple; nothing is inherited.
func TestBuildChildEnv_NoInheritBranch(t *testing.T) {
	t.Setenv("PM_M2_CANARY", "leaked") // must not appear in any branch below

	env, err := buildChildEnv(Command{})
	if err != nil {
		t.Fatalf("buildChildEnv: %v", err)
	}
	want := []string{"PATH=" + curatedPath, "LC_ALL=C", "LANG=C", "NO_COLOR=1"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("buildChildEnv(zero Command) = %v, want exactly %v (allowlist baseline, no inheritance)", env, want)
	}

	// Validated additions slot between the baseline PATH and the forced triple
	// (forcedEnv is appended LAST so the deterministic vars always win).
	env, err = buildChildEnv(Command{Env: []string{"PM_EXTRA=1"}})
	if err != nil {
		t.Fatalf("buildChildEnv with Env: %v", err)
	}
	want = []string{"PATH=" + curatedPath, "PM_EXTRA=1", "LC_ALL=C", "LANG=C", "NO_COLOR=1"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("buildChildEnv(Env addition) = %v, want %v", env, want)
	}

	// ChildPath replaces the baseline PATH; still no inheritance.
	env, err = buildChildEnv(Command{ChildPath: "/curated/bin"})
	if err != nil {
		t.Fatalf("buildChildEnv with ChildPath: %v", err)
	}
	want = []string{"PATH=/curated/bin", "LC_ALL=C", "LANG=C", "NO_COLOR=1"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("buildChildEnv(ChildPath) = %v, want %v", env, want)
	}
}

// AC-4: a canary variable set in the parent process environment never appears
// in a child's environment.
func TestRunner_CanaryNeverReachesChild(t *testing.T) {
	t.Setenv("PM_M2_CANARY", "leaked-from-parent")

	res, err := directRunner(t).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", `printf %s "${PM_M2_CANARY:-unset}"`},
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "unset" {
		t.Errorf("child saw PM_M2_CANARY=%q; the parent environment must never reach a child", got)
	}
}

// AC-4: PATH is present in the child and equals the curated value.
func TestRunner_PathIsCurated(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", `printf %s "$PATH"`},
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != curatedPath {
		t.Errorf("child PATH = %q, want the curated baseline %q", got, curatedPath)
	}
}

// The escalation contract requires an ABSOLUTE path (sudoers/doas match on
// absolute paths; escalating a relative path is a security risk). exec.LookPath
// returns a slash-containing relative Name UNCHANGED and with a nil error, so
// the Runner must enforce absoluteness itself.
func TestResolveAbsolute_BareNameIsAbsolute(t *testing.T) {
	abs, err := resolveAbsolute("sh")
	if err != nil {
		t.Fatalf("resolveAbsolute(sh) err = %v", err)
	}
	if !filepath.IsAbs(abs) {
		t.Errorf("resolveAbsolute(sh) = %q, want an absolute path", abs)
	}
}

func TestResolveAbsolute_RelativeSlashNameResolvedToAbsolute(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	abs, err := resolveAbsolute("./tool")
	if err != nil {
		t.Fatalf("resolveAbsolute(./tool) err = %v", err)
	}
	if !filepath.IsAbs(abs) {
		t.Errorf("resolveAbsolute(./tool) = %q, want an absolute path (LookPath leaves it relative)", abs)
	}
}

// An already-cancelled context must short-circuit: the command never runs and
// the Runner returns ctx.Err(). Without the upfront check a fast-completing
// command could win the race against ctx.Done() and report success — a caller
// passing a dead ctx could still trigger a side effect. (This also keeps the
// real Runner and exectest.FakeRunner behaviourally identical on cancellation.)
func TestRunner_RespectsAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := directRunner(t).Run(ctx, Command{Name: "sh", Args: []string{"-c", "exit 0"}}); !errors.Is(err, context.Canceled) {
		t.Errorf("Run with a pre-cancelled ctx err = %v, want context.Canceled", err)
	}
}

// Stdin is delivered to the child (the chpasswd/cryptsetup path the capability
// layer relies on — secrets travel via stdin, never argv).
func TestRunner_DeliversStdin(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{
		Name:  "cat",
		Stdin: strings.NewReader("piped-secret"),
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if !strings.Contains(res.Stdout, "piped-secret") {
		t.Errorf("Stdout = %q, want the piped stdin echoed back", res.Stdout)
	}
}

// The env hijack blocklist is enforced through Command.Env — a blocked name is
// rejected BEFORE the child is spawned (present-but-wrong → Runner does no work).
func TestRunner_EnvBlocklistRejectedBeforeExec(t *testing.T) {
	r := directRunner(t)
	if _, err := r.Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "true"}, Env: []string{"LD_PRELOAD=/evil.so"}}); !errors.Is(err, ErrBlockedEnvVar) {
		t.Errorf("blocked env err = %v, want ErrBlockedEnvVar", err)
	}
	if _, err := r.Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "true"}, Env: []string{"PATH=/evil"}}); !errors.Is(err, ErrBlockedEnvVar) {
		t.Errorf("PATH-via-Env err = %v, want ErrBlockedEnvVar (use ChildPath for a curated PATH)", err)
	}
	if _, err := r.Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "true"}, Env: []string{"not-key-value"}}); !errors.Is(err, ErrInvalidEnvVar) {
		t.Errorf("malformed env err = %v, want ErrInvalidEnvVar", err)
	}
}

func TestRunner_AllowedEnvReachesChild(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", `printf %s "$PM_TEST_VAR"`},
		Env: []string{"PM_TEST_VAR=visible"},
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if !strings.Contains(res.Stdout, "visible") {
		t.Errorf("Stdout = %q, want the allowed env var visible to the child", res.Stdout)
	}
}

// [SDK-3] / AC-3: the Runner forces a deterministic environment (LC_ALL=C,
// LANG=C, NO_COLOR=1) on EVERY command — not a per-command opt-in — so the
// SDK's parsing of tool output is locale/format-stable regardless of the host.
func TestRunner_ForcesDeterministicEnv(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", `printf '%s|%s|%s' "$LC_ALL" "$LANG" "$NO_COLOR"`},
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "C|C|1" {
		t.Errorf("forced LC_ALL|LANG|NO_COLOR = %q, want \"C|C|1\"", got)
	}
}

// AC-3: a consumer cannot override the forced deterministic env via
// Command.Env — the reserved names are rejected before the command runs.
func TestRunner_RejectsReservedEnv(t *testing.T) {
	for _, e := range []string{"LANG=ja_JP.UTF-8", "LC_ALL=ja_JP.UTF-8", "LC_NUMERIC=de_DE.UTF-8", "LANGUAGE=ja", "NO_COLOR=", "lang=ja_JP.UTF-8", "lc_all=tr_TR.UTF-8"} {
		_, err := directRunner(t).Run(context.Background(), Command{Name: "true", Env: []string{e}})
		if !errors.Is(err, ErrReservedEnvVar) {
			t.Errorf("Run with Env %q err = %v, want ErrReservedEnvVar", e, err)
		}
	}
}

// ChildPath sets an explicit, isolating child PATH (the per-user fan-out
// seam): the curated PATH is authoritative and replaces the baseline.
func TestRunner_ChildPathIsAuthoritative(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", `printf %s "$PATH"`},
		ChildPath: "/curated/bin:/curated/sbin",
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if strings.TrimSpace(res.Stdout) != "/curated/bin:/curated/sbin" {
		t.Errorf("child PATH = %q, want the curated path", res.Stdout)
	}
}

// detectEscalationDenied turns a sudo/doas -n auth refusal into ErrEscalationDenied
// (distinct from the command's own non-zero exit). Pure seam — unit-tested with
// synthetic Results so it needs no password-protected sudo.
func TestDetectEscalationDenied(t *testing.T) {
	tests := []struct {
		name    string
		backend PrivilegeBackend
		res     Result
		want    bool
	}{
		{"sudo password required", Sudo, Result{ExitCode: 1, Stderr: "sudo: a password is required"}, true},
		{"sudo terminal required", Sudo, Result{ExitCode: 1, Stderr: "sudo: a terminal is required to read the password"}, true},
		{"doas auth failure", Doas, Result{ExitCode: 1, Stderr: "doas: Authorization required"}, true},
		{"direct never denied", Direct, Result{ExitCode: 1, Stderr: "anything"}, false},
		{"clean exit not denied", Sudo, Result{ExitCode: 0}, false},
		{"genuine command failure not denied", Sudo, Result{ExitCode: 1, Stderr: "useradd: user already exists"}, false},
	}
	for _, tc := range tests {
		err := detectEscalationDenied(tc.backend, tc.res)
		if got := errors.Is(err, ErrEscalationDenied); got != tc.want {
			t.Errorf("%s: denied=%v, want %v (err=%v)", tc.name, got, tc.want, err)
		}
	}
}

// [SDK-5] / AC-6: ctx cancellation must SIGKILL a SIGTERM-ignoring child after
// a bounded grace and return promptly. Reuses the trap-ignoring harness from
// exec_kill_test.go (a bare sleep would die on the group SIGTERM and pass for
// the wrong reason).
func TestRunner_SIGKILLsChildThatIgnoresSIGTERM(t *testing.T) {
	// Mutates the package-level killGrace seam, so this test must not be made
	// parallel (no t.Parallel) — the same constraint as the sibling kill tests.
	restore := killGrace
	killGrace = 200 * time.Millisecond
	defer func() { killGrace = restore }()

	pidFile := t.TempDir() + "/pid"
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	type result struct{ err error }
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		_, err := directRunner(t).Run(ctx, Command{Name: "sh", Args: []string{"-c", sigtermIgnoringScript(pidFile)}})
		done <- result{err}
	}()

	select {
	case r := <-done:
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("Runner.Run took %v; SIGTERM-ignoring child was not SIGKILLed after grace", elapsed)
		}
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want context.DeadlineExceeded on cancel", r.err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Runner.Run pinned on a SIGTERM-ignoring child — SIGKILL escalation not wired into the Runner")
	}

	assertProcessGroupGone(t, readChildPID(t, pidFile))
}

// The 1 MiB per-stream output cap is preserved on the Runner path.
func TestRunner_OutputCapped(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "yes aaaaaaaaaaaaaaaa | head -c 2000000"},
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if len(res.Stdout) > MaxOutputBytes+len("\n[output truncated]")+64 {
		t.Errorf("Stdout len = %d, want capped near MaxOutputBytes (%d)", len(res.Stdout), MaxOutputBytes)
	}
	if !strings.Contains(res.Stdout, "[output truncated]") {
		t.Error("Stdout missing the [output truncated] marker after exceeding the cap")
	}
}

// Streaming delivers lines through the callback as they arrive. The callback
// is invoked serialized (never concurrently), so this unsynchronized append
// is also the race-detector proof of that contract.
func TestRunner_StreamDeliversLines(t *testing.T) {
	var got []string
	_, err := directRunner(t).Stream(context.Background(),
		Command{Name: "sh", Args: []string{"-c", `printf 'a\nb\nc\n'`}},
		func(s StreamType, line string, seq int64) {
			if s == StreamStdout {
				got = append(got, strings.TrimSpace(line))
			}
		})
	if err != nil {
		t.Fatalf("Stream err = %v", err)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("streamed lines = %v, want [a b c]", got)
	}
}

// Command.Dir runs the child in the requested working directory.
func TestRunner_RunInDir(t *testing.T) {
	dir := t.TempDir()
	res, err := directRunner(t).Run(context.Background(), Command{Name: "pwd", Dir: dir})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != dir {
		t.Errorf("pwd in Dir=%q = %q, want %q", dir, got, dir)
	}
}

// Stderr lines are captured and delivered through the callback (the stderr arm
// of the streaming core).
func TestRunner_StreamDeliversStderr(t *testing.T) {
	var got []string
	res, err := directRunner(t).Stream(context.Background(),
		Command{Name: "sh", Args: []string{"-c", `printf 'e1\ne2\n' >&2`}},
		func(s StreamType, line string, _ int64) {
			if s == StreamStderr {
				got = append(got, strings.TrimSpace(line))
			}
		})
	if err != nil {
		t.Fatalf("Stream err = %v", err)
	}
	if strings.Join(got, ",") != "e1,e2" {
		t.Errorf("streamed stderr = %v, want [e1 e2]", got)
	}
	if !strings.Contains(res.Stderr, "e1") {
		t.Errorf("captured Stderr = %q, want it to contain e1", res.Stderr)
	}
}

// The per-stream output cap also applies to stderr.
func TestRunner_StderrOutputCapped(t *testing.T) {
	res, err := directRunner(t).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "yes aaaaaaaaaaaaaaaa | head -c 2000000 1>&2"},
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if !strings.Contains(res.Stderr, "[output truncated]") {
		t.Error("Stderr missing the [output truncated] marker after exceeding the cap")
	}
}

// A panicking OutputCallback is a caller bug, but it must not take down the
// whole process from an SDK-internal goroutine: delivery stops, the child is
// still reaped, and the panic surfaces as the returned error.
func TestRunner_CallbackPanicContainedAndSurfaced(t *testing.T) {
	res, err := directRunner(t).Stream(context.Background(),
		Command{Name: "sh", Args: []string{"-c", `printf 'a\nb\n'`}},
		func(StreamType, string, int64) { panic("callback bug") })
	if err == nil || !strings.Contains(err.Error(), "callback panicked") {
		t.Fatalf("err = %v, want the callback panic contained and surfaced as an error", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 (the child itself completed cleanly)", res.ExitCode)
	}
}

// A final line without a trailing newline is still delivered — newline-
// terminated, matching what exectest.FakeRunner's replay documents.
func TestRunner_UnterminatedFinalLineDelivered(t *testing.T) {
	var got []string
	res, err := directRunner(t).Stream(context.Background(),
		Command{Name: "sh", Args: []string{"-c", `printf 'a\nb'`}},
		func(s StreamType, line string, _ int64) {
			if s == StreamStdout {
				got = append(got, line)
			}
		})
	if err != nil {
		t.Fatalf("Stream err = %v", err)
	}
	if strings.Join(got, "") != "a\nb\n" {
		t.Errorf("streamed = %q, want %q (unterminated final line newline-terminated)", strings.Join(got, ""), "a\nb\n")
	}
	if !strings.Contains(res.Stdout, "b") {
		t.Errorf("captured Stdout = %q, want the final unterminated line captured", res.Stdout)
	}
}
