package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

// --- shared test harness ---------------------------------------------------

// newFake returns a FakeRunner reporting the Direct backend. Escalate is still
// recorded on each Command, so escalation assertions work regardless.
func newFake() *exectest.FakeRunner { return exectest.New(pmexec.Direct) }

// argv renders a recorded Command as "name arg1 arg2 …" for substring asserts.
func argv(c pmexec.Command) string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

// mustNew builds a Manager over a fresh FakeRunner and fails the test on error.
func mustNew(t *testing.T, b Backend, opts ...Option) (Manager, *exectest.FakeRunner) {
	t.Helper()
	f := newFake()
	m, err := New(b, f, opts...)
	if err != nil {
		t.Fatalf("New(%v): %v", b, err)
	}
	return m, f
}

// ok scripts the next runner call as a clean success with the given stdout.
func ok(f *exectest.FakeRunner, stdout string) { f.Push(pmexec.Result{Stdout: stdout}, nil) }

// TestMutationsReturnCommandOutput pins the contract that a Manager mutation
// returns the package manager's command output (exec.Result), not just an error
// — operators need to see what an install/remove/update actually did. On a clean
// exit the Result carries stdout; on a non-zero exit it carries stdout + stderr
// + exit code AND a typed *exec.CommandError. Driven by the agent migration:
// the agent maps this Result into the pb.CommandOutput it returns to control.
func TestMutationsReturnCommandOutput(t *testing.T) {
	ctx := context.Background()

	t.Run("install surfaces stdout on success", func(t *testing.T) {
		m, f := mustNew(t, Apt)
		f.Push(pmexec.Result{Stdout: "Setting up vim ...\n", ExitCode: 0}, nil)
		res, err := m.Install(ctx, InstallOptions{}, "vim")
		if err != nil {
			t.Fatalf("Install err = %v", err)
		}
		if res.Stdout != "Setting up vim ...\n" {
			t.Errorf("Result.Stdout = %q, want the command stdout", res.Stdout)
		}
		if res.ExitCode != 0 {
			t.Errorf("Result.ExitCode = %d, want 0", res.ExitCode)
		}
	})

	t.Run("install surfaces stdout+stderr+exit AND CommandError on failure", func(t *testing.T) {
		m, f := mustNew(t, Apt)
		f.Push(pmexec.Result{
			Stdout:   "Reading package lists...\n",
			Stderr:   "E: Unable to locate package vim\n",
			ExitCode: 100,
		}, nil)
		res, err := m.Install(ctx, InstallOptions{}, "vim")
		if err == nil {
			t.Fatal("Install err = nil, want a non-zero-exit error")
		}
		var ce *pmexec.CommandError
		if !errors.As(err, &ce) {
			t.Fatalf("err = %v, want *exec.CommandError", err)
		}
		if res.ExitCode != 100 || res.Stdout != "Reading package lists...\n" || res.Stderr != "E: Unable to locate package vim\n" {
			t.Errorf("Result = %+v, want stdout+stderr+exit preserved", res)
		}
	})
}

// --- New -------------------------------------------------------------------

func TestNew_AllBackends(t *testing.T) {
	for _, b := range allBackends {
		m, err := New(b, newFake())
		if err != nil {
			t.Fatalf("New(%v) unexpected error: %v", b, err)
		}
		if m.Backend() != b {
			t.Errorf("New(%v).Backend() = %v, want %v", b, m.Backend(), b)
		}
	}
}

func TestNew_RejectsUnknownBackend(t *testing.T) {
	for _, b := range []Backend{0, Backend(99), Backend(-1)} {
		if _, err := New(b, newFake()); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) error = %v, want ErrUnknownBackend", int(b), err)
		}
	}
}

func TestNew_RejectsNilRunner(t *testing.T) {
	_, err := New(Apt, nil)
	if !errors.Is(err, pmexec.ErrRunnerRequired) {
		t.Errorf("New(Apt, nil) error = %v, want ErrRunnerRequired", err)
	}
}

func TestNew_RejectsTypedNilRunner(t *testing.T) {
	var runner *exectest.FakeRunner
	_, err := New(Apt, runner)
	if !errors.Is(err, pmexec.ErrRunnerRequired) {
		t.Errorf("New(Apt, typed nil) error = %v, want ErrRunnerRequired", err)
	}
}

func TestNew_FlatpakIsFlatpakManager(t *testing.T) {
	m, err := New(Flatpak, newFake())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.(FlatpakManager); !ok {
		t.Fatalf("New(Flatpak) is %T, want a FlatpakManager", m)
	}
}

func TestNew_NativeBackendsAreNotFlatpakManager(t *testing.T) {
	for _, b := range []Backend{Apt, Dnf, Pacman, Zypper} {
		m, err := New(b, newFake())
		if err != nil {
			t.Fatalf("New(%v): %v", b, err)
		}
		if _, ok := m.(FlatpakManager); ok {
			t.Errorf("%v unexpectedly satisfies FlatpakManager", b)
		}
	}
}

// WithUserScope must flip flatpak to --user and drop escalation; the default is
// --system and escalated.
func TestNew_FlatpakScopeOption(t *testing.T) {
	t.Run("default is system + escalated", func(t *testing.T) {
		m, f := mustNew(t, Flatpak)
		ok(f, "")
		if _, err := m.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if !c.Escalate {
			t.Error("system-scope flatpak must escalate")
		}
		if !strings.Contains(argv(c), "--system") {
			t.Errorf("argv = %q, want --system", argv(c))
		}
	})
	t.Run("WithUserScope is user + unescalated", func(t *testing.T) {
		m, f := mustNew(t, Flatpak, WithUserScope())
		ok(f, "")
		if _, err := m.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if c.Escalate {
			t.Error("user-scope flatpak must NOT escalate")
		}
		if !strings.Contains(argv(c), "--user") {
			t.Errorf("argv = %q, want --user", argv(c))
		}
	})
}

// WithUserScope is documented as flatpak-only; applying it to a native backend
// must not change its (always-escalated) behaviour.
func TestNew_UserScopeIgnoredByNativeBackends(t *testing.T) {
	m, f := mustNew(t, Apt, WithUserScope())
	ok(f, "")
	if _, err := m.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := f.Calls()[0]; !c.Escalate {
		t.Error("native apt must escalate regardless of WithUserScope")
	}
}

// --- Backend.String --------------------------------------------------------

func TestBackend_String(t *testing.T) {
	cases := map[Backend]string{
		Apt:         "apt",
		Dnf:         "dnf",
		Pacman:      "pacman",
		Zypper:      "zypper",
		Flatpak:     "flatpak",
		Backend(0):  "Backend(0)",
		Backend(99): "Backend(99)",
	}
	for b, want := range cases {
		if got := b.String(); got != want {
			t.Errorf("Backend(%d).String() = %q, want %q", int(b), got, want)
		}
	}
}

// --- Detect ----------------------------------------------------------------
