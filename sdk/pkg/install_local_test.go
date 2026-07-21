package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/validate"
)

// TestInstallLocal_GoldenArgv pins the per-backend command for installing a
// package from a local file already on disk (a downloaded .deb/.rpm/pacman
// package/flatpak bundle) — the capability the agent's deb/rpm/AppImage actions
// need so they can delegate `dpkg -i`/`rpm -i` to the SDK instead of shelling
// out. Each backend resolves dependencies from the configured repos where it
// can and runs escalated (except user-scope flatpak); the absolute-path
// requirement (not a "--" separator, which dnf5 rejects) keeps the path from
// being parsed as an option.
func TestInstallLocal_GoldenArgv(t *testing.T) {
	ctx := context.Background()

	t.Run("apt resolves deps while installing the file", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Setting up app ...\n")
		if _, err := m.InstallLocal(ctx, "/opt/app.deb", InstallLocalOptions{}); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		want := "apt install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold /opt/app.deb"
		if argv(c) != want || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)\n want %q escalated", argv(c), c.Escalate, want)
		}
	})

	t.Run("dnf installs the local rpm and pulls deps", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{}); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "dnf install -y /opt/app.rpm" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
		}
	})

	t.Run("zypper installs the local rpm", func(t *testing.T) {
		m, f := zypperM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{}); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "zypper --non-interactive install /opt/app.rpm" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
		}
	})

	t.Run("pacman -U installs the local package file", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.pkg.tar.zst", InstallLocalOptions{}); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "pacman -U --noconfirm /opt/app.pkg.tar.zst" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
		}
	})

	t.Run("flatpak installs a bundle, system scope escalated", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.flatpak", InstallLocalOptions{}); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "flatpak install -y --noninteractive --system /opt/app.flatpak" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
		}
	})

	t.Run("flatpak user scope is unescalated", func(t *testing.T) {
		m, f := flatpakM(t, WithUserScope())
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.flatpak", InstallLocalOptions{}); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "flatpak install -y --noninteractive --user /opt/app.flatpak" || c.Escalate {
			t.Errorf("argv = %q (escalate=%v), want --user unescalated", argv(c), c.Escalate)
		}
	})
}

// TestInstallLocal_AllowDowngrade pins how each backend permits installing a
// local file older than the installed version.
func TestInstallLocal_AllowDowngrade(t *testing.T) {
	ctx := context.Background()

	t.Run("apt adds --allow-downgrades", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.deb", InstallLocalOptions{AllowDowngrade: true}); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "--allow-downgrades") {
			t.Errorf("argv = %q, want --allow-downgrades", a)
		}
	})

	t.Run("zypper adds --oldpackage", func(t *testing.T) {
		m, f := zypperM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{AllowDowngrade: true}); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "--oldpackage") {
			t.Errorf("argv = %q, want --oldpackage", a)
		}
	})

	t.Run("dnf retries as an explicit downgrade when the install is rejected", func(t *testing.T) {
		m, f := dnfM(t)
		// dnf refuses to "install" an older local rpm (non-zero exit) — the
		// AllowDowngrade path must retry it as `dnf downgrade`.
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "package app-1.0 is already installed"}, nil)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{AllowDowngrade: true}); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if len(calls) != 2 {
			t.Fatalf("got %d calls, want 2 (install then downgrade)", len(calls))
		}
		if argv(calls[0]) != "dnf install -y --allowerasing /opt/app.rpm" {
			t.Errorf("first argv = %q", argv(calls[0]))
		}
		if argv(calls[1]) != "dnf downgrade -y /opt/app.rpm" || !calls[1].Escalate {
			t.Errorf("retry argv = %q (escalate=%v)", argv(calls[1]), calls[1].Escalate)
		}
	})

	t.Run("dnf does NOT retry on a runner/exec failure", func(t *testing.T) {
		m, f := dnfM(t)
		// An exec/escalation failure (err != nil, not a non-zero exit) must not
		// trigger a second escalated command — mirrors Install's guard.
		f.Push(pmexec.Result{}, pmexec.ErrEscalationUnavailable)
		_, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{AllowDowngrade: true})
		if !errors.Is(err, pmexec.ErrEscalationUnavailable) {
			t.Fatalf("err = %v, want ErrEscalationUnavailable", err)
		}
		if n := len(f.Calls()); n != 1 {
			t.Errorf("got %d calls, want 1 (no downgrade retry after an exec failure)", n)
		}
	})

	t.Run("pacman -U downgrades natively, no extra flag", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.pkg.tar.zst", InstallLocalOptions{AllowDowngrade: true}); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); a != "pacman -U --noconfirm /opt/app.pkg.tar.zst" {
			t.Errorf("argv = %q, want the plain -U form", a)
		}
	})

	t.Run("flatpak ignores AllowDowngrade", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.flatpak", InstallLocalOptions{AllowDowngrade: true}); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); a != "flatpak install -y --noninteractive --system /opt/app.flatpak" {
			t.Errorf("argv = %q, want the unchanged bundle-install form", a)
		}
	})
}

// TestInstallLocal_AllowUnsigned pins the opt-in GPG-skip knob. The agent
// establishes a local artifact's authenticity out of band (HTTPS + a mandatory
// SHA256 checksum), so the file is typically unsigned and dnf/zypper would
// refuse it; AllowUnsigned says "the checksum is the verification, skip the GPG
// check". It is secure-default-OFF — when false every backend's GPG check stays
// in force.
func TestInstallLocal_AllowUnsigned(t *testing.T) {
	ctx := context.Background()

	t.Run("dnf adds --nogpgcheck", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{AllowUnsigned: true}); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); a != "dnf install -y --nogpgcheck /opt/app.rpm" {
			t.Errorf("argv = %q, want --nogpgcheck", a)
		}
	})

	t.Run("zypper adds --allow-unsigned-rpm (per-package, not global)", func(t *testing.T) {
		m, f := zypperM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{AllowUnsigned: true}); err != nil {
			t.Fatal(err)
		}
		a := argv(f.Calls()[0])
		if a != "zypper --non-interactive install --allow-unsigned-rpm /opt/app.rpm" {
			t.Errorf("argv = %q, want --allow-unsigned-rpm", a)
		}
		if strings.Contains(a, "--no-gpg-checks") {
			t.Error("must use per-package --allow-unsigned-rpm, never the global --no-gpg-checks")
		}
	})

	t.Run("dnf carries --nogpgcheck into the downgrade retry too", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "package app-1.0 is already installed"}, nil)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{AllowUnsigned: true, AllowDowngrade: true}); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if len(calls) != 2 {
			t.Fatalf("got %d calls, want 2", len(calls))
		}
		if argv(calls[0]) != "dnf install -y --nogpgcheck --allowerasing /opt/app.rpm" {
			t.Errorf("install argv = %q", argv(calls[0]))
		}
		if argv(calls[1]) != "dnf downgrade -y --nogpgcheck /opt/app.rpm" {
			t.Errorf("downgrade retry argv = %q, want --nogpgcheck carried through", argv(calls[1]))
		}
	})

	t.Run("apt is a no-op (a local .deb has no per-file signature)", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.deb", InstallLocalOptions{AllowUnsigned: true}); err != nil {
			t.Fatal(err)
		}
		want := "apt install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold /opt/app.deb"
		if a := argv(f.Calls()[0]); a != want {
			t.Errorf("argv = %q, want the UNCHANGED apt form (no GPG flag)", a)
		}
	})

	t.Run("pacman is unaffected (pacman -U enforces SigLevel; no per-invocation bypass)", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.pkg.tar.zst", InstallLocalOptions{AllowUnsigned: true}); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); a != "pacman -U --noconfirm /opt/app.pkg.tar.zst" {
			t.Errorf("argv = %q, want the unchanged -U form", a)
		}
	})

	t.Run("flatpak is a no-op", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.InstallLocal(ctx, "/opt/app.flatpak", InstallLocalOptions{AllowUnsigned: true}); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); a != "flatpak install -y --noninteractive --system /opt/app.flatpak" {
			t.Errorf("argv = %q, want the unchanged bundle-install form", a)
		}
	})

	t.Run("default OFF keeps every backend's GPG check (no skip flag)", func(t *testing.T) {
		for _, tc := range []struct {
			b    Backend
			path string
			skip string
		}{
			{Dnf, "/opt/app.rpm", "--nogpgcheck"},
			{Zypper, "/opt/app.rpm", "--allow-unsigned-rpm"},
		} {
			m, f := mustNew(t, tc.b)
			ok(f, "")
			if _, err := m.InstallLocal(ctx, tc.path, InstallLocalOptions{}); err != nil {
				t.Fatal(err)
			}
			if a := argv(f.Calls()[0]); strings.Contains(a, tc.skip) {
				t.Errorf("%s: default argv %q must NOT contain %q", tc.b, a, tc.skip)
			}
		}
	})
}

// TestInstallLocal_RejectsUnsafePathBeforeRunner is the rejection half of the
// contract: an absent, relative, traversing, flag-shaped, or control-bearing
// path is refused BEFORE any escalated command runs, on every backend.
func TestInstallLocal_RejectsUnsafePathBeforeRunner(t *testing.T) {
	ctx := context.Background()
	bad := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"relative", "app.deb"},
		{"relative dotslash", "./app.deb"},
		{"flag-shaped", "-rf.deb"},
		{"traversal", "/opt/../etc/cron.d/x.deb"},
		{"newline", "/opt/a\nb.deb"},
		{"nul", "/opt/a\x00b.deb"},
	}
	backends := allBackends

	for _, b := range backends {
		for _, tc := range bad {
			t.Run(b.String()+"/"+tc.name, func(t *testing.T) {
				m, f := mustNew(t, b)
				if _, err := m.InstallLocal(ctx, tc.path, InstallLocalOptions{}); err == nil {
					t.Errorf("InstallLocal(%q) on %s = nil error, want a validation error", tc.path, b)
				}
				if n := len(f.Calls()); n != 0 {
					t.Errorf("InstallLocal(%q) on %s ran %d command(s) before validation; want 0", tc.path, b, n)
				}
			})
		}
	}
}

// TestInstallLocal_SurfacesResultAndError pins that, like the other mutations,
// InstallLocal returns the package manager's output on success and the output +
// a typed *exec.CommandError on a non-zero exit.
func TestInstallLocal_SurfacesResultAndError(t *testing.T) {
	ctx := context.Background()

	t.Run("success surfaces stdout", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{Stdout: "Installed: app-2.0\n"}, nil)
		res, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Stdout != "Installed: app-2.0\n" {
			t.Errorf("Stdout = %q", res.Stdout)
		}
	})

	t.Run("non-zero exit surfaces CommandError with the Result", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{Stdout: "out\n", Stderr: "Error: nothing provides libfoo\n", ExitCode: 1}, nil)
		res, err := m.InstallLocal(ctx, "/opt/app.rpm", InstallLocalOptions{})
		var ce *pmexec.CommandError
		if !errors.As(err, &ce) || ce.ExitCode != 1 {
			t.Fatalf("err = %v, want *exec.CommandError exit 1", err)
		}
		if res.ExitCode != 1 || res.Stderr != "Error: nothing provides libfoo\n" {
			t.Errorf("Result = %+v, want stderr+exit preserved", res)
		}
	})
}

// TestValidateLocalPackagePath covers the path validator directly: an absolute,
// traversal-free, control-free path is accepted; everything else is rejected.
func TestValidateLocalPackagePath(t *testing.T) {
	good := []string{
		"/opt/app.deb",
		"/var/cache/pm/app.rpm",
		"/opt/My Apps/app.flatpak", // a space is argv-safe; not rejected
		"/tmp/123.pkg.tar.zst",
	}
	for _, p := range good {
		if err := validate.LocalPackagePath(p); err != nil {
			t.Errorf("ValidateLocalPackagePath(%q) = %v, want nil", p, err)
		}
	}
	bad := []string{
		"",              // empty
		"app.deb",       // relative
		"./app.deb",     // relative
		"-rf",           // flag-shaped (not absolute)
		"/opt/../etc/x", // traversal
		"/opt/a\nb",     // newline
		"/opt/a\tb",     // tab
		"/opt/a\x00b",   // NUL
		"/opt/a\x7fb",   // DEL
	}
	for _, p := range bad {
		if err := validate.LocalPackagePath(p); err == nil {
			t.Errorf("ValidateLocalPackagePath(%q) = nil, want an error", p)
		}
	}
}
