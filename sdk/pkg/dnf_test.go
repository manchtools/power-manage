package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

func dnfM(t *testing.T) (Manager, *exectest.FakeRunner) {
	t.Helper()
	return mustNew(t, Dnf)
}

func TestDnf_Version(t *testing.T) {
	t.Run("first line", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "4.18.2\n Installed: dnf-4.18.2\n")
		v, err := m.Version(context.Background())
		if err != nil || v != "4.18.2" {
			t.Fatalf("v=%q err=%v", v, err)
		}
		if c := f.Calls()[0]; argv(c) != "dnf --version" || c.Escalate {
			t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Version(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestDnf_Install(t *testing.T) {
	ctx := context.Background()
	t.Run("multiple latest", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{}, "vim", "git"); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "dnf install -y vim git" || !c.Escalate {
			t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
		}
	})
	t.Run("pinned version uses name-version", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{Version: "8.2.3"}, "vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "vim-8.2.3") {
			t.Errorf("argv=%q want name-version", a)
		}
	})
	t.Run("downgrade retries via explicit downgrade", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "newer already installed"}, nil) // install fails
		ok(f, "")                                                                  // downgrade succeeds
		if _, err := m.Install(ctx, InstallOptions{Version: "1.0", AllowDowngrade: true}, "vim"); err != nil {
			t.Fatalf("downgrade retry should succeed, got %v", err)
		}
		calls := f.Calls()
		if len(calls) != 2 {
			t.Fatalf("want install then downgrade, got %d calls", len(calls))
		}
		if a := argv(calls[0]); !strings.Contains(a, "--allowerasing") {
			t.Errorf("first call argv=%q, want --allowerasing", a)
		}
		if a := argv(calls[1]); a != "dnf downgrade -y vim-1.0" {
			t.Errorf("retry argv=%q", a)
		}
	})
	t.Run("downgrade NOT retried after a runner/exec failure", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied) // install fails to even run
		_, err := m.Install(ctx, InstallOptions{Version: "1.0", AllowDowngrade: true}, "vim")
		if !errors.Is(err, pmexec.ErrEscalationDenied) {
			t.Fatalf("err=%v, want the original escalation error", err)
		}
		if len(f.Calls()) != 1 {
			t.Errorf("a non-exit failure must not trigger a second (downgrade) command, ran %d", len(f.Calls()))
		}
	})
	t.Run("install failure without downgrade is returned", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "no package"}, nil)
		_, err := m.Install(ctx, InstallOptions{}, "ghost")
		var ce *pmexec.CommandError
		if !errors.As(err, &ce) || ce.ExitCode != 1 {
			t.Fatalf("err=%v want CommandError", err)
		}
		if len(f.Calls()) != 1 {
			t.Error("must not retry without AllowDowngrade")
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Install(ctx, InstallOptions{}); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Install(ctx, InstallOptions{}, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
	t.Run("bad version", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Install(ctx, InstallOptions{Version: "1;0"}, "vim"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want version rejection, no exec")
		}
	})
	t.Run("version with multiple packages rejected", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Install(ctx, InstallOptions{Version: "1.0"}, "vim", "git"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want one-package rejection")
		}
	})
}

func TestDnf_Remove(t *testing.T) {
	ctx := context.Background()
	t.Run("remove (purge ignored)", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "")
		if _, err := m.Remove(ctx, RemoveOptions{Purge: true}, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "dnf remove -y vim" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Remove(ctx, RemoveOptions{}); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Remove(ctx, RemoveOptions{}, "--x"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestDnf_Update(t *testing.T) {
	ctx := context.Background()
	t.Run("exit 0 is success", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)
		if _, err := m.Update(ctx); err != nil {
			t.Fatal(err)
		}
		if c := f.Calls()[0]; argv(c) != "dnf check-update" || !c.Escalate {
			t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
		}
	})
	t.Run("exit 100 (updates available) is success", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 100}, nil)
		if _, err := m.Update(ctx); err != nil {
			t.Fatalf("exit 100 must be success, got %v", err)
		}
	})
	t.Run("other non-zero is an error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 5, Stderr: "metadata error"}, nil)
		var ce *pmexec.CommandError
		if _, err := m.Update(ctx); !errors.As(err, &ce) || ce.ExitCode != 5 {
			t.Fatalf("err=%v want CommandError(5)", err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Update(ctx); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestDnf_Upgrade(t *testing.T) {
	ctx := context.Background()
	t.Run("UpgradeAll", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "")
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{}); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "dnf upgrade -y" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("empty Upgrade is a no-op", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Upgrade(ctx); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 0 {
			t.Errorf("empty Upgrade ran %d commands, want 0", len(f.Calls()))
		}
	})
	t.Run("specific", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "")
		if _, err := m.Upgrade(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "dnf upgrade -y vim" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Upgrade(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestDnf_PinUnpin(t *testing.T) {
	ctx := context.Background()
	t.Run("pin reports absent plugin without mutating", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil) // versionlock --help: plugin absent
		if _, err := m.Pin(ctx, "vim"); !errors.Is(err, pmexec.ErrBackendUnavailable) {
			t.Fatalf("err = %v, want ErrBackendUnavailable", err)
		}
		calls := f.Calls()
		if len(calls) != 1 || argv(calls[0]) != "dnf versionlock --help" {
			t.Fatalf("calls = %+v, want only the capability probe", calls)
		}
	})
	t.Run("pin with plugin present skips install", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil) // versionlock --help ok
		ok(f, "")                               // versionlock add
		if _, err := m.Pin(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 2 {
			t.Fatalf("want help+add, got %d", len(f.Calls()))
		}
	})
	t.Run("unpin", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil) // help ok
		ok(f, "")                               // versionlock delete
		if _, err := m.Unpin(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[1]) != "dnf versionlock delete vim" {
			t.Errorf("argv=%q", argv(f.Calls()[1]))
		}
	})
	t.Run("plugin install failure is surfaced", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)                      // help: absent
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "no plugin"}, nil) // install fails
		if _, err := m.Pin(ctx, "vim"); err == nil {
			t.Fatal("want plugin-install failure")
		}
	})
	t.Run("probe runner failure does not trigger a plugin install", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied) // versionlock --help can't run
		if _, err := m.Pin(ctx, "vim"); !errors.Is(err, pmexec.ErrEscalationDenied) {
			t.Fatalf("err=%v, want the probe's runner error", err)
		}
		if len(f.Calls()) != 1 {
			t.Errorf("a probe runner failure must not escalate into a plugin install, ran %d", len(f.Calls()))
		}
	})
	t.Run("unpin surfaces plugin install failure", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)                      // help: absent
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "no plugin"}, nil) // install fails
		if _, err := m.Unpin(ctx, "vim"); err == nil {
			t.Fatal("want plugin-install failure")
		}
	})
	t.Run("pin empty no-op", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Pin(ctx); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("unpin empty no-op", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Unpin(ctx); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("pin bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Pin(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("unpin bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Unpin(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestDnf_Autoremove(t *testing.T) {
	m, f := dnfM(t)
	ok(f, "")
	if _, err := m.Autoremove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := f.Calls()[0]; argv(c) != "dnf autoremove -y" || !c.Escalate {
		t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
	}
}

func TestDnf_Search(t *testing.T) {
	ctx := context.Background()
	t.Run("parses 'name.arch : summary'", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "================ Name Matched ================\nvim.x86_64 : Vi IMproved\n\nnope\n")
		res, err := m.Search(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Name != "vim" || res[0].Description != "Vi IMproved" {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("exit 1 means no matches", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		res, err := m.Search(ctx, "ghost")
		if err != nil || res == nil || len(res) != 0 {
			t.Fatalf("res=%v err=%v", res, err)
		}
	})
	t.Run("other non-zero is an error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 2, Stderr: "broken repo"}, nil)
		if _, err := m.Search(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Search(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestDnf_List(t *testing.T) {
	t.Run("parses rpm query", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "vim\t8.2-1\tx86_64\t3000\tVi IMproved\nshort\tline\n")
		ok(f, "vim-8.2-1.x86_64\n") // getPinnedSet (versionlock list)
		pkgs, err := m.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "vim" || pkgs[0].Size != 3000 || !pkgs[0].Pinned {
			t.Fatalf("pkgs=%+v", pkgs)
		}
	})
	t.Run("pin-set failure tolerated", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "vim\t8.2-1\tx86_64\t3000\tVi IMproved\n")
		f.Push(pmexec.Result{ExitCode: 1}, nil) // versionlock list fails -> nil set
		pkgs, err := m.List(context.Background())
		if err != nil || len(pkgs) != 1 || pkgs[0].Pinned {
			t.Fatalf("pkgs=%+v err=%v", pkgs, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestDnf_ListUpgradable(t *testing.T) {
	ctx := context.Background()
	t.Run("exit 100 then parses rows", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 100, Stdout: "vim.x86_64 8.2-2 updates\n\nshort line\n"}, nil)
		ok(f, "8.2-1\n") // InstalledVersion(vim)
		ups, err := m.ListUpgradable(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(ups) != 1 || ups[0].Name != "vim" || ups[0].Architecture != "x86_64" || ups[0].NewVersion != "8.2-2" || ups[0].CurrentVersion != "8.2-1" {
			t.Fatalf("ups=%+v", ups)
		}
	})
	t.Run("other non-zero is an error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "x"}, nil)
		if _, err := m.ListUpgradable(ctx); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListUpgradable(ctx); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestDnf_Show(t *testing.T) {
	ctx := context.Background()
	t.Run("installed and pinned", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "Version      : 8.2\nRelease      : 1.fc39\nArchitecture : x86_64\nSize         : 3.0 M\nSummary      : Vi IMproved\nRepository   : updates\n")
		f.Push(pmexec.Result{ExitCode: 0}, nil) // IsInstalled rpm -q
		ok(f, "vim-8.2-1\n")                    // IsPinned versionlock list
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "installed" || p.Version != "8.2-1.fc39" || p.Architecture != "x86_64" || p.Size != 3*1024*1024 || !p.Pinned {
			t.Fatalf("p=%+v", p)
		}
	})
	t.Run("available not installed, versionlock plugin absent tolerated", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "Version : 8.2\n")
		f.Push(pmexec.Result{ExitCode: 1}, nil) // rpm -q: not installed
		f.Push(pmexec.Result{ExitCode: 1}, nil) // versionlock list: plugin absent -> not pinned
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "available" || p.Pinned {
			t.Fatalf("p=%+v", p)
		}
	})
	t.Run("pin-check runner failure propagates", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "Version : 8.2\n")
		f.Push(pmexec.Result{ExitCode: 0}, nil)            // installed
		f.Push(pmexec.Result{}, errors.New("versionlock")) // IsPinned runner failure
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("a runner failure in the pin check must propagate")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.Show(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestDnf_ListVersions(t *testing.T) {
	ctx := context.Background()
	t.Run("dedups and skips headers", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "Installed Packages\nvim.x86_64 8.2-1 @updates\nAvailable Packages\nvim.x86_64 8.2-2 updates\nvim.x86_64 8.2-2 updates\nshort line\n")
		ok(f, "8.2-1\n") // InstalledVersion
		info, err := m.ListVersions(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if info.Installed != "8.2-1" || len(info.Versions) != 2 {
			t.Fatalf("info=%+v", info)
		}
	})
	t.Run("installed-version runner failure propagates", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "vim.x86_64 8.2-2 updates\n")
		f.Push(pmexec.Result{}, errors.New("rpm"))
		if _, err := m.ListVersions(ctx, "vim"); err == nil {
			t.Fatal("a runner failure in the installed-version lookup must propagate")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListVersions(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.ListVersions(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestDnf_IsInstalled(t *testing.T) {
	ctx := context.Background()
	t.Run("installed", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)
		if got, err := m.IsInstalled(ctx, "vim"); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("not installed", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if got, err := m.IsInstalled(ctx, "ghost"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.IsInstalled(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.IsInstalled(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestDnf_InstalledVersion(t *testing.T) {
	ctx := context.Background()
	t.Run("installed", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0, Stdout: "8.2-1\n"}, nil)
		if v, err := m.InstalledVersion(ctx, "vim"); err != nil || v != "8.2-1" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("not installed -> empty", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if v, err := m.InstalledVersion(ctx, "ghost"); err != nil || v != "" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledVersion(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.InstalledVersion(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestDnf_InstalledCount(t *testing.T) {
	t.Run("counts", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, ".\n.\n")
		if n, err := m.InstalledCount(context.Background()); err != nil || n != 2 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledCount(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestDnf_HasUpdates(t *testing.T) {
	ctx := context.Background()
	t.Run("exit 100 means updates", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 100}, nil)
		if got, err := m.HasUpdates(ctx, false); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exit 0 means none", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)
		if got, err := m.HasUpdates(ctx, false); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("unexpected exit code surfaces as an error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "metadata problem"}, nil)
		if _, err := m.HasUpdates(ctx, false); err == nil {
			t.Fatal("a non-0/100 check-update exit must be surfaced, not reported as 'no updates'")
		}
	})
	t.Run("security flag added", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 100}, nil)
		if _, err := m.HasUpdates(ctx, true); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "--security") {
			t.Errorf("argv=%q want --security", a)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.HasUpdates(ctx, false); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestDnf_IsPinned(t *testing.T) {
	ctx := context.Background()
	t.Run("locked", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "vim-8.2-1.x86_64\ngit-2.39-1.x86_64\n")
		if got, err := m.IsPinned(ctx, "vim"); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("not locked", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "git-2.39-1.x86_64\n")
		if got, err := m.IsPinned(ctx, "vim"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("plugin absent is tolerated (false)", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if got, err := m.IsPinned(ctx, "vim"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := dnfM(t)
		if _, err := m.IsPinned(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestDnf_ListPinned(t *testing.T) {
	t.Run("lists locked with versions", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil) // ensureVersionLock: help ok
		ok(f, "vim-8.2-1.x86_64\n\n")           // versionlock list
		ok(f, "8.2-1\n")                        // InstalledVersion(vim)
		pkgs, err := m.ListPinned(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "vim" || pkgs[0].Version != "8.2-1" || !pkgs[0].Pinned {
			t.Fatalf("pkgs=%+v", pkgs)
		}
	})
	t.Run("plugin install failure surfaced", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)               // help absent
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "no"}, nil) // install fails
		if _, err := m.ListPinned(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("versionlock list error", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)     // help ok
		f.Push(pmexec.Result{}, errors.New("boom")) // list errors
		if _, err := m.ListPinned(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestDnf_NEVRAParsing(t *testing.T) {
	cases := map[string]string{
		"vim-8.2-1.x86_64":      "vim",
		"glibc-langpack-en-2.3": "glibc-langpack-en",
		"noversion":             "noversion",
		"2048-cli-0.9":          "2048-cli",
	}
	for in, want := range cases {
		if got := parseNEVRAName(in); got != want {
			t.Errorf("parseNEVRAName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDnf_ParseValue(t *testing.T) {
	if v := parseColonValue("Version      : 8.2"); v != "8.2" {
		t.Errorf("parseColonValue keyed line = %q, want 8.2", v)
	}
	if v := parseColonValue("a line with no colon"); v != "" {
		t.Errorf("parseColonValue no-colon = %q, want empty", v)
	}
}

func TestDnf_ParseSize(t *testing.T) {
	cases := map[string]int64{
		"3.0 M": 3 * 1024 * 1024,
		"512 k": 512 * 1024,
		"2 G":   2 * 1024 * 1024 * 1024,
		"100":   100,
	}
	for in, want := range cases {
		got, err := parseSize(in)
		if err != nil {
			t.Fatalf("parseSize(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parseSize(%q) = %d, want %d", in, got, want)
		}
	}
	if _, err := parseSize("bad MB"); !errors.Is(err, ErrMalformedOutput) {
		t.Errorf("parseSize(malformed) error = %v, want ErrMalformedOutput", err)
	}
}

func TestDnf_EnrichmentRunnerFailuresPropagate(t *testing.T) {
	ctx := context.Background()
	t.Run("List: getPinnedSet runner failure", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "vim\t8.2-1\tx86_64\t3000\tVi IMproved\n")   // rpm -qa
		f.Push(pmexec.Result{}, errors.New("versionlock")) // getPinnedSet probe
		if _, err := m.List(ctx); err == nil {
			t.Fatal("a getPinnedSet runner failure must propagate")
		}
	})
	t.Run("ListUpgradable: InstalledVersion runner failure", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 100, Stdout: "vim.x86_64 8.2-2 updates\n"}, nil) // check-update
		f.Push(pmexec.Result{}, errors.New("rpm"))                                      // InstalledVersion
		if _, err := m.ListUpgradable(ctx); err == nil {
			t.Fatal("an InstalledVersion runner failure must propagate")
		}
	})
	t.Run("Show: IsInstalled runner failure", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "Version : 8.2\n")                   // dnf info
		f.Push(pmexec.Result{}, errors.New("rpm")) // IsInstalled
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("an IsInstalled runner failure must propagate")
		}
	})
	t.Run("ListPinned: InstalledVersion runner failure", func(t *testing.T) {
		m, f := dnfM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)    // ensureVersionLock help
		ok(f, "vim-8.2-1.x86_64\n")                // versionlock list
		f.Push(pmexec.Result{}, errors.New("rpm")) // InstalledVersion
		if _, err := m.ListPinned(ctx); err == nil {
			t.Fatal("an InstalledVersion runner failure must propagate")
		}
	})
}
