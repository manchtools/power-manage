package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

// aptM builds an apt Manager over a fresh fake.
func aptM(t *testing.T) (Manager, *exectest.FakeRunner) {
	t.Helper()
	return mustNew(t, Apt)
}

func TestApt_Version(t *testing.T) {
	t.Run("parses version field", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "apt 2.7.14build2 (amd64)\n")
		v, err := m.Version(context.Background())
		if err != nil || v != "2.7.14build2" {
			t.Fatalf("v=%q err=%v", v, err)
		}
		if argv(f.Calls()[0]) != "apt --version" || f.Calls()[0].Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(f.Calls()[0]), f.Calls()[0].Escalate)
		}
	})
	t.Run("short output is malformed", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "apt\n")
		if _, err := m.Version(context.Background()); !errors.Is(err, ErrMalformedOutput) {
			t.Fatalf("err=%v, want ErrMalformedOutput", err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("not found"))
		if _, err := m.Version(context.Background()); err == nil {
			t.Fatal("want exec error")
		}
	})
}

func TestApt_Install(t *testing.T) {
	ctx := context.Background()
	t.Run("multiple packages, latest", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{}, "vim", "git"); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		want := "apt install -y --fix-broken -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold vim git"
		if argv(c) != want || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
		}
		if len(c.Env) == 0 || c.Env[0] != "DEBIAN_FRONTEND=noninteractive" {
			t.Errorf("env = %v, want DEBIAN_FRONTEND", c.Env)
		}
	})
	t.Run("pinned version", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{Version: "2:8.2.3995-1ubuntu2"}, "vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "vim=2:8.2.3995-1ubuntu2") {
			t.Errorf("argv = %q, want name=version", a)
		}
	})
	t.Run("allow downgrade", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{Version: "1.0", AllowDowngrade: true}, "vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "--allow-downgrades") {
			t.Errorf("argv = %q, want --allow-downgrades", a)
		}
	})
	t.Run("empty is a no-op", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Install(ctx, InstallOptions{}); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 0 {
			t.Error("empty install must run nothing")
		}
	})
	t.Run("bad name rejected before exec", func(t *testing.T) {
		m, f := aptM(t)
		_, err := m.Install(ctx, InstallOptions{}, "vim;rm -rf /")
		if err == nil || !strings.Contains(err.Error(), "package name") {
			t.Fatalf("err = %v, want validation rejection", err)
		}
		if len(f.Calls()) != 0 {
			t.Error("rejected name must run nothing")
		}
	})
	t.Run("bad version rejected before exec", func(t *testing.T) {
		m, f := aptM(t)
		_, err := m.Install(ctx, InstallOptions{Version: "1.0;evil"}, "vim")
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("err = %v, want version rejection", err)
		}
		if len(f.Calls()) != 0 {
			t.Error("rejected version must run nothing")
		}
	})
	t.Run("version with multiple packages rejected", func(t *testing.T) {
		m, f := aptM(t)
		_, err := m.Install(ctx, InstallOptions{Version: "1.0"}, "vim", "git")
		if err == nil || !strings.Contains(err.Error(), "exactly one package") {
			t.Fatalf("err = %v, want one-package rejection", err)
		}
		if len(f.Calls()) != 0 {
			t.Error("must run nothing")
		}
	})
	t.Run("version with zero packages rejected", func(t *testing.T) {
		m, _ := aptM(t)
		if _, err := m.Install(ctx, InstallOptions{Version: "1.0"}); err == nil {
			t.Fatal("version with no package must be rejected")
		}
	})
}

func TestApt_Remove(t *testing.T) {
	ctx := context.Background()
	t.Run("remove", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.Remove(ctx, RemoveOptions{}, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "apt remove -y vim" {
			t.Errorf("argv = %q", argv(f.Calls()[0]))
		}
	})
	t.Run("purge", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.Remove(ctx, RemoveOptions{Purge: true}, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "apt purge -y vim" {
			t.Errorf("argv = %q, want purge", argv(f.Calls()[0]))
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Remove(ctx, RemoveOptions{}); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Remove(ctx, RemoveOptions{}, "--force"); err == nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d, want rejection", err, len(f.Calls()))
		}
	})
}

func TestApt_Update(t *testing.T) {
	m, f := aptM(t)
	ok(f, "")
	if _, err := m.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := f.Calls()[0]
	if argv(c) != "apt update" || !c.Escalate {
		t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
	}
}

func TestApt_Upgrade(t *testing.T) {
	ctx := context.Background()
	t.Run("UpgradeAll -> dist-upgrade", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{}); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.HasPrefix(a, "apt dist-upgrade -y") {
			t.Errorf("argv = %q, want dist-upgrade", a)
		}
	})
	t.Run("empty Upgrade is a no-op (not a full upgrade)", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Upgrade(ctx); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 0 {
			t.Errorf("empty Upgrade ran %d commands, want 0", len(f.Calls()))
		}
	})
	t.Run("specific -> only-upgrade", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.Upgrade(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		a := argv(f.Calls()[0])
		if !strings.Contains(a, "install -y --only-upgrade") || !strings.HasSuffix(a, "vim") {
			t.Errorf("argv = %q", a)
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Upgrade(ctx, "vim|sh"); err == nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
}

func TestApt_PinUnpin(t *testing.T) {
	ctx := context.Background()
	t.Run("pin", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.Pin(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		if c := f.Calls()[0]; argv(c) != "apt-mark hold vim" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
		}
	})
	t.Run("unpin", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if _, err := m.Unpin(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "apt-mark unhold vim" {
			t.Errorf("argv = %q", argv(f.Calls()[0]))
		}
	})
	t.Run("pin empty no-op", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Pin(ctx); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("unpin empty no-op", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Unpin(ctx); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("pin bad name", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Pin(ctx, "a b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
	t.Run("unpin bad name", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Unpin(ctx, "a b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_Autoremove(t *testing.T) {
	m, f := aptM(t)
	ok(f, "")
	if _, err := m.Autoremove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := f.Calls()[0]; argv(c) != "apt autoremove -y" || !c.Escalate {
		t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
	}
}

func TestApt_WriteFailure(t *testing.T) {
	m, f := aptM(t)
	f.Push(pmexec.Result{ExitCode: 100, Stderr: "E: Unable to locate package ghost"}, nil)
	_, err := m.Install(context.Background(), InstallOptions{}, "ghost")
	var ce *pmexec.CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 100 {
		t.Fatalf("err = %v, want CommandError(exit 100)", err)
	}
	if !strings.Contains(ce.Stderr, "Unable to locate") {
		t.Errorf("stderr not preserved: %q", ce.Stderr)
	}
}

func TestApt_WriteExecError(t *testing.T) {
	m, f := aptM(t)
	f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied)
	if _, err := m.Update(context.Background()); !errors.Is(err, pmexec.ErrEscalationDenied) {
		t.Fatalf("err = %v, want ErrEscalationDenied", err)
	}
}

func TestApt_Search(t *testing.T) {
	t.Run("always uses apt-cache search (parsable single-line format)", func(t *testing.T) {
		// Even when apt is present, Search must use `apt-cache search`: `apt search`
		// emits a multi-line presentation format that would not parse on " - ".
		m, f := aptM(t)
		ok(f, "vim - Vi IMproved\nneovim - heavily refactored vim fork\nnot-a-result\n")
		res, err := m.Search(context.Background(), "vim")
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 || res[0].Name != "vim" || res[0].Description != "Vi IMproved" {
			t.Fatalf("results = %+v", res)
		}
		if a := argv(f.Calls()[0]); a != "apt-cache search vim" {
			t.Errorf("argv = %q, want apt-cache search", a)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Search(context.Background(), "vim"); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_List(t *testing.T) {
	t.Run("parses installed, applies size and pin", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\t2:8.2\tamd64\tinstall ok installed\t3000\tVi IMproved\n"+
			"halfpkg\t1.0\tamd64\tdeinstall ok config-files\t10\tleftover\n"+
			"short\tfields\n")
		ok(f, "vim\n") // getPinnedSet (apt-mark showhold)
		pkgs, err := m.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 1 {
			t.Fatalf("want only the installed package, got %+v", pkgs)
		}
		p := pkgs[0]
		if p.Name != "vim" || p.Size != 3000*1024 || p.Description != "Vi IMproved" || !p.Pinned {
			t.Errorf("package = %+v", p)
		}
	})
	t.Run("pin-set lookup runner failure propagates", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\t2:8.2\tamd64\tinstall ok installed\t3000\tVi IMproved\n")
		f.Push(pmexec.Result{}, errors.New("apt-mark missing")) // getPinnedSet runner failure
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("a runner failure in the pin-set lookup must propagate, not be swallowed")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_ListUpgradable(t *testing.T) {
	t.Run("parses upgradable rows", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Listing...\n"+
			"vim/jammy-updates 2:8.2.2 amd64 [upgradable from: 2:8.2.1]\n"+
			"garbage line without match\n")
		ups, err := m.ListUpgradable(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(ups) != 1 {
			t.Fatalf("ups = %+v", ups)
		}
		u := ups[0]
		if u.Name != "vim" || u.NewVersion != "2:8.2.2" || u.CurrentVersion != "2:8.2.1" || u.Architecture != "amd64" {
			t.Errorf("update = %+v", u)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListUpgradable(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_Show(t *testing.T) {
	ctx := context.Background()
	t.Run("installed and pinned", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Package: vim\nVersion: 2:8.2\nArchitecture: amd64\nInstalled-Size: 3000\nDescription: Vi IMproved\n")
		f.Push(pmexec.Result{ExitCode: 0}, nil) // IsInstalled: dpkg -s -> installed
		ok(f, "vim\n")                          // IsPinned: apt-mark showhold vim
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "installed" || p.Version != "2:8.2" || p.Size != 3000*1024 || !p.Pinned {
			t.Errorf("pkg = %+v", p)
		}
		if got := argv(f.Calls()[0]); got != "apt-cache show vim" {
			t.Errorf("show argv = %q, want machine-readable apt-cache output", got)
		}
	})
	t.Run("available (not installed)", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Package: vim\nVersion: 2:8.2\n")
		f.Push(pmexec.Result{ExitCode: 1}, nil) // dpkg -s -> not installed
		ok(f, "")                               // apt-mark showhold vim -> not pinned
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "available" || p.Pinned {
			t.Errorf("pkg = %+v", p)
		}
	})
	t.Run("uses only the first version stanza", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Package: vim\nVersion: 2:8.2\nArchitecture: amd64\nInstalled-Size: 3000\nDescription: candidate\n\nPackage: vim\nVersion: 2:8.1\nArchitecture: i386\nInstalled-Size: 1\nDescription: older\n")
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		ok(f, "")
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Version != "2:8.2" || p.Architecture != "amd64" || p.Size != 3000*1024 || p.Description != "candidate" {
			t.Errorf("pkg = %+v, want first stanza", p)
		}
	})
	t.Run("pin-check runner failure propagates", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Package: vim\nVersion: 2:8.2\n")
		f.Push(pmexec.Result{ExitCode: 0}, nil)             // IsInstalled -> installed
		f.Push(pmexec.Result{}, errors.New("apt-mark err")) // IsPinned runner failure
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("a runner failure in the pin check must propagate")
		}
	})
	t.Run("exec error on show", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Show(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_ListVersions(t *testing.T) {
	ctx := context.Background()
	t.Run("parses madison, dedups versions", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "  vim | 2:8.2 | http://archive jammy/main amd64\n"+
			"  vim | 2:8.2 | http://archive jammy/main i386\n"+
			"  vim | 2:8.1 | http://archive jammy/universe amd64\n"+
			"short | line\n")
		ok(f, "2:8.2\n") // InstalledVersion (dpkg-query)
		info, err := m.ListVersions(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if info.Installed != "2:8.2" || len(info.Versions) != 2 {
			t.Fatalf("info = %+v", info)
		}
	})
	t.Run("installed-version runner failure propagates", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "  vim | 2:8.2 | http://archive jammy/main amd64\n")
		f.Push(pmexec.Result{}, errors.New("dpkg-query err")) // InstalledVersion runner failure
		if _, err := m.ListVersions(ctx, "vim"); err == nil {
			t.Fatal("a runner failure in the installed-version lookup must propagate")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListVersions(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.ListVersions(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_IsInstalled(t *testing.T) {
	ctx := context.Background()
	t.Run("installed (exit 0)", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)
		got, err := m.IsInstalled(ctx, "vim")
		if err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("not installed (exit 1)", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if got, err := m.IsInstalled(ctx, "ghost"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.IsInstalled(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.IsInstalled(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_InstalledVersion(t *testing.T) {
	ctx := context.Background()
	t.Run("trims output", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "2:8.2\n")
		if v, err := m.InstalledVersion(ctx, "vim"); err != nil || v != "2:8.2" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("absent package returns empty, not error", func(t *testing.T) {
		// dpkg-query exits non-zero for an unknown package — a benign miss.
		m, f := aptM(t)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "no packages found matching ghost"}, nil)
		if v, err := m.InstalledVersion(ctx, "ghost"); err != nil || v != "" {
			t.Fatalf("v=%q err=%v, want \"\",nil for an absent package", v, err)
		}
	})
	t.Run("runner error propagates", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledVersion(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.InstalledVersion(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_InstalledCount(t *testing.T) {
	t.Run("counts lines", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, ".\n.\n.\n")
		if n, err := m.InstalledCount(context.Background()); err != nil || n != 3 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledCount(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_HasUpdates(t *testing.T) {
	t.Run("Inst lines mean updates", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Reading package lists...\nInst vim [2:8.2.1] (2:8.2.2 jammy [amd64])\nConf vim\n")
		got, err := m.HasUpdates(context.Background(), false)
		if err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("no Inst lines mean none", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Reading package lists...\nCalculating upgrade...\n")
		if got, err := m.HasUpdates(context.Background(), true); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.HasUpdates(context.Background(), false); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_IsPinned(t *testing.T) {
	ctx := context.Background()
	t.Run("held", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\n")
		if got, err := m.IsPinned(ctx, "vim"); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("not held", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "\n")
		if got, err := m.IsPinned(ctx, "vim"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.IsPinned(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.IsPinned(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_ListPinned(t *testing.T) {
	t.Run("lists held with versions", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\n\ngit\n") // showhold (blank line skipped)
		ok(f, "2:8.2\n")      // InstalledVersion vim
		ok(f, "1:2.39\n")     // InstalledVersion git
		pkgs, err := m.ListPinned(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 2 || pkgs[0].Name != "vim" || pkgs[0].Version != "2:8.2" || !pkgs[0].Pinned {
			t.Fatalf("pkgs = %+v", pkgs)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListPinned(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

// Each enrichment/secondary lookup must propagate a runner failure rather than
// swallow it (fail-closed; CodeRabbit review).
func TestApt_EnrichmentRunnerFailuresPropagate(t *testing.T) {
	ctx := context.Background()
	t.Run("Show: IsInstalled runner failure", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Package: vim\nVersion: 2:8.2\n")               // show
		f.Push(pmexec.Result{}, errors.New("dpkg -s failed")) // IsInstalled
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("an IsInstalled runner failure must propagate")
		}
	})
	t.Run("ListPinned: InstalledVersion runner failure", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\n")                                           // apt-mark showhold
		f.Push(pmexec.Result{}, errors.New("dpkg-query failed")) // InstalledVersion
		if _, err := m.ListPinned(ctx); err == nil {
			t.Fatal("an InstalledVersion runner failure must propagate")
		}
	})
}
