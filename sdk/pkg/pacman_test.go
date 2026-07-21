package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

func pacmanM(t *testing.T) (Manager, *exectest.FakeRunner) {
	t.Helper()
	return mustNew(t, Pacman)
}

const samplePacmanConf = "[options]\nHoldPkg = pacman glibc\nIgnorePkg = linux\n\n[core]\nServer = https://x\n"

func TestPacman_Version(t *testing.T) {
	t.Run("parses v-prefixed token", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, " Pacman v6.0.2 - libalpm v13.0.2\n")
		v, err := m.Version(context.Background())
		if err != nil || v != "6.0.2" {
			t.Fatalf("v=%q err=%v", v, err)
		}
		if c := f.Calls()[0]; argv(c) != "pacman --version" || c.Escalate {
			t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
		}
	})
	t.Run("no version token is malformed", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "some banner without the marker\n")
		if _, err := m.Version(context.Background()); !errors.Is(err, ErrMalformedOutput) {
			t.Fatalf("err=%v, want ErrMalformedOutput", err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Version(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestPacman_Install(t *testing.T) {
	ctx := context.Background()
	t.Run("latest with --needed", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{}, "vim", "git"); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "pacman -S --noconfirm --needed vim git" || !c.Escalate {
			t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
		}
	})
	t.Run("pinned version (no --needed)", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{Version: "9.0-1"}, "vim"); err != nil {
			t.Fatal(err)
		}
		a := argv(f.Calls()[0])
		if !strings.Contains(a, "vim=9.0-1") || strings.Contains(a, "--needed") {
			t.Errorf("argv=%q", a)
		}
	})
	t.Run("allow downgrade does not force-overwrite", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{Version: "1.0", AllowDowngrade: true}, "vim"); err != nil {
			t.Fatal(err)
		}
		a := argv(f.Calls()[0])
		if strings.Contains(a, "--overwrite") {
			t.Errorf("must not pass the data-loss-prone --overwrite: %q", a)
		}
		if !strings.Contains(a, "vim=1.0") {
			t.Errorf("argv=%q want version-pinned install", a)
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Install(ctx, InstallOptions{}); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Install(ctx, InstallOptions{}, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("bad version", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Install(ctx, InstallOptions{Version: "1;0"}, "vim"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("version with multiple packages rejected", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Install(ctx, InstallOptions{Version: "1.0"}, "vim", "git"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want one-package rejection")
		}
	})
}

func TestPacman_Remove(t *testing.T) {
	ctx := context.Background()
	t.Run("remove (-R)", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.Remove(ctx, RemoveOptions{}, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "pacman -R --noconfirm vim" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("purge (-Rns)", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.Remove(ctx, RemoveOptions{Purge: true}, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "pacman -Rns --noconfirm vim" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Remove(ctx, RemoveOptions{}); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Remove(ctx, RemoveOptions{}, "--x"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestPacman_UpdateUpgrade(t *testing.T) {
	ctx := context.Background()
	t.Run("update -Sy", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.Update(ctx); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "pacman -Sy --noconfirm" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("UpgradeAll -Syu", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{}); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "pacman -Syu --noconfirm" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("empty Upgrade is a no-op", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Upgrade(ctx); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 0 {
			t.Errorf("empty Upgrade ran %d commands, want 0", len(f.Calls()))
		}
	})
	t.Run("upgrade specific", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "")
		if _, err := m.Upgrade(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "pacman -S --noconfirm vim" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("upgrade bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Upgrade(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("write exec error surfaced", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied)
		if _, err := m.Update(ctx); !errors.Is(err, pmexec.ErrEscalationDenied) {
			t.Fatalf("err=%v want ErrEscalationDenied", err)
		}
	})
}

func TestPacman_Autoremove(t *testing.T) {
	ctx := context.Background()
	t.Run("removes orphans", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "orphan1\norphan2\n") // -Qtdq
		ok(f, "")                   // -Rns
		if _, err := m.Autoremove(ctx); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if len(calls) != 2 || argv(calls[1]) != "pacman -Rns --noconfirm orphan1 orphan2" {
			t.Fatalf("calls=%d argv=%q", len(calls), argv(calls[len(calls)-1]))
		}
	})
	t.Run("no orphans (exit 1)", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if _, err := m.Autoremove(ctx); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 1 {
			t.Error("no orphans must not run -Rns")
		}
	})
	t.Run("blank query output is a no-op", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "  \n\n") // exit 0 but only blank lines
		if _, err := m.Autoremove(ctx); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 1 {
			t.Error("blank orphan list must not run -Rns")
		}
	})
	t.Run("query failure surfaced", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 2, Stderr: "db error"}, nil)
		if _, err := m.Autoremove(ctx); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("query exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Autoremove(ctx); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestPacman_Search(t *testing.T) {
	ctx := context.Background()
	t.Run("two-line repo/name + indented desc", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "extra/vim 9.0-1\n    Vi Improved\n\ncommunity/neovim 0.9-1\n    fork\n")
		res, err := m.Search(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 || res[0].Name != "vim" || res[0].Repository != "extra" || res[0].Version != "9.0-1" || res[0].Description != "Vi Improved" {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("exit 1 means no matches", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if res, err := m.Search(ctx, "ghost"); err != nil || res == nil || len(res) != 0 {
			t.Fatalf("res=%v err=%v", res, err)
		}
	})
	t.Run("other non-zero is an error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 2, Stderr: "broken"}, nil)
		if _, err := m.Search(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Search(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestPacman_List(t *testing.T) {
	t.Run("parses -Q with pin", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "vim 9.0-1\nlinux 6.1-1\nshort\n")
		ok(f, samplePacmanConf) // getPinnedSet via cat
		pkgs, err := m.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 2 {
			t.Fatalf("pkgs=%+v", pkgs)
		}
		var linux *Package
		for i := range pkgs {
			if pkgs[i].Name == "linux" {
				linux = &pkgs[i]
			}
		}
		if linux == nil || !linux.Pinned {
			t.Errorf("linux should be pinned via IgnorePkg: %+v", pkgs)
		}
	})
	t.Run("pin-set lookup failure propagates", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "vim 9.0-1\n")
		f.Push(pmexec.Result{}, errors.New("cat failed")) // reading pacman.conf fails
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("an unreadable pacman.conf must propagate, not be swallowed")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestPacman_ListUpgradable(t *testing.T) {
	ctx := context.Background()
	t.Run("arrow and simple formats", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "vim 9.0-1 -> 9.0-2\ngit 2.39-1\n")
		ok(f, "git 2.39-1\n") // InstalledVersion(git) for the simple-format row
		ups, err := m.ListUpgradable(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(ups) != 2 {
			t.Fatalf("ups=%+v", ups)
		}
		if ups[0].Name != "vim" || ups[0].CurrentVersion != "9.0-1" || ups[0].NewVersion != "9.0-2" {
			t.Errorf("arrow row = %+v", ups[0])
		}
		if ups[1].Name != "git" || ups[1].CurrentVersion != "2.39-1" || ups[1].NewVersion != "2.39-1" {
			t.Errorf("simple row = %+v", ups[1])
		}
	})
	t.Run("exit 1 means none", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if ups, err := m.ListUpgradable(ctx); err != nil || ups == nil || len(ups) != 0 {
			t.Fatalf("ups=%v err=%v", ups, err)
		}
	})
	t.Run("other non-zero is an error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 2, Stderr: "x"}, nil)
		if _, err := m.ListUpgradable(ctx); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListUpgradable(ctx); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestPacman_Show(t *testing.T) {
	ctx := context.Background()
	installedInfo := "Name            : vim\nVersion         : 9.0-1\nDescription     : Vi Improved\nArchitecture    : x86_64\nInstalled Size  : 3.00 MiB\nRepository      : extra\n"
	t.Run("installed via -Qi, pinned", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 0, Stdout: installedInfo}, nil) // -Qi
		ok(f, "[options]\nIgnorePkg = vim\n")                          // IsPinned cat conf
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "installed" || p.Version != "9.0-1" || p.Architecture != "x86_64" || p.Size != 3*1024*1024 || p.Repository != "extra" || !p.Pinned {
			t.Fatalf("p=%+v", p)
		}
	})
	t.Run("available via -Si", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)                        // -Qi: not installed
		f.Push(pmexec.Result{ExitCode: 0, Stdout: installedInfo}, nil) // -Si
		ok(f, samplePacmanConf)                                        // IsPinned
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "available" || p.Pinned {
			t.Fatalf("p=%+v", p)
		}
	})
	t.Run("pin-check failure propagates", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 0, Stdout: installedInfo}, nil) // -Qi
		f.Push(pmexec.Result{}, errors.New("cat failed"))              // IsPinned -> readConf error
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("a pin-check failure must propagate")
		}
	})
	t.Run("-Qi exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("not installed and not in any repo -> package not found", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil) // -Qi: not installed
		f.Push(pmexec.Result{ExitCode: 1}, nil) // -Si: not in any sync repo
		if _, err := m.Show(ctx, "ghost"); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("err=%v, want a 'package not found' error", err)
		}
	})
	t.Run("-Si runner error propagates", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)           // -Qi not installed
		f.Push(pmexec.Result{}, errors.New("db corrupt")) // -Si runner failure
		if _, err := m.Show(ctx, "ghost"); err == nil {
			t.Fatal("a -Si runner failure must propagate")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Show(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestPacman_ListVersions(t *testing.T) {
	ctx := context.Background()
	t.Run("reads -Si version + repository", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "vim 9.0-1\n") // InstalledVersion
		ok(f, "Name : vim\nVersion : 9.0-2\nRepository : extra\n")
		info, err := m.ListVersions(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if info.Installed != "9.0-1" || len(info.Versions) != 1 || info.Versions[0].Version != "9.0-2" || info.Versions[0].Repository != "extra" {
			t.Fatalf("info=%+v", info)
		}
	})
	t.Run("installed-version runner failure propagates", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("pacman -Q failed")) // InstalledVersion runner failure
		if _, err := m.ListVersions(ctx, "vim"); err == nil {
			t.Fatal("a runner failure in the installed-version lookup must propagate")
		}
	})
	t.Run("not in any repo returns info without versions", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "vim 9.0-1\n")                    // InstalledVersion
		f.Push(pmexec.Result{ExitCode: 1}, nil) // -Si: not in any sync repo (benign)
		info, err := m.ListVersions(ctx, "vim")
		if err != nil || len(info.Versions) != 0 {
			t.Fatalf("info=%+v err=%v", info, err)
		}
	})
	t.Run("-Si runner failure propagates", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "vim 9.0-1\n")                      // InstalledVersion
		f.Push(pmexec.Result{}, errors.New("db")) // -Si runner failure
		if _, err := m.ListVersions(ctx, "vim"); err == nil {
			t.Fatal("a -Si runner failure must propagate")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.ListVersions(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestPacman_IsInstalledAndVersion(t *testing.T) {
	ctx := context.Background()
	t.Run("installed", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)
		if got, err := m.IsInstalled(ctx, "vim"); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("not installed", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if got, err := m.IsInstalled(ctx, "ghost"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("IsInstalled exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.IsInstalled(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("IsInstalled bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.IsInstalled(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("InstalledVersion present", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "vim 9.0-1\n")
		if v, err := m.InstalledVersion(ctx, "vim"); err != nil || v != "9.0-1" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("InstalledVersion not installed -> empty", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if v, err := m.InstalledVersion(ctx, "ghost"); err != nil || v != "" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("InstalledVersion malformed output -> error", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "onlyname\n")
		if _, err := m.InstalledVersion(ctx, "vim"); !errors.Is(err, ErrMalformedOutput) {
			t.Fatalf("err=%v, want ErrMalformedOutput", err)
		}
	})
	t.Run("InstalledVersion exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledVersion(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("InstalledVersion bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.InstalledVersion(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestPacman_InstalledCount(t *testing.T) {
	t.Run("counts", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "a\nb\nc\n")
		if n, err := m.InstalledCount(context.Background()); err != nil || n != 3 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledCount(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestPacman_HasUpdates(t *testing.T) {
	ctx := context.Background()
	t.Run("updates available", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "vim 9.0-1 -> 9.0-2\n")
		if got, err := m.HasUpdates(ctx, false); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("none (exit 1)", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if got, err := m.HasUpdates(ctx, false); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exit 0 empty means none", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "  \n")
		if got, err := m.HasUpdates(ctx, false); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("other non-zero is an error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{ExitCode: 2, Stderr: "x"}, nil)
		if _, err := m.HasUpdates(ctx, false); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.HasUpdates(ctx, false); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestPacman_Pin(t *testing.T) {
	ctx := context.Background()
	t.Run("appends to IgnorePkg via tee", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, samplePacmanConf) // readConf
		ok(f, "")               // tee
		if _, err := m.Pin(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		tee := f.Calls()[1]
		if argv(tee) != "tee /etc/pacman.conf" || !tee.Escalate || tee.Stdin == nil {
			t.Fatalf("tee call = %q escalate=%v stdin=%v", argv(tee), tee.Escalate, tee.Stdin != nil)
		}
		body := readAll(t, tee)
		if !strings.Contains(body, "IgnorePkg = linux vim") {
			t.Errorf("written conf missing merged IgnorePkg:\n%s", body)
		}
	})
	t.Run("already-pinned package is not duplicated", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, samplePacmanConf) // linux already ignored
		ok(f, "")
		if _, err := m.Pin(ctx, "linux"); err != nil {
			t.Fatal(err)
		}
		body := readAll(t, f.Calls()[1])
		if strings.Count(body, "linux") != 1 { // single IgnorePkg entry, not duplicated
			t.Errorf("linux should appear once in IgnorePkg, not duplicated:\n%s", body)
		}
	})
	t.Run("config-injection name rejected by stricter gate", func(t *testing.T) {
		m, f := pacmanM(t)
		// passes ValidatePackageName (':' allowed) but fails validPacmanPkgName
		if _, err := m.Pin(ctx, "vim:amd64"); err == nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d, want stricter-gate rejection with no exec", err, len(f.Calls()))
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Pin(ctx); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Pin(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("readConf failure surfaced", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("cat failed"))
		if _, err := m.Pin(ctx, "vim"); err == nil || !strings.Contains(err.Error(), "pacman.conf") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("tee failure surfaced", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, samplePacmanConf)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "permission denied"}, nil)
		if _, err := m.Pin(ctx, "vim"); err == nil {
			t.Fatal("want tee failure")
		}
	})
	t.Run("tee exec error surfaced", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, samplePacmanConf)
		f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied)
		if _, err := m.Pin(ctx, "vim"); !errors.Is(err, pmexec.ErrEscalationDenied) {
			t.Fatalf("err=%v want ErrEscalationDenied", err)
		}
	})
}

func TestPacman_Unpin(t *testing.T) {
	ctx := context.Background()
	t.Run("removes from IgnorePkg", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "[options]\nIgnorePkg = linux vim\n") // readConf
		ok(f, "")                                   // tee
		if _, err := m.Unpin(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		body := readAll(t, f.Calls()[1])
		if !strings.Contains(body, "IgnorePkg = linux") || strings.Contains(body, "vim") {
			t.Errorf("vim should be removed from IgnorePkg:\n%s", body)
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Unpin(ctx); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.Unpin(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("readConf failure surfaced", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("cat failed"))
		if _, err := m.Unpin(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestPacman_ListPinnedAndIsPinned(t *testing.T) {
	ctx := context.Background()
	t.Run("ListPinned with versions", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "[options]\nIgnorePkg = linux vim\n") // readConf
		ok(f, "linux 6.1-1\n")                      // InstalledVersion(linux)
		ok(f, "vim 9.0-1\n")                        // InstalledVersion(vim)
		pkgs, err := m.ListPinned(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 2 || pkgs[0].Name != "linux" || pkgs[0].Version != "6.1-1" || !pkgs[0].Pinned {
			t.Fatalf("pkgs=%+v", pkgs)
		}
	})
	t.Run("ListPinned readConf error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("cat failed"))
		if _, err := m.ListPinned(ctx); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("IsPinned true/false", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, samplePacmanConf) // linux ignored
		if got, err := m.IsPinned(ctx, "linux"); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
		ok(f, samplePacmanConf)
		if got, err := m.IsPinned(ctx, "vim"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("IsPinned readConf error", func(t *testing.T) {
		m, f := pacmanM(t)
		f.Push(pmexec.Result{}, errors.New("cat failed"))
		if _, err := m.IsPinned(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("IsPinned bad name", func(t *testing.T) {
		m, f := pacmanM(t)
		if _, err := m.IsPinned(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

// --- pure helpers ----------------------------------------------------------

func TestPacman_BuildIgnorePkgConf(t *testing.T) {
	t.Run("replaces existing IgnorePkg line", func(t *testing.T) {
		out := buildIgnorePkgConf("[options]\nIgnorePkg = old\nServer = x\n", []string{"a", "b"})
		if !strings.Contains(out, "IgnorePkg = a b") || strings.Contains(out, "old") {
			t.Errorf("conf=%q", out)
		}
	})
	t.Run("empty set drops the directive", func(t *testing.T) {
		out := buildIgnorePkgConf("[options]\nIgnorePkg = old\n", nil)
		if strings.Contains(out, "IgnorePkg") {
			t.Errorf("empty set must remove IgnorePkg, got %q", out)
		}
	})
	t.Run("inserts after [options] when absent", func(t *testing.T) {
		out := buildIgnorePkgConf("[options]\nServer = x\n[core]\n", []string{"a"})
		lines := strings.Split(out, "\n")
		if lines[0] != "[options]" || lines[1] != "IgnorePkg = a" {
			t.Errorf("IgnorePkg should follow [options]:\n%s", out)
		}
	})
	t.Run("no [options] section leaves conf unchanged", func(t *testing.T) {
		in := "Server = x\n"
		if out := buildIgnorePkgConf(in, []string{"a"}); strings.Contains(out, "IgnorePkg") {
			t.Errorf("without [options] there is nowhere to insert: %q", out)
		}
	})
	t.Run("consolidates multiple IgnorePkg lines into one", func(t *testing.T) {
		// pacman.conf may carry several IgnorePkg directives (getIgnoredPackages
		// reads them all). The rewrite must drop ALL of them and emit a single
		// consolidated line, otherwise stale entries survive an Unpin.
		in := "[options]\nIgnorePkg = a\nIgnorePkg = b\nServer = x\n"
		out := buildIgnorePkgConf(in, []string{"a", "b", "c"})
		if n := strings.Count(out, "IgnorePkg"); n != 1 {
			t.Errorf("want exactly one IgnorePkg line, got %d:\n%s", n, out)
		}
		if !strings.Contains(out, "IgnorePkg = a b c") {
			t.Errorf("want consolidated line:\n%s", out)
		}
	})
	t.Run("dropping all entries removes every IgnorePkg line", func(t *testing.T) {
		in := "[options]\nIgnorePkg = a\nIgnorePkg = b\n"
		if out := buildIgnorePkgConf(in, nil); strings.Contains(out, "IgnorePkg") {
			t.Errorf("emptying must drop every IgnorePkg line:\n%s", out)
		}
	})
}

func TestPacman_GetIgnoredPackages(t *testing.T) {
	got := getIgnoredPackages("[options]\nIgnorePkg = a b # inline comment\n#IgnorePkg = c\nIgnorePkg = d\n")
	want := []string{"a", "b", "d"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("getIgnoredPackages = %v, want %v", got, want)
	}
}

func TestPacman_PinRejectsConfigWithoutOptions(t *testing.T) {
	m, f := pacmanM(t)
	ok(f, "[core]\nServer = https://example.invalid\n")
	if _, err := m.Pin(context.Background(), "vim"); !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("Pin error = %v, want ErrMalformedOutput", err)
	}
	if len(f.Calls()) != 1 {
		t.Fatalf("Pin made %d calls, want read only and no write", len(f.Calls()))
	}
}

func TestPacman_ParseValueAndSize(t *testing.T) {
	if v := parseColonValue("Version : 9.0"); v != "9.0" {
		t.Errorf("parseColonValue=%q", v)
	}
	if v := parseColonValue("no colon"); v != "" {
		t.Errorf("parseColonValue no-colon=%q", v)
	}
	cases := map[string]int64{
		"3.00 MiB": 3 * 1024 * 1024,
		"512 KiB":  512 * 1024,
		"2 GiB":    2 * 1024 * 1024 * 1024,
		"900 B":    900,
		"42":       42,
	}
	for in, want := range cases {
		got, err := parsePacmanSize(in)
		if err != nil {
			t.Fatalf("parsePacmanSize(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parsePacmanSize(%q)=%d want %d", in, got, want)
		}
	}
}

// readAll drains a recorded Command's stdin reader.
func readAll(t *testing.T, c pmexec.Command) string {
	t.Helper()
	if c.Stdin == nil {
		return ""
	}
	b := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, err := c.Stdin.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

func TestPacman_EnrichmentRunnerFailuresPropagate(t *testing.T) {
	ctx := context.Background()
	t.Run("ListUpgradable: InstalledVersion runner failure", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "git 2.39-1\n")                     // -Qu (simple format triggers InstalledVersion)
		f.Push(pmexec.Result{}, errors.New("-Q")) // InstalledVersion
		if _, err := m.ListUpgradable(ctx); err == nil {
			t.Fatal("an InstalledVersion runner failure must propagate")
		}
	})
	t.Run("ListPinned: InstalledVersion runner failure", func(t *testing.T) {
		m, f := pacmanM(t)
		ok(f, "[options]\nIgnorePkg = linux\n")   // readConf
		f.Push(pmexec.Result{}, errors.New("-Q")) // InstalledVersion
		if _, err := m.ListPinned(ctx); err == nil {
			t.Fatal("an InstalledVersion runner failure must propagate")
		}
	})
}
