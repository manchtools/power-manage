package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

// flatpakM builds a system-scope flatpak FlatpakManager over a fresh fake.
func flatpakM(t *testing.T, opts ...Option) (FlatpakManager, *exectest.FakeRunner) {
	t.Helper()
	f := newFake()
	m, err := New(Flatpak, f, opts...)
	if err != nil {
		t.Fatalf("New(Flatpak): %v", err)
	}
	fm, ok := m.(FlatpakManager)
	if !ok {
		t.Fatalf("New(Flatpak) is %T, want FlatpakManager", m)
	}
	return fm, f
}

func TestFlatpak_Version(t *testing.T) {
	t.Run("parses version", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "Flatpak 1.14.4\n")
		v, err := m.Version(context.Background())
		if err != nil || v != "1.14.4" {
			t.Fatalf("v=%q err=%v", v, err)
		}
		if c := f.Calls()[0]; argv(c) != "flatpak --version" || c.Escalate {
			t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
		}
	})
	t.Run("short output is malformed", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "Flatpak\n")
		if _, err := m.Version(context.Background()); !errors.Is(err, ErrMalformedOutput) {
			t.Fatalf("err=%v, want ErrMalformedOutput", err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Version(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestFlatpak_InstallFromRemote(t *testing.T) {
	ctx := context.Background()
	t.Run("explicit remote operand precedes the appid", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{Remote: "flathub"}, "org.vim.Vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); a != "flatpak install -y --noninteractive --system flathub org.vim.Vim" {
			t.Errorf("argv=%q, want the remote operand before the appid", a)
		}
	})
	t.Run("flag-shaped remote is rejected before running", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Install(ctx, InstallOptions{Remote: "-evil"}, "org.vim.Vim"); err == nil {
			t.Fatal("want a validation error for a flag-shaped remote")
		}
		if len(f.Calls()) != 0 {
			t.Error("a rejected remote must run nothing")
		}
	})
	t.Run("empty remote keeps the existing no-remote behavior", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{}, "org.vim.Vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); a != "flatpak install -y --noninteractive --system org.vim.Vim" {
			t.Errorf("argv=%q, want no remote operand", a)
		}
	})
}

func TestFlatpak_Install(t *testing.T) {
	ctx := context.Background()
	t.Run("system scope, escalated", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{}, "org.vim.Vim"); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "flatpak install -y --noninteractive --system org.vim.Vim" || !c.Escalate {
			t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
		}
	})
	t.Run("version is validated but ignored", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		// flatpak cannot pin a version, but multiple packages with a version are
		// allowed here (version is ignored, not one-package-enforced).
		if _, err := m.Install(ctx, InstallOptions{Version: "1.0"}, "org.vim.Vim", "org.gnu.emacs"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); strings.Contains(a, "1.0") {
			t.Errorf("version must not reach argv: %q", a)
		}
	})
	t.Run("user scope is unprivileged", func(t *testing.T) {
		m, f := flatpakM(t, WithUserScope())
		ok(f, "")
		if _, err := m.Install(ctx, InstallOptions{}, "org.vim.Vim"); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if !strings.Contains(argv(c), "--user") || c.Escalate {
			t.Errorf("argv=%q escalate=%v, want --user unescalated", argv(c), c.Escalate)
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Install(ctx, InstallOptions{}); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Install(ctx, InstallOptions{}, "org.vim.Vim;rm"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("bad version", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Install(ctx, InstallOptions{Version: "1;0"}, "org.vim.Vim"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestFlatpak_Remove(t *testing.T) {
	ctx := context.Background()
	t.Run("remove", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.Remove(ctx, RemoveOptions{}, "org.vim.Vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "flatpak uninstall -y --noninteractive --system org.vim.Vim" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("purge adds --delete-data", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.Remove(ctx, RemoveOptions{Purge: true}, "org.vim.Vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "--delete-data") {
			t.Errorf("argv=%q want --delete-data", a)
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Remove(ctx, RemoveOptions{}); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Remove(ctx, RemoveOptions{}, "--x"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestFlatpak_UpdateUpgrade(t *testing.T) {
	ctx := context.Background()
	t.Run("update --appstream", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.Update(ctx); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "flatpak update --appstream -y --noninteractive --system" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("UpgradeAll", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{}); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "flatpak update -y --noninteractive --system" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("empty Upgrade is a no-op", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Upgrade(ctx); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 0 {
			t.Errorf("empty Upgrade ran %d commands, want 0", len(f.Calls()))
		}
	})
	t.Run("upgrade specific", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if _, err := m.Upgrade(ctx, "org.vim.Vim"); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(argv(f.Calls()[0]), "--system org.vim.Vim") {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("upgrade bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Upgrade(ctx, "a;b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("write exec error surfaced", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied)
		if _, err := m.Update(ctx); !errors.Is(err, pmexec.ErrEscalationDenied) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestFlatpak_Autoremove(t *testing.T) {
	m, f := flatpakM(t)
	ok(f, "")
	if _, err := m.Autoremove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a := argv(f.Calls()[0]); a != "flatpak uninstall --unused -y --noninteractive --system" {
		t.Errorf("argv=%q", a)
	}
}

func TestFlatpak_Search(t *testing.T) {
	ctx := context.Background()
	t.Run("parses tab-separated rows", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "GNU Emacs\tEditor\torg.gnu.emacs\t28\tstable\tflathub\nVim\tVi IMproved\torg.vim.Vim\t9\tstable\tflathub\n")
		res, err := m.Search(ctx, "edit")
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 || res[0].Name != "org.gnu.emacs" || res[0].Description != "Editor" {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("first line without a tab is treated as a header and skipped", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "No matches header line\nVim\tVi IMproved\torg.vim.Vim\t9\tstable\tflathub\n")
		res, err := m.Search(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Name != "org.vim.Vim" {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("exit 1 means no matches", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if res, err := m.Search(ctx, "ghost"); err != nil || res == nil || len(res) != 0 {
			t.Fatalf("res=%v err=%v", res, err)
		}
	})
	t.Run("other non-zero is an error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 2, Stderr: "x"}, nil)
		if _, err := m.Search(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Search(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestFlatpak_List(t *testing.T) {
	t.Run("parses columns with pin", func(t *testing.T) {
		m, f := flatpakM(t)
		// Second row has only 3 columns (< 4) and is skipped.
		ok(f, "org.vim.Vim\t9.0\tx86_64\t3.0 MB\tVi IMproved\tflathub\nshort\tfields\tonly\n")
		ok(f, "org.vim.Vim\n") // getPinnedSet (flatpak mask)
		pkgs, err := m.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 1 {
			t.Fatalf("the 3-column row must be skipped, got %+v", pkgs)
		}
		vim := pkgs[0]
		if vim.Name != "org.vim.Vim" || vim.Size != 3*1000*1000 || vim.Repository != "flathub" || vim.Description != "Vi IMproved" || !vim.Pinned {
			t.Fatalf("vim=%+v", vim)
		}
	})
	t.Run("pin-set failure propagates", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\t9.0\tx86_64\t3.0 MB\tVi IMproved\tflathub\n")
		f.Push(pmexec.Result{ExitCode: 1}, nil) // mask fails -> nil set
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("mask query failure returned nil error")
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestFlatpak_ListUpgradable(t *testing.T) {
	ctx := context.Background()
	t.Run("parses updates", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\t9.1\tflathub\nshort\n")
		ok(f, "9.0\n") // InstalledVersion(org.vim.Vim)
		ups, err := m.ListUpgradable(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(ups) != 1 || ups[0].Name != "org.vim.Vim" || ups[0].NewVersion != "9.1" || ups[0].CurrentVersion != "9.0" || ups[0].Repository != "flathub" {
			t.Fatalf("ups=%+v", ups)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListUpgradable(ctx); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestFlatpak_Show(t *testing.T) {
	ctx := context.Background()
	installed := "Version: 9.0\nArch: x86_64\nDescription: Vi IMproved\nInstalled: 3.0 MB\nOrigin: flathub\n"
	t.Run("installed and pinned", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 0, Stdout: installed}, nil) // info
		ok(f, "org.vim.Vim\n")                                     // IsPinned mask
		p, err := m.Show(ctx, "org.vim.Vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "installed" || p.Version != "9.0" || p.Architecture != "x86_64" || p.Size != 3*1000*1000 || p.Repository != "flathub" || !p.Pinned {
			t.Fatalf("p=%+v", p)
		}
	})
	t.Run("not installed falls back to remote-info", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil) // info: not installed
		ok(f, "Version: 9.2\nArch: x86_64\nDescription: from remote\nDownload: 5.0 MB\n")
		p, err := m.Show(ctx, "org.vim.Vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "available" || p.Repository != "flathub" || p.Version != "9.2" || p.Size != 5*1000*1000 {
			t.Fatalf("p=%+v", p)
		}
	})
	t.Run("not installed and not on remote -> package not found", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil) // info: not installed
		f.Push(pmexec.Result{ExitCode: 1}, nil) // remote-info: not offered by flathub
		if _, err := m.Show(ctx, "org.ghost.App"); err == nil || !strings.Contains(err.Error(), "package not found") {
			t.Fatalf("err=%v, want 'package not found'", err)
		}
	})
	t.Run("remote-info runner error propagates", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)          // info: not installed
		f.Push(pmexec.Result{}, errors.New("transport")) // remote-info runner failure
		if _, err := m.Show(ctx, "org.ghost.App"); err == nil {
			t.Fatal("a remote-info runner failure must propagate, not become 'package not found'")
		}
	})
	t.Run("info exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Show(ctx, "org.vim.Vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Show(ctx, "a;b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestFlatpak_ListVersions(t *testing.T) {
	ctx := context.Background()
	t.Run("reads remote-info version", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "9.0\n") // InstalledVersion
		ok(f, "Version: 9.2\nArch: x86_64\n")
		info, err := m.ListVersions(ctx, "org.vim.Vim")
		if err != nil {
			t.Fatal(err)
		}
		if info.Installed != "9.0" || len(info.Versions) != 1 || info.Versions[0].Version != "9.2" || info.Versions[0].Repository != "flathub" {
			t.Fatalf("info=%+v", info)
		}
	})
	t.Run("installed-version runner failure propagates", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("flatpak info err")) // InstalledVersion runner failure
		if _, err := m.ListVersions(ctx, "org.vim.Vim"); err == nil {
			t.Fatal("a runner failure in the installed-version lookup must propagate")
		}
	})
	t.Run("not on remote returns info without versions", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "9.0\n")                          // InstalledVersion
		f.Push(pmexec.Result{ExitCode: 1}, nil) // remote-info: not offered by flathub (benign)
		info, err := m.ListVersions(ctx, "org.vim.Vim")
		if err != nil || len(info.Versions) != 0 {
			t.Fatalf("info=%+v err=%v", info, err)
		}
	})
	t.Run("remote-info runner failure propagates", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "9.0\n")                                   // InstalledVersion
		f.Push(pmexec.Result{}, errors.New("transport")) // remote-info runner failure
		if _, err := m.ListVersions(ctx, "org.vim.Vim"); err == nil {
			t.Fatal("a remote-info runner failure must propagate")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.ListVersions(ctx, "a;b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestFlatpak_IsInstalledVersionCount(t *testing.T) {
	ctx := context.Background()
	t.Run("installed", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)
		if got, err := m.IsInstalled(ctx, "org.vim.Vim"); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("not installed", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if got, err := m.IsInstalled(ctx, "org.ghost.App"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("IsInstalled exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.IsInstalled(ctx, "org.vim.Vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("IsInstalled bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.IsInstalled(ctx, "a;b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("InstalledVersion present", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 0, Stdout: "9.0\n"}, nil)
		if v, err := m.InstalledVersion(ctx, "org.vim.Vim"); err != nil || v != "9.0" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("InstalledVersion not installed -> empty", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if v, err := m.InstalledVersion(ctx, "org.ghost.App"); err != nil || v != "" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("InstalledVersion exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledVersion(ctx, "org.vim.Vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("InstalledVersion bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.InstalledVersion(ctx, "a;b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("InstalledCount", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\norg.gnu.emacs\n")
		if n, err := m.InstalledCount(ctx); err != nil || n != 2 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	})
	t.Run("InstalledCount exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledCount(ctx); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestFlatpak_HasUpdates(t *testing.T) {
	ctx := context.Background()
	t.Run("updates available", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\n")
		if got, err := m.HasUpdates(ctx, false); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("none", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "\n")
		if got, err := m.HasUpdates(ctx, false); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.HasUpdates(ctx, false); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestFlatpak_PinUnpin(t *testing.T) {
	ctx := context.Background()
	t.Run("pin masks each package", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "") // current mask set
		ok(f, "") // mask org.vim.Vim
		f.Push(pmexec.Result{Stdout: "masked\n"}, nil)
		res, err := m.Pin(ctx, "org.vim.Vim", "org.gnu.emacs")
		if err != nil {
			t.Fatal(err)
		}
		if res.Stdout != "masked\n" {
			t.Fatalf("result = %+v, want the last applied command result", res)
		}
		calls := f.Calls()
		if len(calls) != 3 || argv(calls[1]) != "flatpak mask org.vim.Vim --system" {
			t.Fatalf("calls=%d argv1=%q", len(calls), argv(calls[1]))
		}
	})
	t.Run("unpin removes the mask", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\n") // current mask set
		ok(f, "")              // unmask
		if _, err := m.Unpin(ctx, "org.vim.Vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[1]) != "flatpak mask --remove org.vim.Vim --system" {
			t.Errorf("argv=%q", argv(f.Calls()[1]))
		}
	})
	t.Run("unpin rolls back earlier changes", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.a.A\norg.b.B\n")                          // current mask set
		ok(f, "")                                            // first unmask ok
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "x"}, nil) // second unmask fails
		ok(f, "")                                            // restore first mask
		if _, err := m.Unpin(ctx, "org.a.A", "org.b.B"); err == nil {
			t.Fatal("want apply error")
		}
		calls := f.Calls()
		if len(calls) != 4 || argv(calls[3]) != "flatpak mask org.a.A --system" {
			t.Fatalf("calls = %+v, want first mask restored", calls)
		}
	})
	t.Run("pin rolls back earlier changes", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")                                            // current mask set
		ok(f, "")                                            // first mask ok
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "x"}, nil) // second mask fails
		ok(f, "")                                            // restore first unmasked state
		_, err := m.Pin(ctx, "org.a.A", "org.b.B")
		if err == nil {
			t.Fatal("want apply error")
		}
		calls := f.Calls()
		if len(calls) != 4 || argv(calls[3]) != "flatpak mask --remove org.a.A --system" {
			t.Fatalf("calls = %+v, want first mask removed", calls)
		}
	})
	t.Run("pin bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Pin(ctx, "a;b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("unpin bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.Unpin(ctx, "a;b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestFlatpak_ListPinnedAndIsPinned(t *testing.T) {
	ctx := context.Background()
	t.Run("ListPinned with versions", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\n\norg.gnu.emacs\n") // mask (blank line skipped)
		ok(f, "9.0\n")                          // InstalledVersion vim
		ok(f, "28\n")                           // InstalledVersion emacs
		pkgs, err := m.ListPinned(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 2 || pkgs[0].Name != "org.vim.Vim" || pkgs[0].Version != "9.0" || !pkgs[0].Pinned {
			t.Fatalf("pkgs=%+v", pkgs)
		}
	})
	t.Run("ListPinned exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListPinned(ctx); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("IsPinned true", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\n")
		if got, err := m.IsPinned(ctx, "org.vim.Vim"); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("IsPinned false", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.gnu.emacs\n")
		if got, err := m.IsPinned(ctx, "org.vim.Vim"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("IsPinned propagates mask failure", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if _, err := m.IsPinned(ctx, "org.vim.Vim"); err == nil {
			t.Fatal("mask query failure returned nil error")
		}
	})
	t.Run("IsPinned bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if _, err := m.IsPinned(ctx, "a;b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
}

func TestFlatpak_Remotes(t *testing.T) {
	ctx := context.Background()
	t.Run("AddRemote validates and adds", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if err := m.AddRemote(ctx, "flathub", "https://dl.flathub.org/repo/flathub.flatpakrepo"); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if !strings.HasPrefix(argv(c), "flatpak remote-add --if-not-exists flathub https://") || !c.Escalate {
			t.Errorf("argv=%q escalate=%v", argv(c), c.Escalate)
		}
	})
	t.Run("AddRemote rejects a bad remote name", func(t *testing.T) {
		m, f := flatpakM(t)
		if err := m.AddRemote(ctx, "--from=evil", "https://x/y"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want name rejection, no exec")
		}
	})
	t.Run("AddRemote rejects a non-https url", func(t *testing.T) {
		m, f := flatpakM(t)
		if err := m.AddRemote(ctx, "flathub", "http://insecure/repo"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want url rejection, no exec")
		}
	})
	t.Run("RemoveRemote", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "")
		if err := m.RemoveRemote(ctx, "flathub"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "flatpak remote-delete --force flathub --system" {
			t.Errorf("argv=%q", argv(f.Calls()[0]))
		}
	})
	t.Run("RemoveRemote rejects a bad name", func(t *testing.T) {
		m, f := flatpakM(t)
		if err := m.RemoveRemote(ctx, "a b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection")
		}
	})
	t.Run("ListRemotes", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "flathub\nfedora\n\n")
		remotes, err := m.ListRemotes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(remotes) != 2 || remotes[0] != "flathub" {
			t.Fatalf("remotes=%v", remotes)
		}
	})
	t.Run("ListRemotes exec error", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListRemotes(ctx); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestFlatpak_ParseHelpers(t *testing.T) {
	t.Run("parseFlatpakSearchLine", func(t *testing.T) {
		if r := parseFlatpakSearchLine("Name\tDesc\torg.app.Id\t1\tstable\tflathub"); r == nil || r.Name != "org.app.Id" || r.Description != "Desc" {
			t.Errorf("got %+v", r)
		}
		if r := parseFlatpakSearchLine("too\tfew"); r != nil {
			t.Errorf("a <3-field line must yield nil, got %+v", r)
		}
	})
	t.Run("parseFlatpakValue", func(t *testing.T) {
		if v := parseFlatpakValue("Version: 1.0"); v != "1.0" {
			t.Errorf("got %q", v)
		}
		if v := parseFlatpakValue("nocolon"); v != "" {
			t.Errorf("no-colon must be empty, got %q", v)
		}
	})
	t.Run("parseFlatpakSize", func(t *testing.T) {
		cases := map[string]int64{
			"100 kB":    100 * 1000,
			"100 KB":    100 * 1000,
			"1 KiB":     1024,
			"5 MB":      5 * 1000 * 1000,
			"2 MiB":     2 * 1024 * 1024,
			"3 GB":      3 * 1000 * 1000 * 1000,
			"1 GiB":     1024 * 1024 * 1024,
			"512 bytes": 512,
			"1,024 KiB": 1024 * 1024, // comma stripped
		}
		for in, want := range cases {
			got, err := parseFlatpakSize(in)
			if err != nil {
				t.Fatalf("parseFlatpakSize(%q): %v", in, err)
			}
			if got != want {
				t.Errorf("parseFlatpakSize(%q)=%d want %d", in, got, want)
			}
		}
	})
}

func TestFlatpak_EnrichmentRunnerFailuresPropagate(t *testing.T) {
	ctx := context.Background()
	t.Run("List: getPinnedSet runner failure", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\t9.0\tx86_64\t3.0 MB\tVi IMproved\tflathub\n") // list
		f.Push(pmexec.Result{}, errors.New("mask"))                       // getPinnedSet probe
		if _, err := m.List(ctx); err == nil {
			t.Fatal("a getPinnedSet runner failure must propagate")
		}
	})
	t.Run("ListUpgradable: InstalledVersion runner failure", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\t9.1\tflathub\n")        // remote-ls
		f.Push(pmexec.Result{}, errors.New("info")) // InstalledVersion
		if _, err := m.ListUpgradable(ctx); err == nil {
			t.Fatal("an InstalledVersion runner failure must propagate")
		}
	})
	t.Run("Show: IsPinned runner failure", func(t *testing.T) {
		m, f := flatpakM(t)
		f.Push(pmexec.Result{ExitCode: 0, Stdout: "Version: 9.0\n"}, nil) // info (installed)
		f.Push(pmexec.Result{}, errors.New("mask"))                       // IsPinned probe
		if _, err := m.Show(ctx, "org.vim.Vim"); err == nil {
			t.Fatal("an IsPinned runner failure must propagate")
		}
	})
	t.Run("ListPinned: InstalledVersion runner failure", func(t *testing.T) {
		m, f := flatpakM(t)
		ok(f, "org.vim.Vim\n")                      // mask
		f.Push(pmexec.Result{}, errors.New("info")) // InstalledVersion
		if _, err := m.ListPinned(ctx); err == nil {
			t.Fatal("an InstalledVersion runner failure must propagate")
		}
	})
}
