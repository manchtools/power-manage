//go:build linux

package fsafe

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
)

// Direct-backend Manager tests over a real filesystem (filesystem tier): the
// deployed root agent's path — fd-anchored writes, direct reads, the openat
// walk for recursive delete. The runner really executes mkdir/rm/chmod for
// the runner-backed methods.

func newDirectManager(t *testing.T) Manager {
	t.Helper()
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestNew_NilRunnerRejected(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, pmexec.ErrRunnerRequired) {
		t.Fatalf("New(nil) = %v, want ErrRunnerRequired (fail-closed)", err)
	}
}

func TestManager_WriteFile_Direct(t *testing.T) {
	m := newDirectManager(t)
	path := filepath.Join(t.TempDir(), "app.conf")
	if err := m.WriteFile(context.Background(), path, []byte("k=v\n"), WriteOptions{Mode: 0o600}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "k=v\n" {
		t.Errorf("content = %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestManager_WriteFile_DefaultsModeTo0644(t *testing.T) {
	m := newDirectManager(t)
	path := filepath.Join(t.TempDir(), "app.conf")
	if err := m.WriteFile(context.Background(), path, []byte("x"), WriteOptions{}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %#o, want the deterministic 0644 default", info.Mode().Perm())
	}
}

func TestManager_WriteFile_RefusesSetuid(t *testing.T) {
	m := newDirectManager(t)
	path := filepath.Join(t.TempDir(), "evil")
	err := m.WriteFile(context.Background(), path, []byte("#!/bin/sh\n"), WriteOptions{Mode: 0o755 | os.ModeSetuid})
	if !errors.Is(err, ErrUnsafeMode) {
		t.Fatalf("err = %v, want ErrUnsafeMode", err)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Error("refused setuid write still created the file")
	}
}

func TestManager_WriteFileFrom_MidStreamErrorLeavesOriginal(t *testing.T) {
	m := newDirectManager(t)
	path := filepath.Join(t.TempDir(), "app.conf")
	if err := os.WriteFile(path, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("upstream died")
	err := m.WriteFileFrom(context.Background(), path, &errReader{data: strings.NewReader("part"), err: boom}, WriteOptions{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the stream error", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "original\n" {
		t.Errorf("original clobbered: %q", got)
	}
}

func TestManager_WriteFile_BackupTaken(t *testing.T) {
	m := newDirectManager(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "app.conf")
	backup := filepath.Join(dir, "app.conf.bak")
	if err := os.WriteFile(path, []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteFile(context.Background(), path, []byte("v2\n"), WriteOptions{Backup: backup}); err != nil {
		t.Fatalf("WriteFile with backup: %v", err)
	}
	got, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(got) != "v1\n" {
		t.Errorf("backup = %q, want the prior content", got)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2\n" {
		t.Errorf("target = %q, want the new content", got)
	}
}

func TestManager_WriteFile_BackupEqualTargetRefused(t *testing.T) {
	m := newDirectManager(t)
	path := filepath.Join(t.TempDir(), "app.conf")
	err := m.WriteFile(context.Background(), path, []byte("x"), WriteOptions{Backup: path})
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("backup == target: err = %v, want ErrInvalidPath", err)
	}
}

func TestManager_ReadFile_AbsentVsEmpty(t *testing.T) {
	m := newDirectManager(t)
	dir := t.TempDir()

	if _, err := m.ReadFile(context.Background(), filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err = %v, want ErrNotExist (absent is not silent-empty)", err)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := m.ReadFile(context.Background(), empty)
	if err != nil || b != nil {
		t.Errorf("empty file = (%v, %v), want (nil, nil)", b, err)
	}
}

func TestManager_Exists_Direct(t *testing.T) {
	m := newDirectManager(t)
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, err := m.Exists(context.Background(), present)
	if err != nil || !ok {
		t.Errorf("Exists(present) = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = m.Exists(context.Background(), filepath.Join(dir, "missing"))
	if err != nil || ok {
		t.Errorf("Exists(missing) = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestManager_ReadDir_Direct(t *testing.T) {
	m := newDirectManager(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	entries, err := m.ReadDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	byName := map[string]bool{}
	for _, e := range entries {
		byName[e.Name] = e.IsDir
	}
	if len(byName) != 3 {
		t.Fatalf("entries = %v, want 3", entries)
	}
	if !byName["sub"] {
		t.Error("sub not reported as a directory")
	}
	if byName["file.txt"] {
		t.Error("file.txt reported as a directory")
	}
	if byName["link"] {
		t.Error("symlink reported with its target's type; want the link's own (IsDir=false)")
	}

	if _, err := m.ReadDir(context.Background(), filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing dir: err = %v, want ErrNotExist", err)
	}
	if _, err := m.ReadDir(context.Background(), filepath.Join(dir, "file.txt")); err == nil {
		t.Error("ReadDir on a regular file returned no error, want ENOTDIR-class failure (never a silent empty list)")
	}
}

func TestManager_RemoveDir_Direct_RemovesTreeWithoutFollowingSymlinks(t *testing.T) {
	m := newDirectManager(t)
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	if err := os.MkdirAll(filepath.Join(victim, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "keep", "data"), []byte("v"), 0o644); err != nil {
		t.Fatal(err)
	}

	doomed := filepath.Join(base, "doomed")
	if err := os.MkdirAll(filepath.Join(doomed, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(doomed, "nested", "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink INSIDE the doomed tree pointing at the victim: the walk must
	// unlink the symlink entry itself, never traverse into the target.
	if err := os.Symlink(victim, filepath.Join(doomed, "trap")); err != nil {
		t.Fatal(err)
	}

	if err := m.RemoveDir(context.Background(), doomed); err != nil {
		t.Fatalf("RemoveDir: %v", err)
	}
	if _, err := os.Lstat(doomed); !os.IsNotExist(err) {
		t.Error("doomed tree still present")
	}
	if _, err := os.Stat(filepath.Join(victim, "keep", "data")); err != nil {
		t.Errorf("victim tree damaged through the planted symlink: %v", err)
	}
}

func TestManager_RemoveDir_Direct_RefusesSymlinkLeaf(t *testing.T) {
	m := newDirectManager(t)
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(base, "managed")
	if err := os.Symlink(victim, leaf); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveDir(context.Background(), leaf); err == nil {
		t.Fatal("RemoveDir followed a symlink leaf, want refusal")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("victim removed through symlink leaf: %v", err)
	}
}

// AC-11: create AND delete under a protected prefix are both refused — on the
// attack list, before any command or filesystem effect.
func TestManager_RemoveDir_RefusesProtectedPrefix(t *testing.T) {
	m := newDirectManager(t)
	attack := []string{
		"/etc/cron.d",
		"/etc/sudoers.d",
		"/home/alice",
		"/var/lib/postgresql",
		"/usr/bin",
		"/boot/efi",
	}
	for _, p := range attack {
		if err := m.RemoveDir(context.Background(), p); !errors.Is(err, ErrProtectedTarget) {
			t.Errorf("RemoveDir(%q) = %v, want ErrProtectedTarget", p, err)
		}
	}
}

func TestManager_Mkdir_RefusesProtectedPrefix(t *testing.T) {
	m := newDirectManager(t)
	attack := []string{
		"/etc/cron.d/pm-test",
		"/etc/systemd/system/pm-test.d",
		"/usr/local/bin/pm-test",
		"/home/alice/pm-test",
	}
	for _, p := range attack {
		err := m.Mkdir(context.Background(), p, MkdirOptions{Recursive: true})
		if !errors.Is(err, ErrProtectedTarget) {
			t.Errorf("Mkdir(%q) = %v, want ErrProtectedTarget (create side, [SDK-8])", p, err)
		}
	}
}

func TestManager_Mkdir_RefusesSymlinkResolvingIntoProtected(t *testing.T) {
	m := newDirectManager(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "innocent")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	err := m.Mkdir(context.Background(), filepath.Join(link, "cron.d", "pm-test"), MkdirOptions{Recursive: true})
	if !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("Mkdir through a symlink into /etc = %v, want ErrProtectedTarget (resolution is part of the check)", err)
	}
}

func TestManager_Mkdir_CreatesWithMode(t *testing.T) {
	m := newDirectManager(t)
	path := filepath.Join(t.TempDir(), "a", "b")
	if err := m.Mkdir(context.Background(), path, MkdirOptions{Recursive: true, Mode: 0o750}); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o750 {
		t.Errorf("created dir mode = %#o, want 0750", info.Mode().Perm())
	}
}

func TestManager_Remove_Direct(t *testing.T) {
	m := newDirectManager(t)
	path := filepath.Join(t.TempDir(), "gone")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove(context.Background(), path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("file still present after Remove")
	}
}

func TestManager_SetMode_Direct(t *testing.T) {
	m := newDirectManager(t)
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.SetMode(context.Background(), path, 0o640); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %#o, want 0640", info.Mode().Perm())
	}
}

func TestManager_SetOwnership_BothEmptyIsNoop(t *testing.T) {
	m := newDirectManager(t)
	// No file needed: both-empty must return nil without touching anything.
	if err := m.SetOwnership(context.Background(), "/nonexistent/pm-test", "", ""); err != nil {
		t.Fatalf("SetOwnership(\"\", \"\") = %v, want nil no-op", err)
	}
}

func TestManager_SetOwnershipRecursive_RefusesProtectedTree(t *testing.T) {
	m := newDirectManager(t)
	for _, p := range []string{"/", "/etc", "/usr", "/home"} {
		if err := m.SetOwnershipRecursive(context.Background(), p, "nobody", ""); !errors.Is(err, ErrProtectedTarget) {
			t.Errorf("SetOwnershipRecursive(%q) = %v, want ErrProtectedTarget", p, err)
		}
	}
}
