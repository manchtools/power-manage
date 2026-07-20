//go:build linux

package fsafe

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// AC-9: the fd-anchored primitives refuse a symlink final component in the
// open itself — the check and the handle are the same syscall, so there is no
// window to swap one in — and metadata changes go through the held fd.

func TestOpenRealDir_OpensRealDirectory(t *testing.T) {
	dir := t.TempDir()
	f, err := OpenRealDir(dir)
	if err != nil {
		t.Fatalf("OpenRealDir(%q) = %v", dir, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat via fd: %v", err)
	}
	if !info.IsDir() {
		t.Error("fd does not reference a directory")
	}
}

func TestOpenRealDir_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRealDir(link); err == nil {
		_ = f.Close()
		t.Error("OpenRealDir followed a symlink, want ELOOP-class refusal")
	}
}

func TestOpenRealDir_RefusesNonDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRealDir(file); err == nil {
		_ = f.Close()
		t.Error("OpenRealDir opened a regular file, want ENOTDIR-class refusal")
	}
}

func TestFchownNoFollow_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("v"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "planted")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := FchownNoFollow(link, -1, -1); err == nil {
		t.Error("FchownNoFollow followed a planted symlink, want refusal")
	}
}

func TestFchownNoFollow_RefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	// Must return (not hang): the open is O_NONBLOCK, so a FIFO with no writer
	// cannot DoS the caller; the IsRegular check then rejects it.
	err := FchownNoFollow(fifo, -1, -1)
	if err == nil {
		t.Error("FchownNoFollow accepted a FIFO, want non-regular refusal")
	}
}

func TestFchownNoFollow_NoopOnRegular(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// -1/-1 is the chown(2) leave-unchanged sentinel; the call must succeed
	// unprivileged.
	if err := FchownNoFollow(file, -1, -1); err != nil {
		t.Errorf("FchownNoFollow(regular, -1, -1) = %v, want nil", err)
	}
}

func TestSetDirPermissionsNoFollow_AppliesMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SetDirPermissionsNoFollow(target, 0o750, -1, -1); err != nil {
		t.Fatalf("SetDirPermissionsNoFollow: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("mode = %#o, want 0750 (applied through the held fd)", info.Mode().Perm())
	}
}

func TestSetDirPermissionsNoFollow_RefusesSymlinkedDir(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := SetDirPermissionsNoFollow(link, 0o700, -1, -1); err == nil {
		t.Fatal("SetDirPermissionsNoFollow followed a symlink, want refusal")
	}
	info, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("target dir mode changed to %#o through a symlink", info.Mode().Perm())
	}
}

func TestResolveOwnership(t *testing.T) {
	uid, gid, err := ResolveOwnership("", "")
	if err != nil || uid != -1 || gid != -1 {
		t.Errorf("empty ownership = (%d, %d, %v), want (-1, -1, nil)", uid, gid, err)
	}

	uid, gid, err = ResolveOwnership("0", "0")
	if err != nil || uid != 0 || gid != 0 {
		t.Errorf("numeric ownership = (%d, %d, %v), want (0, 0, nil)", uid, gid, err)
	}

	me, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	wantUID, err := strconv.Atoi(me.Uid)
	if err != nil {
		t.Skipf("non-numeric uid %q", me.Uid)
	}
	uid, _, err = ResolveOwnership(me.Username, "")
	if err != nil {
		t.Fatalf("resolve current user %q: %v", me.Username, err)
	}
	if uid != wantUID {
		t.Errorf("uid = %d, want %d", uid, wantUID)
	}

	if _, _, err := ResolveOwnership("no-such-user-pm-test", ""); err == nil {
		t.Error("unknown owner resolved, want error (callers must fail closed)")
	} else if !strings.Contains(err.Error(), "no-such-user-pm-test") {
		t.Errorf("error %v does not name the unresolvable owner", err)
	}
}
