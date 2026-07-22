//go:build linux

package fsafe

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestValidateRootOnlyFileInfo_RequiresRegularRootOwnedExactModeAndBound(t *testing.T) {
	tests := []struct {
		name string
		info fakeRootFileInfo
		want string
	}{
		{name: "regular root-only", info: fakeRootFileInfo{mode: 0o600, size: 8, stat: syscall.Stat_t{Uid: 0}}},
		{name: "non-regular", info: fakeRootFileInfo{mode: os.ModeNamedPipe | 0o600, size: 8, stat: syscall.Stat_t{Uid: 0}}, want: "is not a regular file"},
		{name: "non-root owner", info: fakeRootFileInfo{mode: 0o600, size: 8, stat: syscall.Stat_t{Uid: 1000}}, want: "is not root-owned"},
		{name: "permissive mode", info: fakeRootFileInfo{mode: 0o640, size: 8, stat: syscall.Stat_t{Uid: 0}}, want: "must have mode 0600"},
		{name: "special mode bits", info: fakeRootFileInfo{mode: os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0o600, size: 8, stat: syscall.Stat_t{Uid: 0}}, want: "must have mode 0600"},
		{name: "too large", info: fakeRootFileInfo{mode: 0o600, size: 9, stat: syscall.Stat_t{Uid: 0}}, want: "is too large"},
		{name: "negative size", info: fakeRootFileInfo{mode: 0o600, size: -1, stat: syscall.Stat_t{Uid: 0}}, want: "has an invalid size"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRootOnlyFileInfo("/var/lib/power-manage/identity.pem", test.info, 8, 0o600)
			if test.want == "" && err != nil {
				t.Fatalf("validateRootOnlyFileInfo: %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("validateRootOnlyFileInfo error = %v; want category %q", err, test.want)
			}
		})
	}
}

func TestReadRootFile_RefusesFinalSymlink(t *testing.T) {
	allowWriteFileNewTestParent(t)
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	path := filepath.Join(directory, "identity.pem")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := ReadRootFile(path, 64, 0o600); err == nil || !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("ReadRootFile symlink error = %v; want ELOOP from no-follow open", err)
	}
}

func TestReadRootFile_RejectsInvalidBoundBeforeFilesystemAccess(t *testing.T) {
	if _, err := ReadRootFile("/definitely/absent/identity.pem", 0, 0o600); err == nil || !strings.Contains(err.Error(), "maximum file size must be within") {
		t.Fatalf("ReadRootFile invalid-bound error = %v; want argument rejection", err)
	}
}

func TestReadRootFile_ReadsOnlyBoundedMode0600RootFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned fixture")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("harden root-owned fixture directory: %v", err)
	}
	path := filepath.Join(directory, "identity.pem")
	if err := os.WriteFile(path, []byte("12345678"), 0o600); err != nil {
		t.Fatalf("write root-only file: %v", err)
	}
	got, err := ReadRootFile(path, 8, 0o600)
	if err != nil || string(got) != "12345678" {
		t.Fatalf("ReadRootFile = %q, %v; want exact bounded content", got, err)
	}
	if _, err := ReadRootFile(path, 7, 0o600); err == nil || !strings.Contains(err.Error(), "is too large") {
		t.Fatalf("oversize ReadRootFile error = %v; want too large", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("make root file too permissive: %v", err)
	}
	if _, err := ReadRootFile(path, 8, 0o600); err == nil || !strings.Contains(err.Error(), "must have mode 0600") {
		t.Fatalf("permissive ReadRootFile error = %v; want mode 0600", err)
	}
}

func TestWriteFileAtomic_ReplacesSymlinkEntryWithoutTouchingTarget(t *testing.T) {
	allowWriteFileNewTestParent(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("harden temp directory: %v", err)
	}
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	path := filepath.Join(directory, "identity.pem")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatalf("create planted symlink: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "replacement" {
		t.Fatalf("replacement = %q, %v; want replacement", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("replacement info = %v, %v; want regular 0600", info, err)
	}
	got, err = os.ReadFile(victim)
	if err != nil || string(got) != "victim" {
		t.Fatalf("victim = %q, %v; want untouched", got, err)
	}
}

type fakeRootFileInfo struct {
	mode os.FileMode
	size int64
	stat syscall.Stat_t
}

func (f fakeRootFileInfo) Name() string       { return "identity.pem" }
func (f fakeRootFileInfo) Size() int64        { return f.size }
func (f fakeRootFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeRootFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeRootFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeRootFileInfo) Sys() any           { return &f.stat }
