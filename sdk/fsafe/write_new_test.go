//go:build linux

package fsafe

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileNew_AtomicallyRefusesOverwrite(t *testing.T) {
	allowWriteFileNewTestParent(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("harden temp directory: %v", err)
	}
	path := filepath.Join(directory, "identity.pem")
	if err := WriteFileNew(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("WriteFileNew first create: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat new file: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode = %v; want regular 0600", info.Mode())
	}
	if err := WriteFileNew(path, []byte("second"), 0o600); err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite error = %v; want os.ErrExist", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read preserved file: %v", err)
	}
	if string(content) != "first" {
		t.Fatalf("file content = %q; want original", content)
	}
}

func TestWriteFileNew_RefusesFinalSymlink(t *testing.T) {
	allowWriteFileNewTestParent(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("harden temp directory: %v", err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("safe"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	path := filepath.Join(directory, "identity.pem")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("create final symlink: %v", err)
	}
	if err := WriteFileNew(path, []byte("secret"), 0o600); err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("symlink create error = %v; want os.ErrExist", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read symlink target: %v", err)
	}
	if string(content) != "safe" {
		t.Fatalf("symlink target content = %q; want untouched", content)
	}
}

func allowWriteFileNewTestParent(t *testing.T) {
	t.Helper()
	original := parentDirSafe
	parentDirSafe = func(string) error { return nil }
	t.Cleanup(func() { parentDirSafe = original })
}
