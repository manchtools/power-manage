//go:build linux

package fsafe

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"
)

// ReadRootFile reads one bounded regular file through a no-follow descriptor.
// The file must be root-owned and have exactly the requested permission bits.
func ReadRootFile(path string, maxBytes int64, mode os.FileMode) ([]byte, error) {
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return nil, fmt.Errorf("fsafe: maximum file size must be within 1..%d bytes", int64(math.MaxInt64-1))
	}
	resolved, err := resolveRootFilePath(path, mode)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open root-only file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat root-only file %s: %w", path, err)
	}
	if err := validateRootOnlyFileInfo(path, info, maxBytes, mode); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read root-only file %s: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("root-only file %s is too large", path)
	}
	return data, nil
}

// WriteFileAtomic atomically replaces one file with root-directory-safe,
// no-follow publication. An existing symlink entry is replaced, never followed.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	resolved, err := resolveRootFilePath(path, mode)
	if err != nil {
		return err
	}
	if err := replaceFileFrom(resolved, bytes.NewReader(data), mode, true); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func resolveRootFilePath(path string, mode os.FileMode) (string, error) {
	if err := ValidatePath(path); err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: path %q is not absolute", ErrInvalidPath, path)
	}
	if err := validateMode(mode); err != nil {
		return "", err
	}
	clean := filepath.Clean(path)
	parent, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return "", fmt.Errorf("resolve parent of %s: %w", path, err)
	}
	if err := parentDirSafe(parent); err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(clean)), nil
}

func validateRootOnlyFileInfo(path string, info os.FileInfo, maxBytes int64, mode os.FileMode) error {
	if info == nil {
		return fmt.Errorf("root-only file %s has no file metadata", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("root-only file %s is not a regular file", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("root-only file %s has unavailable ownership metadata", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("root-only file %s is not root-owned", path)
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("root-only file %s must have mode %04o", path, mode.Perm())
	}
	if info.Size() < 0 {
		return fmt.Errorf("root-only file %s has an invalid size", path)
	}
	if info.Size() > maxBytes {
		return fmt.Errorf("root-only file %s is too large", path)
	}
	return nil
}
