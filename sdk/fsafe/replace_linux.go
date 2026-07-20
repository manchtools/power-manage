//go:build linux

package fsafe

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// replaceFileFrom atomically replaces path with the bytes streamed from src
// ([SDK-9], AC-10/AC-12): a random O_EXCL temp in the target directory,
// io.Copy (bounded memory — the content is never held whole), chmod before
// the file is reachable by name, fsync, then an atomic rename. A mid-stream
// error leaves the original untouched and removes the temp. With
// removeExisting false the rename refuses to clobber an existing target.
func replaceFileFrom(path string, src io.Reader, perm os.FileMode, removeExisting bool) (err error) {
	if err := validateMode(perm); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()        // double close after the success path is a harmless no-op
			_ = os.Remove(tmpName) // best-effort cleanup; the primary error wins
		}
	}()
	if _, err = io.Copy(tmp, src); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err = tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp for %s: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp for %s: %w", path, err)
	}
	if err = safeRename(tmpName, path, removeExisting); err != nil {
		return err
	}
	// Make the rename itself durable. Best-effort: the data is already synced,
	// and a dir-fsync failure must not report a completed replace as failed.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close() // read-only dir fd
	}
	return nil
}

// safeRename renames oldPath over newPath. With removeExisting an existing
// target (including a planted symlink ENTRY — mv -T semantics, never
// followed) is atomically replaced; without it the rename fails on any
// existing target via RENAME_NOREPLACE.
func safeRename(oldPath, newPath string, removeExisting bool) error {
	if removeExisting {
		if err := os.Rename(oldPath, newPath); err != nil {
			return fmt.Errorf("rename %s -> %s: %w", oldPath, newPath, err)
		}
		return nil
	}
	err := renameat2(oldPath, newPath, renameNoReplace)
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
		// Filesystem/kernel without RENAME_NOREPLACE: check-then-rename.
		// ponytail: inherently racy fallback; modern kernels take the atomic
		// path above, and the racy window only widens to plain rename(2).
		if _, lerr := os.Lstat(newPath); lerr == nil {
			return fmt.Errorf("rename %s -> %s: %w", oldPath, newPath, syscall.EEXIST)
		} else if !os.IsNotExist(lerr) {
			return fmt.Errorf("rename %s -> %s: %w", oldPath, newPath, lerr)
		}
		if rerr := os.Rename(oldPath, newPath); rerr != nil {
			return fmt.Errorf("rename %s -> %s: %w", oldPath, newPath, rerr)
		}
		return nil
	}
	return fmt.Errorf("rename %s -> %s (no-replace): %w", oldPath, newPath, err)
}
