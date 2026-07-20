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
		// Filesystem/kernel without RENAME_NOREPLACE. os.Link is the atomic
		// no-clobber primitive: link(2) creates newPath as a second name for the
		// temp's inode and fails EEXIST if newPath already exists — including a
		// planted symlink ENTRY, which it neither follows nor clobbers — so a
		// concurrent creator cannot be silently overwritten the way the old
		// check-then-rename fallback (Lstat then rename) could between its two
		// syscalls. Then drop the temp name; the inode now lives at newPath.
		if lerr := os.Link(oldPath, newPath); lerr != nil {
			return fmt.Errorf("rename %s -> %s (no-replace link): %w", oldPath, newPath, lerr)
		}
		// The link IS the atomic commit — newPath now holds the content, so the
		// replace has already succeeded. Dropping the temp name is best-effort: a
		// Remove failure here (e.g. the temp was concurrently unlinked) must not
		// report a completed replace as failed and drive the caller to retry into
		// an EEXIST. Worst case a redundant hardlink to the same inode lingers in
		// the dir; it never touches newPath. Mirrors the best-effort temp cleanup
		// in replaceFileFrom's defer and the dir-fsync above.
		_ = os.Remove(oldPath)
		return nil
	}
	return fmt.Errorf("rename %s -> %s (no-replace): %w", oldPath, newPath, err)
}
