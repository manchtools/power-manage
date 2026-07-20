//go:build linux

package fsafe

import (
	"fmt"
	"os"
	"syscall"
)

// dirOpenFlags opens a REAL directory or fails: O_NOFOLLOW turns a symlink
// into ELOOP and O_DIRECTORY turns anything else into ENOTDIR — the check and
// the handle are the same syscall, so there is no swap window.
const dirOpenFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// OpenRealDir opens path as a real directory, refusing a symlink or
// non-directory final component in the open itself ([SDK-7]).
func OpenRealDir(path string) (*os.File, error) {
	f, err := os.OpenFile(path, dirOpenFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("open real dir %s: %w", path, err)
	}
	return f, nil
}

// FchownNoFollow changes ownership of a REGULAR file through a held fd: the
// O_NOFOLLOW open refuses a planted symlink, O_NONBLOCK keeps a FIFO from
// hanging the open, and the IsRegular check then rejects every non-regular
// type. uid/gid -1 leave the respective id unchanged (chown(2) sentinel).
func FchownNoFollow(path string, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s without following links: %w", path, err)
	}
	defer func() { _ = f.Close() }() // read-only fd; close cannot lose data
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("chown %s: not a regular file (%v)", path, info.Mode().Type())
	}
	if err := f.Chown(uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

// SetDirPermissionsNoFollow applies mode (and, when not -1, ownership) to a
// real directory through a held fd — a symlinked directory is refused by the
// open itself.
func SetDirPermissionsNoFollow(path string, mode os.FileMode, uid, gid int) error {
	if err := validateMode(mode); err != nil {
		return err
	}
	f, err := OpenRealDir(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only dir fd
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if uid != -1 || gid != -1 {
		if err := f.Chown(uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	return nil
}
