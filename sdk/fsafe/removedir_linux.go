//go:build linux

package fsafe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openNoFollowChain opens path by walking every component from "/" with
// O_NOFOLLOW|O_DIRECTORY openat calls — no component anywhere in the chain
// may be a symlink, so a planted link cannot redirect the walk.
func openNoFollowChain(path string) (*os.File, error) {
	p := filepath.Clean(path)
	if !filepath.IsAbs(p) {
		return nil, fmt.Errorf("%w: %q is not absolute", ErrInvalidPath, path)
	}
	f, err := os.OpenFile("/", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /: %w", err)
	}
	if p == "/" {
		return f, nil
	}
	for _, comp := range strings.Split(p[1:], "/") {
		fd, err := syscall.Openat(int(f.Fd()), comp, dirOpenFlags, 0)
		_ = f.Close() // read-only dir fd, superseded by the child fd
		if err != nil {
			return nil, fmt.Errorf("open component %q of %s without following links: %w", comp, p, err)
		}
		f = os.NewFile(uintptr(fd), comp)
	}
	return f, nil
}

// removeDirSecure removes the directory tree at path with every step
// fd-anchored: symlinks anywhere in the chain refuse the walk, and symlink
// ENTRIES inside the tree are unlinked, never followed ([SDK-7]).
func removeDirSecure(path string) error {
	p := filepath.Clean(path)
	if p == "/" {
		return fmt.Errorf("%w: /", ErrProtectedTarget)
	}
	parent, err := openNoFollowChain(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }() // read-only dir fd
	return removeAtRecursive(int(parent.Fd()), filepath.Base(p))
}

// removeAtRecursive removes dirfd/name recursively. The no-follow directory
// open IS the type probe: ELOOP (symlink) and ENOTDIR (file, fifo, device)
// mean "unlink the entry itself"; only a real directory recurses. At the top
// of the recursion the same probe refuses a symlink or non-directory leaf.
func removeAtRecursive(dirfd int, name string) error {
	fd, err := syscall.Openat(dirfd, name, dirOpenFlags, 0)
	if err != nil {
		return fmt.Errorf("open %s as a real directory: %w", name, err)
	}
	d := os.NewFile(uintptr(fd), name)
	// ponytail: read ALL names for this ONE level, then delete — a per-level
	// bound (not cumulative across the tree). Deliberately not batched on this
	// fd: interleaving getdents with unlink on the SAME cursor can SKIP entries
	// on htree directories (ext4), leaving the tree non-empty so the final rmdir
	// fails ENOTEMPTY. Upgrade path if one directory can hold tens of millions
	// of entries: bound memory by RE-OPENING the dir per fixed-size batch
	// (os.RemoveAll's strategy) — never by batching reads on this same cursor.
	names, err := d.Readdirnames(-1)
	if err != nil {
		_ = d.Close() // read-only dir fd
		return fmt.Errorf("list %s: %w", name, err)
	}
	dfd := int(d.Fd())
	for _, child := range names {
		cfd, oerr := syscall.Openat(dfd, child, dirOpenFlags, 0)
		if oerr == nil {
			_ = syscall.Close(cfd) // probe fd only; the recursion reopens no-follow
			if rerr := removeAtRecursive(dfd, child); rerr != nil {
				_ = d.Close()
				return rerr
			}
			continue
		}
		if !errors.Is(oerr, syscall.ELOOP) && !errors.Is(oerr, syscall.ENOTDIR) {
			_ = d.Close()
			return fmt.Errorf("probe %s/%s: %w", name, child, oerr)
		}
		if uerr := unlinkatFlags(dfd, child, 0); uerr != nil {
			_ = d.Close()
			return fmt.Errorf("unlink %s/%s: %w", name, child, uerr)
		}
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := unlinkatFlags(dirfd, name, atRemoveDir); err != nil {
		return fmt.Errorf("rmdir %s: %w", name, err)
	}
	return nil
}
