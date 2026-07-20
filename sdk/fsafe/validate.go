package fsafe

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// ValidatePath is the chokepoint every operation calls before a path reaches
// a syscall or argv: empty, NUL-bearing, and leading-dash paths are refused.
// Deliberately minimal — absoluteness and protection rules are the caller's.
func ValidatePath(path string) error {
	switch {
	case path == "":
		return fmt.Errorf("%w: empty path", ErrInvalidPath)
	case strings.ContainsRune(path, 0):
		return fmt.Errorf("%w: path contains NUL", ErrInvalidPath)
	case strings.HasPrefix(path, "-"):
		return fmt.Errorf("%w: path starts with '-'", ErrInvalidPath)
	}
	return nil
}

// validateMode refuses setuid/setgid; sticky and plain permission bits pass.
func validateMode(mode os.FileMode) error {
	if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return fmt.Errorf("%w: %v", ErrUnsafeMode, mode)
	}
	return nil
}

// modeArg renders the 4-digit octal string chmod expects — the special bits
// sit in different positions in os.FileMode than in the unix mode word.
func modeArg(mode os.FileMode) string {
	bits := uint32(mode.Perm())
	if mode&os.ModeSticky != 0 {
		bits |= 0o1000
	}
	if mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&os.ModeSetuid != 0 {
		bits |= 0o4000
	}
	return fmt.Sprintf("%04o", bits)
}

// Ownership renders the chown owner[:group] argument. Empty parts collapse:
// ("", "") is "", ("", "g") is ":g" — chown's own grammar.
func Ownership(owner, group string) string {
	if group == "" {
		return owner
	}
	return owner + ":" + group
}

// ResolveAndValidatePath validates, requires an absolute path, resolves
// symlinks in the deepest EXISTING ancestor chain (so a symlinked directory
// cannot redirect a later mutation), and preserves any missing tail.
func ResolveAndValidatePath(path string) (string, error) {
	if err := ValidatePath(path); err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: %q is not absolute", ErrInvalidPath, path)
	}
	p := filepath.Clean(path)
	existing := p
	var tail []string
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolve %s: %w", path, err)
		}
		tail = append([]string{filepath.Base(existing)}, tail...)
		parent := filepath.Dir(existing)
		if parent == existing { // reached "/"
			break
		}
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	return filepath.Join(append([]string{resolved}, tail...)...), nil
}

// ResolveOwnership turns owner/group names (or numeric IDs) into a uid/gid
// pair for fchown. Empty means "leave unchanged" (-1, the chown(2) sentinel).
// An unresolvable name is an error naming it — callers must fail closed, not
// chown to something else.
func ResolveOwnership(owner, group string) (int, int, error) {
	uid := -1
	if owner != "" {
		n, err := strconv.Atoi(owner)
		if err != nil {
			u, lerr := user.Lookup(owner)
			if lerr != nil {
				return -1, -1, fmt.Errorf("resolve owner %q: %w", owner, lerr)
			}
			if n, err = strconv.Atoi(u.Uid); err != nil {
				return -1, -1, fmt.Errorf("resolve owner %q: non-numeric uid %q", owner, u.Uid)
			}
		}
		uid = n
	}
	gid := -1
	if group != "" {
		n, err := strconv.Atoi(group)
		if err != nil {
			g, lerr := user.LookupGroup(group)
			if lerr != nil {
				return -1, -1, fmt.Errorf("resolve group %q: %w", group, lerr)
			}
			if n, err = strconv.Atoi(g.Gid); err != nil {
				return -1, -1, fmt.Errorf("resolve group %q: non-numeric gid %q", group, g.Gid)
			}
		}
		gid = n
	}
	return uid, gid, nil
}
