package fsafe

import (
	"path/filepath"
	"strings"
)

// protectedExact are directories whose EXACT path is never a mutation target.
// Children may be: config files in /etc, app data under /srv, /opt, /var.
var protectedExact = map[string]bool{
	"/":      true,
	"/bin":   true,
	"/boot":  true,
	"/dev":   true,
	"/etc":   true,
	"/home":  true,
	"/lib":   true,
	"/lib64": true,
	"/media": true,
	"/mnt":   true,
	"/opt":   true,
	"/proc":  true,
	"/root":  true,
	"/run":   true,
	"/sbin":  true,
	"/srv":   true,
	"/sys":   true,
	"/tmp":   true,
	"/usr":   true,
	"/var":   true,
}

// protectedPrefixes are subtrees where the root AND every descendant are
// refused for subtree-level mutation (RemoveDir, Mkdir, recursive ownership):
// system binaries, boot chain, device/kernel trees, credentials and home
// directories, service state under /var/lib. Deliberately NOT here: /var/log,
// /var/cache, /srv, /opt, /tmp children — managed app data must stay mutable.
var protectedPrefixes = []string{
	"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
	"/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var/lib",
}

// IsProtectedPath reports whether the cleaned path IS a protected directory
// itself (exact match only — children are governed by the prefix rules).
func IsProtectedPath(path string) bool {
	return protectedExact[filepath.Clean(path)]
}

// IsUnderProtectedPrefix reports whether the cleaned path is a protected
// directory or sits anywhere under a protected subtree prefix. Purely
// lexical — see ResolvesUnderProtectedPrefix for the symlink-aware form.
func IsUnderProtectedPrefix(path string) bool {
	p := filepath.Clean(path)
	if !filepath.IsAbs(p) {
		// A relative path cannot be classified against absolute prefixes; a
		// deny predicate must fail closed rather than read it as safe. The
		// Manager always resolves to absolute first, but the predicate must
		// not depend on that.
		return true
	}
	if protectedExact[p] {
		return true
	}
	for _, prefix := range protectedPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// ResolvesUnderProtectedPrefix is the [SDK-8] check: the path's existing
// ancestor chain is symlink-resolved first, so a path SPELLED innocently but
// RESOLVING into a protected subtree is still caught. A path that cannot be
// resolved reports (true, err) — fail closed.
func ResolvesUnderProtectedPrefix(path string) (bool, error) {
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return true, err
	}
	return IsUnderProtectedPrefix(resolved), nil
}
