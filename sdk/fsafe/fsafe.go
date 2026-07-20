// Package fsafe is the SDK's privileged-filesystem capability ([SDK-7..9],
// SPEC-004): fd-anchored, symlink-refusing mutations on the Direct backend
// and exact, injection-safe argv through the exec.Runner on Sudo/Doas —
// with protected-path prefixes refusing subtree-level mutation of system
// directories on every backend.
//
// It is mechanism, not policy: the protected-prefix set encodes "never let a
// managed mutation take out /etc or /usr as a subtree", while single-file
// config writes under those trees remain the package's core purpose.
package fsafe

import (
	"errors"
	"os"
)

// Sentinels, all errors.Is-matchable so callers can fail closed per cause.
var (
	// ErrInvalidPath rejects paths that must never reach a syscall or argv:
	// empty, NUL-bearing, leading-dash, or (where required) non-absolute.
	ErrInvalidPath = errors.New("fsafe: invalid path")

	// ErrUnsafeMode refuses modes carrying setuid or setgid — a managed
	// mutation must never mint a privileged executable.
	ErrUnsafeMode = errors.New("fsafe: unsafe mode (setuid/setgid refused)")

	// ErrUnsafeParentDir refuses an escalated write whose parent directory an
	// unprivileged user could manipulate between check and effect.
	ErrUnsafeParentDir = errors.New("fsafe: parent directory unsafe for escalated write")

	// ErrProtectedTarget refuses subtree-level mutation (create or delete) of
	// a protected system path ([SDK-8]).
	ErrProtectedTarget = errors.New("fsafe: protected path refused")
)

// WriteOptions parameterises WriteFile/WriteFileFrom.
type WriteOptions struct {
	Mode   os.FileMode // 0 means the deterministic default 0644
	Owner  string      // user name or numeric uid; "" leaves ownership alone
	Group  string      // group name or numeric gid; "" leaves group alone
	Backup string      // copy an existing target here before replacing; "" skips
}

// MkdirOptions parameterises Mkdir.
type MkdirOptions struct {
	Mode      os.FileMode // 0 means no explicit chmod after create
	Owner     string
	Group     string
	Recursive bool // mkdir -p semantics
}

// DirEntry is one ReadDir result. IsDir reports the entry's OWN type — a
// symlink is never reported with its target's type.
type DirEntry struct {
	Name  string
	IsDir bool
}
