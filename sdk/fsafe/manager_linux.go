//go:build linux

package fsafe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
)

// Manager is the privileged-filesystem capability over an exec.Runner: on
// the Direct backend it uses this package's fd-anchored primitives; on
// Sudo/Doas every operation becomes exact, injection-safe argv through the
// runner ([SDK-7..9]).
type Manager struct{ r pmexec.Runner }

// New builds a Manager. A nil runner is refused — there is no default
// escalation path to fall back to.
func New(r pmexec.Runner) (Manager, error) {
	if r == nil {
		return Manager{}, fmt.Errorf("fsafe: %w", pmexec.ErrRunnerRequired)
	}
	return Manager{r: r}, nil
}

func (m Manager) direct() bool { return m.r.Backend() == pmexec.Direct }

// run executes one escalated command. On Direct the runner performs a bare
// invocation (Escalate is a no-op there), so every fsafe operation carries
// the flag unconditionally.
func (m Manager) run(ctx context.Context, name string, args ...string) (pmexec.Result, error) {
	return m.r.Run(ctx, pmexec.Command{Name: name, Args: args, Escalate: true})
}

func cmdErr(name string, res pmexec.Result) error {
	return &pmexec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
}

// isENOENTStderr recognises the C-locale ENOENT diagnostic by suffix. Stable
// because the runner forces a deterministic child environment ([SDK-5]).
func isENOENTStderr(stderr string) bool {
	return strings.HasSuffix(strings.TrimSpace(stderr), "No such file or directory")
}

// ReadFile returns the file's content. Absent is fs.ErrNotExist — never a
// silent empty result; an existing empty file is (nil, nil).
func (m Manager) ReadFile(ctx context.Context, path string) ([]byte, error) {
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return nil, err
	}
	if m.direct() {
		// No-follow read, matching the direct-backend mutators: a symlink
		// swapped in at the resolved path after resolution is refused (ELOOP)
		// rather than followed, so this privileged read cannot be redirected to
		// an arbitrary target; O_NONBLOCK + the IsRegular check keep a planted
		// FIFO from hanging the open and refuse every non-regular type.
		f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }() // read-only fd
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("read %s: not a regular file (%v)", path, info.Mode().Type())
		}
		b, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, nil
		}
		return b, nil
	}
	res, err := m.run(ctx, "cat", "--", resolved)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		if isENOENTStderr(res.Stderr) {
			return nil, fmt.Errorf("read %s: %w", path, fs.ErrNotExist)
		}
		return nil, cmdErr("cat", res)
	}
	if res.Stdout == "" {
		return nil, nil
	}
	return []byte(res.Stdout), nil
}

// WriteFile atomically replaces path with data.
func (m Manager) WriteFile(ctx context.Context, path string, data []byte, opts WriteOptions) error {
	return m.WriteFileFrom(ctx, path, bytes.NewReader(data), opts)
}

// WriteFileFrom atomically replaces path with the bytes streamed from src —
// the content is never buffered whole (AC-12). Mode 0 defaults to 0644;
// setuid/setgid are refused before any effect.
func (m Manager) WriteFileFrom(ctx context.Context, path string, src io.Reader, opts WriteOptions) error {
	mode := opts.Mode
	if mode == 0 {
		mode = 0o644
	}
	if err := validateMode(mode); err != nil {
		return err
	}
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return err
	}
	var backup string
	if opts.Backup != "" {
		// Deliberately NOT ResolveAndValidatePath: the backup is a create, and
		// resolving would FOLLOW a planted final symlink (backup -> /etc/shadow)
		// before the write ever ran. Keep the literal path — its parent-dir safety
		// (vetted root-owned on BOTH backends) plus the atomic replace are what
		// protect it.
		if err := ValidatePath(opts.Backup); err != nil {
			return err
		}
		if !filepath.IsAbs(opts.Backup) {
			return fmt.Errorf("%w: backup %q is not absolute", ErrInvalidPath, opts.Backup)
		}
		backup = filepath.Clean(opts.Backup)
		if backup == resolved || backup == filepath.Clean(path) {
			return fmt.Errorf("%w: backup path equals the target", ErrInvalidPath)
		}
	}
	if m.direct() {
		return m.writeFileFromDirect(resolved, src, mode, opts, backup)
	}
	return m.writeFileFromEscalated(ctx, resolved, src, mode, opts, backup)
}

func (m Manager) writeFileFromDirect(resolved string, src io.Reader, mode os.FileMode, opts WriteOptions, backup string) error {
	// [SDK-7]: parent-dir safety before EVERY mutation, on BOTH backends. The
	// direct backend is already root (see exec.Direct), so replaceFileFrom's
	// random O_EXCL temp + rename races the same TOCTOU the escalated write vets:
	// an attacker who can write the target directory can unlink our temp and
	// replant that name as a symlink between CreateTemp and the rename, so the
	// rename publishes the attacker-controlled entry. A root-owned,
	// non-group/other-writable parent forecloses that — the attacker cannot touch
	// entries in a directory they cannot write. The backup is a mutation too, so
	// its parent is vetted before the backup replace below.
	if err := parentDirSafe(filepath.Dir(resolved)); err != nil {
		return err
	}
	if backup != "" {
		if err := parentDirSafe(filepath.Dir(backup)); err != nil {
			return err
		}
	}
	if backup != "" {
		// Stream the existing target fd->temp->backup (bounded memory, AC-12):
		// open no-follow read-only, preserve its mode, and let replaceFileFrom's
		// random-temp atomic replace write the backup — its now-vetted root-owned
		// parent blocks the temp-republish race, and the rename replaces any
		// planted symlink ENTRY at the backup path rather than following it.
		// O_NONBLOCK so a FIFO planted at the target path returns immediately
		// instead of hanging the open until a writer appears (matching
		// FchownNoFollow/SetMode); a non-regular target is then refused before
		// streaming so we only ever copy real file bytes into the backup.
		f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		switch {
		case err == nil:
			info, ierr := f.Stat()
			if ierr != nil {
				_ = f.Close()
				return fmt.Errorf("backup %s: %w", resolved, ierr)
			}
			if !info.Mode().IsRegular() {
				_ = f.Close()
				return fmt.Errorf("backup %s: target is not a regular file", resolved)
			}
			berr := replaceFileFrom(backup, f, info.Mode().Perm(), true)
			_ = f.Close() // read-only fd
			if berr != nil {
				return fmt.Errorf("backup %s: %w", resolved, berr)
			}
		case errors.Is(err, fs.ErrNotExist):
			// nothing to back up
		default:
			return fmt.Errorf("backup %s: %w", resolved, err)
		}
	}
	if err := replaceFileFrom(resolved, src, mode, true); err != nil {
		return err
	}
	if opts.Owner != "" || opts.Group != "" {
		uid, gid, err := ResolveOwnership(opts.Owner, opts.Group)
		if err != nil {
			return err
		}
		return FchownNoFollow(resolved, uid, gid)
	}
	return nil
}

// escalatedWriteScript is the single-root-shell write: everything after the
// unprivileged parent-safety check happens inside ONE escalated sh -c —
// backup, mktemp in the target directory, content via stdin, chmod/chown on
// the temp, atomic mv -T — so no second escalation opens a check/effect
// window. Positional: $1 target, $2 octal mode, $3 owner[:group] (may be
// empty), $4 backup path (may be empty).
const escalatedWriteScript = `set -eu
target=$1
mode=$2
owner=$3
backup=$4
dir=$(dirname -- "$target")
if [ -n "$backup" ]; then
  # Defense in depth (the parents are already vetted root-owned in Go): never
  # let cp follow a symlink planted at either the backup OR the target path
  # into an arbitrary root file. A symlink at $target would make cp copy the
  # referent content (e.g. /etc/shadow) into the backup — the escalated
  # parity of the direct backend's O_NOFOLLOW target open. -T keeps $backup a
  # plain file even if an existing directory sits at that name.
  if [ -L "$backup" ]; then
    echo "fsafe: backup path is a symlink, refusing" >&2
    exit 1
  fi
  if [ -L "$target" ]; then
    echo "fsafe: target is a symlink, refusing to back it up through the link" >&2
    exit 1
  fi
  if [ -e "$target" ]; then
    cp -p -T -- "$target" "$backup"
  fi
fi
tmp=$(mktemp "$dir/.pm-XXXXXXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod -- "$mode" "$tmp"
if [ -n "$owner" ]; then
  chown -- "$owner" "$tmp"
fi
mv -T -- "$tmp" "$target"
`

func (m Manager) writeFileFromEscalated(ctx context.Context, resolved string, src io.Reader, mode os.FileMode, opts WriteOptions, backup string) error {
	if err := parentDirSafe(filepath.Dir(resolved)); err != nil {
		return err
	}
	// [SDK-7]: parent-dir safety before EVERY mutation. The backup write is a
	// mutation too — its parent must be root-owned and non-writable so an
	// attacker cannot plant or swap a symlink there for the escalated cp to
	// follow into an arbitrary root file.
	if backup != "" {
		if err := parentDirSafe(filepath.Dir(backup)); err != nil {
			return err
		}
	}
	res, err := m.r.Run(ctx, pmexec.Command{
		Name:     "sh",
		Args:     []string{"-c", escalatedWriteScript, "sh", resolved, modeArg(mode), Ownership(opts.Owner, opts.Group), backup},
		Stdin:    src,
		Escalate: true,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("sh", res)
	}
	return nil
}

// parentDirSafe refuses a privileged mutation whose parent directory a
// less-privileged actor could manipulate between check and effect ([SDK-7]:
// parent-dir safety before EVERY mutation): the parent must be root-owned and
// not group/other-writable. Applied to every shell-out mutator on BOTH
// backends — the escalated tier runs the mutation as root via sudo (this check
// is unprivileged, before sudo), and the Direct tier IS already root (see
// exec.Direct), so a writable parent races a root create/chmod/chown/cp on
// both. The remaining fd-anchored Direct mutators (SetMode/SetOwnership/Remove
// no-follow) close the same race by construction and skip this check; the
// Direct WriteFile path is NOT fd-anchored (random-temp CreateTemp + rename),
// so it vets the parent here just like the escalated tier.
//
// The sticky bit is NOT an exemption. Sticky (e.g. /tmp's 1777) only stops an
// unprivileged co-tenant from unlinking or renaming ANOTHER user's EXISTING
// entry; it does nothing to stop them creating a NEW name — a planted symlink —
// at a target that does not exist yet, which the privileged cp/mv would then
// act through ([SDK-7]: "Symlink TOCTOU"). Any writable parent fails closed.
func parentDirSafe(dir string) error {
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return fmt.Errorf("stat parent %s: %w", dir, err)
	}
	if st.Uid != 0 || st.Mode&0o022 != 0 {
		return fmt.Errorf("%w: %s", ErrUnsafeParentDir, dir)
	}
	return nil
}

// createAnchorSafe verifies the deepest EXISTING ancestor of a privileged
// create (mkdir, mkdir -p, cp -a subtree, cp to a new file) is root-owned and
// non-writable, so an attacker cannot redirect the resolved path by planting a
// symlink at the first not-yet-existing name between this check and the
// privileged create. For a non-recursive create the anchor is the immediate
// parent; for `mkdir -p` it is wherever the new chain attaches to the existing
// tree. A safe anchor is non-writable, so the attacker cannot inject anything
// BENEATH it — every component the privileged create then makes is root-owned
// by construction. (Its guarantee is exactly "no injection beneath the deepest
// existing ancestor"; an existing ancestor ABOVE the anchor is not re-checked,
// the same single-level ceiling parentDirSafe has on the write path.)
func createAnchorSafe(path string) error {
	dir := filepath.Dir(path)
	for {
		err := parentDirSafe(dir)
		if err == nil {
			return nil
		}
		// Walk up ONLY past a not-yet-existing ancestor. An existing-but-unsafe
		// ancestor, or any other stat failure, fails closed here.
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir { // reached "/" without an existing anchor
			return err
		}
		dir = parent
	}
}

// ReadDir lists a directory. Entries report their OWN type (a symlink is
// never reported as its target); a missing directory is fs.ErrNotExist and a
// non-directory is an error — never a silent empty list.
func (m Manager) ReadDir(ctx context.Context, path string) ([]DirEntry, error) {
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return nil, err
	}
	if m.direct() {
		// No-follow dir open (OpenRealDir = O_DIRECTORY|O_NOFOLLOW): a symlink
		// swapped in at the resolved path after resolution is refused (ELOOP)
		// rather than followed, so this privileged listing cannot be redirected
		// to an arbitrary directory. Entries still report their OWN type.
		f, err := OpenRealDir(resolved)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }() // read-only dir fd
		entries, err := f.ReadDir(-1)
		if err != nil {
			return nil, err
		}
		out := make([]DirEntry, 0, len(entries))
		for _, e := range entries {
			out = append(out, DirEntry{Name: e.Name(), IsDir: e.IsDir()})
		}
		return out, nil
	}
	// The trailing slash is load-bearing: it makes find fail on a
	// non-directory instead of listing the file itself. Records are
	// newline-delimited — a NUL delimiter cannot be used: a literal NUL in the
	// argv makes Go's exec reject the command (EINVAL), and the runner's
	// stdout capture is line-oriented. A newline embedded in a filename cannot
	// forge a phantom entry: every record must be `<type>/<basename>` and a
	// basename never contains '/', so any post-newline segment fails the
	// rec[1] != '/' check below and the whole listing fails closed rather than
	// yielding a spoofed entry.
	res, err := m.run(ctx, "find", resolved+"/", "-maxdepth", "1", "-mindepth", "1", "-printf", "%y/%f\n")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		if isENOENTStderr(res.Stderr) {
			return nil, fmt.Errorf("read dir %s: %w", path, fs.ErrNotExist)
		}
		return nil, cmdErr("find", res)
	}
	var out []DirEntry
	for _, rec := range strings.Split(res.Stdout, "\n") {
		if rec == "" {
			continue
		}
		// %y/%f: one type character, '/', then the basename (which never
		// contains '/') — split on the first slash.
		if len(rec) < 2 || rec[1] != '/' {
			return nil, fmt.Errorf("read dir %s: unparseable find output record %q", path, rec)
		}
		out = append(out, DirEntry{Name: rec[2:], IsDir: rec[0] == 'd'})
	}
	return out, nil
}

// existsPredicate is the escalated no-follow existence test. Bare `test -e`
// dereferences a symlink and would report a dangling symlink absent, diverging
// from the direct backend's os.Lstat — the `|| -L` arm restores parity. $1 is
// positional (never interpolated) so the path stays injection-safe.
const existsPredicate = `[ -e "$1" ] || [ -L "$1" ]`

// Exists reports whether an entry is present at path WITHOUT following a
// symlink leaf, so a dangling symlink counts as existing on both backends: the
// direct backend uses os.Lstat, and the escalated backend uses
// `[ -e "$1" ] || [ -L "$1" ]` — bare `test -e` derefs and would wrongly report
// a dangling symlink absent, diverging from Lstat. A runner failure surfaces as
// an error — never a silent false.
func (m Manager) Exists(ctx context.Context, path string) (bool, error) {
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return false, err
	}
	if m.direct() {
		if _, err := os.Lstat(resolved); err == nil {
			return true, nil
		} else if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		} else {
			return false, err
		}
	}
	// Positional $1 (not interpolated) keeps the path injection-safe; the `|| -L`
	// arm restores Lstat parity for a dangling symlink.
	res, err := m.run(ctx, "sh", "-c", existsPredicate, "sh", resolved)
	if err != nil {
		return false, err
	}
	switch res.ExitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, cmdErr("sh", res)
	}
}

// Mkdir creates a directory. Creation under a protected prefix is refused —
// the create side of [SDK-8] — with symlink resolution part of the check. The
// parent is vetted root-owned before the create ([SDK-7]) so a writable parent
// cannot redirect the resolved path between check and the privileged create.
// Recorded ceiling (parity with Copy/CopyTree/SetOwnershipRecursive): always
// shells `mkdir` — there is no fd-anchored mkdirat primitive in M3, so the
// create is not fd-anchored on EITHER backend (both run as root: escalated via
// sudo, Direct is already root), which is exactly why the anchor-safety check
// applies to both rather than an fd handle.
func (m Manager) Mkdir(ctx context.Context, path string, opts MkdirOptions) error {
	if opts.Mode != 0 {
		if err := validateMode(opts.Mode); err != nil {
			return err
		}
	}
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return err
	}
	if IsUnderProtectedPrefix(resolved) {
		return fmt.Errorf("%w: mkdir %s", ErrProtectedTarget, path)
	}
	if err := createAnchorSafe(resolved); err != nil {
		return err
	}
	// Fold the mode into the create (`mkdir -m`) so the new directory never
	// exists with a laxer umask-derived mode in a window between two escalated
	// calls. Ownership stays a following chown — the residual window has the
	// dir owned by root (the escalated uid), which is more restrictive than
	// the target owner, so it is fail-safe, not a downgrade.
	args := []string{"--", resolved}
	if opts.Mode != 0 {
		args = append([]string{"-m", modeArg(opts.Mode)}, args...)
	}
	if opts.Recursive {
		args = append([]string{"-p"}, args...)
	}
	res, err := m.run(ctx, "mkdir", args...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("mkdir", res)
	}
	if opts.Owner != "" || opts.Group != "" {
		return m.SetOwnership(ctx, resolved, opts.Owner, opts.Group)
	}
	return nil
}

// Remove deletes a single non-directory entry. Missing is success (rm -f
// semantics); a directory is refused — that is RemoveDir's job.
func (m Manager) Remove(ctx context.Context, path string) error {
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return err
	}
	if m.direct() {
		if info, lerr := os.Lstat(resolved); lerr == nil && info.IsDir() {
			return fmt.Errorf("remove %s: is a directory (use RemoveDir)", path)
		}
		if err := os.Remove(resolved); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	// [SDK-7] parent-dir safety before the escalated rm. rm unlinks a symlink
	// at the target rather than following it, but a writable parent still lets
	// a swapped non-final path component redirect the delete — vet the parent
	// root-owned so the entry cannot be swapped between check and effect.
	if err := parentDirSafe(filepath.Dir(resolved)); err != nil {
		return err
	}
	res, err := m.run(ctx, "rm", "-f", "--", resolved)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("rm", res)
	}
	return nil
}

// RemoveDir deletes a directory tree. Protected prefixes are refused with
// symlink resolution part of the check ([SDK-8]); the operation itself uses
// the ORIGINAL spelling, so on the direct backend the fd-anchored walk
// refuses a symlink leaf instead of deleting whatever it points at.
//
// Recorded ceiling (parity with Copy/CopyTree/SetOwnershipRecursive): the
// escalated backend shells `rm -rf` rather than the fd-anchored removeDirSecure
// walk — fds cannot be held across the sudo boundary without a privileged
// helper binary, which is out of M3 scope. The residual TOCTOU-on-ancestor gap
// versus the direct tier is bounded by three in-tier mitigations: the
// symlink-resolving protected-prefix guard refuses protected trees BEFORE the
// rm (fail closed), `rm -r` unlinks a symlink encountered during recursion
// rather than following it, and the cleaned original spelling (no trailing
// slash) plus argv `--` keep the target literal and injection-safe. Upgrade
// path: embed removeDirSecure in a root helper when the escalated tier must
// fd-anchor.
//
// Deliberately excluded from the round-5 parentDirSafe sweep that guards the
// existing-target mutators (SetMode/SetOwnership/SetOwnershipRecursive/Remove/
// Copy): unlike chmod/chown/cp, `rm -rf` unlinks a command-line symlink arg
// rather than dereferencing it, and the symlink-resolving protected-prefix guard
// already runs before the delete — the three mitigations above cover the
// escalated tier, so an immediate-parent vet would add no protection `rm` does
// not already have. A parent vet here would also refuse legitimate deletions of
// trees under an app-owned (non-root) parent, a behavior change out of scope for
// a review round.
func (m Manager) RemoveDir(ctx context.Context, path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	p := filepath.Clean(path)
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%w: %q is not absolute", ErrInvalidPath, path)
	}
	under, err := ResolvesUnderProtectedPrefix(p)
	if err != nil {
		return err
	}
	if under {
		return fmt.Errorf("%w: remove %s", ErrProtectedTarget, path)
	}
	if m.direct() {
		return removeDirSecure(p)
	}
	res, err := m.run(ctx, "rm", "-rf", "--", p)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("rm", res)
	}
	return nil
}

// Copy copies one file. Like WriteFile's target, the destination is deliberately
// NOT protected-prefix guarded (single-file config writes under /etc are the
// point) and NOT symlink-resolved (resolving would FOLLOW a planted dst symlink
// before the copy) — but it still gets [SDK-7] parent-dir safety on BOTH
// backends. `cp --remove-destination` unlinks dst before copying, so a symlink
// planted at dst is removed rather than followed into an arbitrary root file
// (GNU cp otherwise follows a dst symlink to an existing regular file); with the
// parent vetted root-owned, an attacker cannot plant that symlink in the first
// place. Recorded ceiling: shells cp on every backend — there is no fd-anchored
// copy primitive.
func (m Manager) Copy(ctx context.Context, src, dst string) error {
	if err := ValidatePath(src); err != nil {
		return err
	}
	if err := ValidatePath(dst); err != nil {
		return err
	}
	cleanDst := filepath.Clean(dst)
	if !filepath.IsAbs(cleanDst) {
		return fmt.Errorf("%w: dst %q is not absolute", ErrInvalidPath, dst)
	}
	if err := parentDirSafe(filepath.Dir(cleanDst)); err != nil {
		return err
	}
	res, err := m.run(ctx, "cp", "--remove-destination", "--", src, cleanDst)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("cp", res)
	}
	return nil
}

// CopyTree copies a directory tree (cp -a -T: preserve, no nested-dir
// surprise when dst exists). A tree copy CREATES a subtree at dst — the
// create side of [SDK-8] — so a protected-prefix destination is refused, with
// symlink resolution part of the check (like Mkdir). Single-file Copy is
// deliberately NOT guarded: it is governed by higher-layer policy, in parity
// with WriteFile whose purpose is writing single config files under /etc.
// Recorded ceiling: shells cp on all backends.
func (m Manager) CopyTree(ctx context.Context, src, dst string) error {
	if err := ValidatePath(src); err != nil {
		return err
	}
	resolvedDst, err := ResolveAndValidatePath(dst)
	if err != nil {
		return err
	}
	if IsUnderProtectedPrefix(resolvedDst) {
		return fmt.Errorf("%w: copy tree to %s", ErrProtectedTarget, dst)
	}
	// Create-mutation ([SDK-7]): vet the destination parent on BOTH backends so
	// a writable parent cannot redirect the resolved dst between check and the
	// privileged cp — Direct is already root, so it races the same as escalated.
	if err := createAnchorSafe(resolvedDst); err != nil {
		return err
	}
	res, err := m.run(ctx, "cp", "-a", "-T", "--", src, resolvedDst)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("cp", res)
	}
	return nil
}

// SetMode changes permission bits. setuid/setgid are refused before any
// effect; on the direct backend the chmod goes through a no-follow fd.
func (m Manager) SetMode(ctx context.Context, path string, mode os.FileMode) error {
	if err := validateMode(mode); err != nil {
		return err
	}
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return err
	}
	if m.direct() {
		f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s without following links: %w", resolved, err)
		}
		defer func() { _ = f.Close() }() // read-only fd
		if err := f.Chmod(mode); err != nil {
			return fmt.Errorf("chmod %s: %w", resolved, err)
		}
		return nil
	}
	// Escalated chmod follows a symlink at the target (there is no no-follow
	// chmod) — vet the parent root-owned so it cannot be swapped for a link to
	// an arbitrary root file between check and effect ([SDK-7]).
	if err := parentDirSafe(filepath.Dir(resolved)); err != nil {
		return err
	}
	res, err := m.run(ctx, "chmod", modeArg(mode), "--", resolved)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("chmod", res)
	}
	return nil
}

// SetOwnership changes owner/group of a single entry. Both empty is a no-op.
func (m Manager) SetOwnership(ctx context.Context, path, owner, group string) error {
	if owner == "" && group == "" {
		return nil
	}
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return err
	}
	if m.direct() {
		uid, gid, err := ResolveOwnership(owner, group)
		if err != nil {
			return err
		}
		info, err := os.Lstat(resolved)
		if err != nil {
			return err
		}
		if info.IsDir() {
			f, err := OpenRealDir(resolved)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }() // read-only dir fd
			if err := f.Chown(uid, gid); err != nil {
				return fmt.Errorf("chown %s: %w", resolved, err)
			}
			return nil
		}
		return FchownNoFollow(resolved, uid, gid)
	}
	// Escalated chown dereferences a symlink at the target — vet the parent
	// root-owned so it cannot be swapped between check and effect ([SDK-7]).
	if err := parentDirSafe(filepath.Dir(resolved)); err != nil {
		return err
	}
	res, err := m.run(ctx, "chown", Ownership(owner, group), "--", resolved)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("chown", res)
	}
	return nil
}

// SetOwnershipRecursive chowns a whole tree. A protected subtree is refused
// like RemoveDir — a recursive ownership change is a subtree-wide mutation.
// Recorded ceiling: shells chown -R on every backend.
func (m Manager) SetOwnershipRecursive(ctx context.Context, path, owner, group string) error {
	if owner == "" && group == "" {
		return nil
	}
	resolved, err := ResolveAndValidatePath(path)
	if err != nil {
		return err
	}
	if IsUnderProtectedPrefix(resolved) {
		return fmt.Errorf("%w: recursive chown %s", ErrProtectedTarget, path)
	}
	// chown -R dereferences its top-level target argument on every backend
	// (Direct is already root, so it races the same as escalated) — vet the
	// parent root-owned so the tree root cannot be swapped for a symlink
	// between check and the privileged recursive chown ([SDK-7]).
	if err := parentDirSafe(filepath.Dir(resolved)); err != nil {
		return err
	}
	res, err := m.run(ctx, "chown", "-R", Ownership(owner, group), "--", resolved)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("chown", res)
	}
	return nil
}
