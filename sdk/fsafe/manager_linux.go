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
		b, err := os.ReadFile(resolved)
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
		// before the write ever ran. Keep the literal path — its parent safety
		// (escalated) and no-follow atomic replace (direct) are what protect it.
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
	if backup != "" {
		// Stream the existing target fd->temp->backup (bounded memory, AC-12):
		// open no-follow read-only, preserve its mode, and let replaceFileFrom's
		// no-follow atomic swap write the backup — a planted symlink at the
		// backup path is replaced, never followed.
		f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		switch {
		case err == nil:
			bmode := mode
			if info, ierr := f.Stat(); ierr == nil {
				bmode = info.Mode().Perm()
			}
			berr := replaceFileFrom(backup, f, bmode, true)
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
  # Defense in depth (the parent is already vetted root-owned in Go): never
  # let cp follow a symlink planted at the backup path into a root file.
  if [ -L "$backup" ]; then
    echo "fsafe: backup path is a symlink, refusing" >&2
    exit 1
  fi
  if [ -e "$target" ]; then
    cp -p -- "$target" "$backup"
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
	if err := escalatedParentSafe(filepath.Dir(resolved)); err != nil {
		return err
	}
	// [SDK-7]: parent-dir safety before EVERY mutation. The backup write is a
	// mutation too — its parent must be root-owned and non-writable so an
	// attacker cannot plant or swap a symlink there for the escalated cp to
	// follow into an arbitrary root file.
	if backup != "" {
		if err := escalatedParentSafe(filepath.Dir(backup)); err != nil {
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

// escalatedParentSafe refuses an escalated write whose parent directory an
// unprivileged user could manipulate between check and effect: the parent
// must be root-owned and not group/other-writable (sticky excepted). Checked
// UNPRIVILEGED, before sudo ever runs.
func escalatedParentSafe(dir string) error {
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return fmt.Errorf("stat parent %s: %w", dir, err)
	}
	perm := st.Mode & 0o7777
	sticky := perm&0o1000 != 0
	if st.Uid != 0 || (perm&0o022 != 0 && !sticky) {
		return fmt.Errorf("%w: %s", ErrUnsafeParentDir, dir)
	}
	return nil
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
		entries, err := os.ReadDir(resolved)
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
	// NUL-delimited (not newline): a basename can contain any byte except '/'
	// and NUL, so a filename with an embedded newline cannot spoof a phantom
	// entry.
	res, err := m.run(ctx, "find", resolved+"/", "-maxdepth", "1", "-mindepth", "1", "-printf", "%y/%f\x00")
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
	for _, rec := range strings.Split(res.Stdout, "\x00") {
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

// Exists reports whether path exists (without following a symlink leaf on
// the direct backend). A runner failure surfaces as an error — never a
// silent false.
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
	res, err := m.run(ctx, "test", "-e", resolved)
	if err != nil {
		return false, err
	}
	switch res.ExitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, cmdErr("test", res)
	}
}

// Mkdir creates a directory. Creation under a protected prefix is refused —
// the create side of [SDK-8] — with symlink resolution part of the check.
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

// Copy copies one file. Recorded ceiling: shells cp on every backend — there
// is no fd-anchored copy primitive, and the paths are validated argv.
func (m Manager) Copy(ctx context.Context, src, dst string) error {
	if err := ValidatePath(src); err != nil {
		return err
	}
	if err := ValidatePath(dst); err != nil {
		return err
	}
	res, err := m.run(ctx, "cp", "--", src, dst)
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
	res, err := m.run(ctx, "chown", "-R", Ownership(owner, group), "--", resolved)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("chown", res)
	}
	return nil
}
