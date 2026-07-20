//go:build linux

package fsafe

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// AC-10 / AC-12: the streaming replace core — random-named O_EXCL temp
// reopened O_NOFOLLOW, io.Copy (bounded memory), fsync, atomic rename; a
// planted symlink at the destination is REPLACED by the rename, never
// followed; a mid-stream error leaves the original untouched and no temp
// litter behind.

func TestReplaceFileFrom_WritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.conf")
	if err := replaceFileFrom(path, strings.NewReader("key=value\n"), 0o600, true); err != nil {
		t.Fatalf("replaceFileFrom: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "key=value\n" {
		t.Errorf("content = %q, want %q", got, "key=value\n")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %#o, want 0600 (applied before the file is reachable by name)", info.Mode().Perm())
	}
}

type errReader struct {
	data io.Reader
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	n, err := r.data.Read(p)
	if err == io.EOF {
		return n, r.err
	}
	return n, err
}

func TestReplaceFileFrom_MidStreamErrorLeavesOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(path, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	boom := errors.New("stream failed")
	err := replaceFileFrom(path, &errReader{data: strings.NewReader("partial"), err: boom}, 0o644, true)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the stream error surfaced", err)
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "original\n" {
		t.Errorf("original clobbered: content = %q", got)
	}

	entries, globErr := filepath.Glob(filepath.Join(dir, ".*tmp*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(entries) != 0 {
		t.Errorf("temp litter left behind after failure: %v", entries)
	}
}

func TestReplaceFileFrom_SwapReplacesPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("victim-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "target")
	// The attacker plants a symlink at the destination before the swap: the
	// rename must REPLACE the symlink (mv -T semantics), never follow it.
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}

	if err := replaceFileFrom(path, strings.NewReader("new\n"), 0o644, true); err != nil {
		t.Fatalf("replaceFileFrom over planted symlink: %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("destination is still a symlink after the swap")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "victim-content\n" {
		t.Errorf("victim written through the planted symlink: %q", got)
	}
}

func TestReplaceFileFrom_NoClobberRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "present")
	if err := os.WriteFile(path, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFileFrom(path, strings.NewReader("new\n"), 0o644, false); err == nil {
		t.Fatal("no-clobber replace over an existing file succeeded, want refusal")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep\n" {
		t.Errorf("existing file changed by refused replace: %q", got)
	}
}

// The pre-RENAME_NOREPLACE fallback (old kernel / FS without the flag) must
// still enforce no-clobber atomically. Forcing renameat2 to ENOSYS drives the
// fallback; os.Link fails EEXIST on an existing target and never renames over
// it — closing the check-then-rename TOCTOU the old Lstat-then-rename fallback
// carried (CR round 6). Red-first: replacing the link with a plain os.Rename
// clobbers "keep" with "new" and this test fails.
func TestSafeRename_NoReplaceFallbackDoesNotClobber(t *testing.T) {
	orig := renameat2
	renameat2 = func(_, _ string, _ uint) error { return syscall.ENOSYS }
	t.Cleanup(func() { renameat2 = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "present")
	if err := os.WriteFile(path, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := replaceFileFrom(path, strings.NewReader("new\n"), 0o644, false)
	if err == nil {
		t.Fatal("no-clobber fallback overwrote an existing target, want EEXIST")
	}
	if !errors.Is(err, syscall.EEXIST) {
		t.Errorf("err = %v, want EEXIST from the atomic os.Link fallback", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "keep\n" {
		t.Errorf("existing file changed by the no-clobber fallback: %q", got)
	}
	// No temp litter left behind on the refusal.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "present" {
		t.Errorf("directory left with unexpected entries after refusal: %v", entries)
	}
}

// patternReader yields n bytes of a repeating pattern without materializing
// them — the AC-12 streaming source.
type patternReader struct {
	n   int64
	off int64
}

func (r *patternReader) Read(p []byte) (int, error) {
	if r.off >= r.n {
		return 0, io.EOF
	}
	max := int64(len(p))
	if rem := r.n - r.off; rem < max {
		max = rem
	}
	for i := int64(0); i < max; i++ {
		p[i] = byte('a' + (r.off+i)%26)
	}
	r.off += max
	return int(max), nil
}

func TestReplaceFileFrom_LargeContentStreams(t *testing.T) {
	const size = 64 << 20 // 64 MiB — far beyond any full-content buffer a caller should hold
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")
	if err := replaceFileFrom(path, &patternReader{n: size}, 0o644, true); err != nil {
		t.Fatalf("replaceFileFrom(64 MiB): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != size {
		t.Fatalf("size = %d, want %d", info.Size(), size)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 26)
	if _, err := io.ReadFull(f, head); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(head, []byte("abcdefghijklmnopqrstuvwxyz")) {
		t.Errorf("head = %q, want the pattern start", head)
	}
}

func TestSafeRename_NoReplaceRefusesPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "tmpfile")
	if err := os.WriteFile(oldPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("v"), 0o644); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(dir, "dest")
	if err := os.Symlink(victim, newPath); err != nil {
		t.Fatal(err)
	}
	if err := safeRename(oldPath, newPath, false); err == nil {
		t.Fatal("no-replace rename over a planted symlink succeeded, want EEXIST-class refusal")
	}
	if fi, err := os.Lstat(newPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("planted symlink disturbed by a refused rename (err=%v)", err)
	}
}
