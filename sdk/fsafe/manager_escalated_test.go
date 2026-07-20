//go:build linux

package fsafe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

// Escalated-backend tier (FakeRunner): the Manager's Sudo/Doas path builds
// exact, injection-safe argv and never touches the filesystem directly. These
// tests pin the command surface — the argv IS the trust boundary.

func newEscalatedManager(t *testing.T) (*exectest.FakeRunner, Manager) {
	t.Helper()
	fr := exectest.New(pmexec.Sudo)
	m, err := New(fr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return fr, m
}

func mustCalls(t *testing.T, fr *exectest.FakeRunner, want int) []pmexec.Command {
	t.Helper()
	calls := fr.Calls()
	if len(calls) != want {
		t.Fatalf("runner received %d calls, want %d: %+v", len(calls), want, calls)
	}
	return calls
}

// [SDK-9] escalated write: everything happens in ONE root shell — mktemp,
// cat > tmp, chmod, chown, mv -T — so there is no window between validation
// and effect that a second sudo invocation would open. Content travels via
// stdin, never argv.
func TestManager_WriteFile_Escalated_SingleRootShell(t *testing.T) {
	fr, m := newEscalatedManager(t)
	err := m.WriteFile(context.Background(), "/etc/pm-test.conf", []byte("secret=1\n"), WriteOptions{
		Mode:   0o600,
		Owner:  "root",
		Group:  "wheel",
		Backup: "/etc/pm-test.conf.bak",
	})
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	calls := mustCalls(t, fr, 1)
	c := calls[0]
	if c.Name != "sh" {
		t.Errorf("Name = %q, want sh", c.Name)
	}
	if !c.Escalate {
		t.Error("write command not escalated")
	}
	if len(c.Args) != 7 {
		t.Fatalf("Args = %q, want 7 elements [-c script sh path mode ownership backup]", c.Args)
	}
	if c.Args[0] != "-c" || c.Args[1] == "" || c.Args[2] != "sh" {
		t.Errorf("Args[0..2] = %q, want [-c <script> sh]", c.Args[:3])
	}
	if got, want := c.Args[3:], []string{"/etc/pm-test.conf", "0600", "root:wheel", "/etc/pm-test.conf.bak"}; !slices.Equal(got, want) {
		t.Errorf("positional args = %q, want %q", got, want)
	}
	if c.Stdin == nil {
		t.Fatal("content not delivered via stdin")
	}
	data, err := io.ReadAll(c.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "secret=1\n" {
		t.Errorf("stdin = %q, want the file content", data)
	}
	for _, a := range c.Args {
		if a == "secret=1\n" {
			t.Error("file content leaked into argv")
		}
	}
}

// The parent-directory safety check runs UNPRIVILEGED, before any sudo: a
// group/other-writable non-sticky parent means an attacker can swap the
// target between check and write, so the whole operation is refused with
// zero commands issued.
func TestManager_WriteFile_Escalated_UnsafeParentRefusedBeforeSudo(t *testing.T) {
	fr, m := newEscalatedManager(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	err := m.WriteFile(context.Background(), filepath.Join(dir, "target.conf"), []byte("x"), WriteOptions{})
	if !errors.Is(err, ErrUnsafeParentDir) {
		t.Fatalf("err = %v, want ErrUnsafeParentDir", err)
	}
	mustCalls(t, fr, 0)
}

// The backup destination is a mutation too ([SDK-7]: parent-dir safety
// before EVERY mutation). If only the target's parent is vetted, an attacker
// who controls the backup path's parent can plant a symlink at the backup so
// the escalated `cp` overwrites an arbitrary root file. The backup's parent
// must pass the same unprivileged root-owned check — before any sudo.
func TestManager_WriteFile_Escalated_UnsafeBackupParentRefused(t *testing.T) {
	fr, m := newEscalatedManager(t)
	attackerDir := t.TempDir()
	// World-writable so the parent reads as attacker-controlled regardless of
	// who runs the test: under root-run CI t.TempDir() is root-owned 0700 and
	// would otherwise pass the root-owned-non-writable check.
	if err := os.Chmod(attackerDir, 0o777); err != nil {
		t.Fatal(err)
	}
	err := m.WriteFile(context.Background(), "/etc/pm-test.conf", []byte("x"), WriteOptions{
		Backup: filepath.Join(attackerDir, "planted.bak"),
	})
	if !errors.Is(err, ErrUnsafeParentDir) {
		t.Fatalf("err = %v, want ErrUnsafeParentDir for an attacker-controlled backup parent", err)
	}
	mustCalls(t, fr, 0)
}

func TestManager_WriteFile_Escalated_SetuidRefusedBeforeSudo(t *testing.T) {
	fr, m := newEscalatedManager(t)
	err := m.WriteFile(context.Background(), "/etc/pm-test.conf", []byte("x"), WriteOptions{Mode: 0o755 | os.ModeSetuid})
	if !errors.Is(err, ErrUnsafeMode) {
		t.Fatalf("err = %v, want ErrUnsafeMode", err)
	}
	mustCalls(t, fr, 0)
}

func TestManager_ReadFile_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	fr.Push(pmexec.Result{ExitCode: 0, Stdout: "key=value\n"}, nil)
	got, err := m.ReadFile(context.Background(), "/etc/pm-test.conf")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "key=value\n" {
		t.Errorf("content = %q", got)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "cat" || !slices.Equal(c.Args, []string{"--", "/etc/pm-test.conf"}) {
		t.Errorf("argv = %s %q, want cat [-- /etc/pm-test.conf]", c.Name, c.Args)
	}
	if !c.Escalate {
		t.Error("read not escalated")
	}
}

// A non-zero cat exit whose stderr is the C-locale ENOENT message maps to
// fs.ErrNotExist; any other failure surfaces as a CommandError carrying the
// stderr — never silently empty.
func TestManager_ReadFile_Escalated_ENOENTMapsToNotExist(t *testing.T) {
	fr, m := newEscalatedManager(t)
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "cat: /etc/pm-missing.conf: No such file or directory\n"}, nil)
	_, err := m.ReadFile(context.Background(), "/etc/pm-missing.conf")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}

	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "cat: /etc/pm-test.conf: Permission denied\n"}, nil)
	_, err = m.ReadFile(context.Background(), "/etc/pm-test.conf")
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatal("permission failure misread as not-exist")
	}
	var ce *pmexec.CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *exec.CommandError", err)
	}
}

func TestManager_ReadFile_Escalated_EmptyIsNilNil(t *testing.T) {
	fr, m := newEscalatedManager(t)
	fr.Push(pmexec.Result{ExitCode: 0, Stdout: ""}, nil)
	got, err := m.ReadFile(context.Background(), "/etc/empty.conf")
	if err != nil || got != nil {
		t.Errorf("empty file = (%v, %v), want (nil, nil)", got, err)
	}
}

// ReadDir shells `find <path>/ -maxdepth 1 -mindepth 1 -printf '%y/%f\n'`.
// The trailing slash is load-bearing: it makes find fail on a non-directory
// instead of listing the file itself. The record delimiter is a newline, not
// NUL: a literal NUL in the argv makes Go's exec reject the command with
// EINVAL, so the FakeRunner argv is scanned for a NUL to prove the real
// invocation would start.
func TestManager_ReadDir_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	fr.Push(pmexec.Result{ExitCode: 0, Stdout: "d/sub\nf/file.txt\nl/link\n"}, nil)
	entries, err := m.ReadDir(context.Background(), "/etc/app.d")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "find" || !slices.Equal(c.Args, []string{"/etc/app.d/", "-maxdepth", "1", "-mindepth", "1", "-printf", "%y/%f\n"}) {
		t.Errorf("argv = %s %q", c.Name, c.Args)
	}
	// A literal NUL anywhere in the argv makes exec.Command fail (EINVAL) on a
	// real backend; the FakeRunner never execs, so scan the recorded argv to
	// catch an exec-invalid command that a stubbed runner would otherwise mask.
	for _, a := range c.Args {
		if strings.ContainsRune(a, 0) {
			t.Errorf("argv element %q contains a NUL byte — Go exec rejects it (EINVAL) on real backends", a)
		}
	}
	byName := map[string]bool{}
	for _, e := range entries {
		byName[e.Name] = e.IsDir
	}
	if len(byName) != 3 {
		t.Fatalf("entries = %+v, want 3", entries)
	}
	// Assert each expected name is PRESENT with the right type — a missing key
	// reads as false, so a bare `byName["file.txt"]` check passes even after
	// file.txt is dropped and replaced by an unexpected non-directory entry.
	if got, ok := byName["sub"]; !ok || !got {
		t.Errorf("missing or non-dir 'sub': %+v", entries)
	}
	if got, ok := byName["file.txt"]; !ok || got {
		t.Errorf("missing 'file.txt' or misreported as dir: %+v", entries)
	}
	if got, ok := byName["link"]; !ok || got {
		t.Errorf("missing 'link' or misreported as dir: %+v", entries)
	}
}

// A filename containing a newline cannot forge a phantom entry: the newline
// record delimiter derails parsing into the fail-closed error at the next
// record. A basename never contains '/', so the post-newline segment can never
// look like a valid `<type>/<name>` record — the whole listing errors rather
// than returning a trusted phantom.
func TestManager_ReadDir_Escalated_NewlineInNameFailsClosed(t *testing.T) {
	fr, m := newEscalatedManager(t)
	// Simulates a file literally named "weird\nd" alongside a real dir "real".
	fr.Push(pmexec.Result{ExitCode: 0, Stdout: "f/weird\nd\nd/real\n"}, nil)
	if _, err := m.ReadDir(context.Background(), "/etc/app.d"); err == nil {
		t.Fatal("a newline-bearing filename did not fail closed: want an unparseable-record error")
	}
}

func TestManager_ReadDir_Escalated_ErrorRows(t *testing.T) {
	fr, m := newEscalatedManager(t)
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "find: ‘/etc/missing/’: No such file or directory\n"}, nil)
	if _, err := m.ReadDir(context.Background(), "/etc/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing dir: err = %v, want fs.ErrNotExist", err)
	}

	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "find: ‘/etc/passwd/’: Not a directory\n"}, nil)
	if _, err := m.ReadDir(context.Background(), "/etc/passwd"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("non-directory: err = %v, want a non-ErrNotExist failure (never a silent empty list)", err)
	}
}

func TestManager_Exists_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	fr.Push(pmexec.Result{ExitCode: 0}, nil)
	ok, err := m.Exists(context.Background(), "/etc/pm-test.conf")
	if err != nil || !ok {
		t.Errorf("exit 0: (%v, %v), want (true, nil)", ok, err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "test" || !slices.Equal(c.Args, []string{"-e", "/etc/pm-test.conf"}) {
		t.Errorf("argv = %s %q, want test [-e path]", c.Name, c.Args)
	}

	fr.Push(pmexec.Result{ExitCode: 1}, nil)
	ok, err = m.Exists(context.Background(), "/etc/pm-missing.conf")
	if err != nil || ok {
		t.Errorf("exit 1: (%v, %v), want (false, nil)", ok, err)
	}

	fr.Push(pmexec.Result{}, pmexec.ErrEscalationDenied)
	if _, err := m.Exists(context.Background(), "/etc/pm-test.conf"); !errors.Is(err, pmexec.ErrEscalationDenied) {
		t.Errorf("runner failure: err = %v, want the escalation error surfaced (never a silent false)", err)
	}
}

// Mode is folded into the create (`mkdir -m`) so the directory never exists
// with a laxer umask-derived mode between two escalated calls. Ownership
// stays a following chown — the residual window has the dir owned by root
// (the escalated uid), which is MORE restrictive than the target owner, so
// it is fail-safe, not a downgrade.
func TestManager_Mkdir_Escalated_ArgvSequence(t *testing.T) {
	fr, m := newEscalatedManager(t)
	err := m.Mkdir(context.Background(), "/srv/app/data", MkdirOptions{Recursive: true, Mode: 0o750, Owner: "root", Group: "root"})
	if err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	calls := mustCalls(t, fr, 2)
	if calls[0].Name != "mkdir" || !slices.Equal(calls[0].Args, []string{"-p", "-m", "0750", "--", "/srv/app/data"}) {
		t.Errorf("call 0 = %s %q, want mkdir [-p -m 0750 -- path] (mode set atomically at create)", calls[0].Name, calls[0].Args)
	}
	if calls[1].Name != "chown" || !slices.Equal(calls[1].Args, []string{"root:root", "--", "/srv/app/data"}) {
		t.Errorf("call 1 = %s %q, want chown [root:root -- path]", calls[1].Name, calls[1].Args)
	}
	for i, c := range calls {
		if !c.Escalate {
			t.Errorf("call %d not escalated", i)
		}
	}
}

func TestManager_Mkdir_Escalated_MinimalIsSingleCall(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.Mkdir(context.Background(), "/srv/app", MkdirOptions{}); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "mkdir" || !slices.Equal(c.Args, []string{"--", "/srv/app"}) {
		t.Errorf("argv = %s %q, want mkdir [-- path] with no gratuitous chmod/chown", c.Name, c.Args)
	}
}

func TestManager_Remove_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.Remove(context.Background(), "/etc/pm-test.conf"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "rm" || !slices.Equal(c.Args, []string{"-f", "--", "/etc/pm-test.conf"}) {
		t.Errorf("argv = %s %q, want rm [-f -- path]", c.Name, c.Args)
	}
}

func TestManager_RemoveDir_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.RemoveDir(context.Background(), "/srv/app/data"); err != nil {
		t.Fatalf("RemoveDir: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "rm" || !slices.Equal(c.Args, []string{"-rf", "--", "/srv/app/data"}) {
		t.Errorf("argv = %s %q, want rm [-rf -- path]", c.Name, c.Args)
	}
}

func TestManager_RemoveDir_Escalated_ProtectedRefusedBeforeSudo(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.RemoveDir(context.Background(), "/etc/cron.d"); !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("err = %v, want ErrProtectedTarget", err)
	}
	mustCalls(t, fr, 0)
}

func TestManager_SetMode_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.SetMode(context.Background(), "/etc/pm-test.conf", 0o640); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "chmod" || !slices.Equal(c.Args, []string{"0640", "--", "/etc/pm-test.conf"}) {
		t.Errorf("argv = %s %q, want chmod [0640 -- path]", c.Name, c.Args)
	}
}

func TestManager_SetMode_Escalated_SetuidRefused(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.SetMode(context.Background(), "/etc/pm-test.conf", 0o755|os.ModeSetuid); !errors.Is(err, ErrUnsafeMode) {
		t.Fatalf("err = %v, want ErrUnsafeMode", err)
	}
	mustCalls(t, fr, 0)
}

func TestManager_SetOwnership_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.SetOwnership(context.Background(), "/etc/pm-test.conf", "root", "wheel"); err != nil {
		t.Fatalf("SetOwnership: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "chown" || !slices.Equal(c.Args, []string{"root:wheel", "--", "/etc/pm-test.conf"}) {
		t.Errorf("argv = %s %q, want chown [root:wheel -- path]", c.Name, c.Args)
	}
}

func TestManager_SetOwnershipRecursive_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.SetOwnershipRecursive(context.Background(), "/srv/app", "app", "app"); err != nil {
		t.Fatalf("SetOwnershipRecursive: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "chown" || !slices.Equal(c.Args, []string{"-R", "app:app", "--", "/srv/app"}) {
		t.Errorf("argv = %s %q, want chown [-R app:app -- path]", c.Name, c.Args)
	}
}

// A recursive ownership change over a protected subtree is a subtree-wide
// mutation — refused like RemoveDir, before any command.
func TestManager_SetOwnershipRecursive_Escalated_ProtectedRefused(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.SetOwnershipRecursive(context.Background(), "/etc", "app", "app"); !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("err = %v, want ErrProtectedTarget", err)
	}
	mustCalls(t, fr, 0)
}

func TestManager_Copy_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.Copy(context.Background(), "/etc/app.conf", "/etc/app.conf.new"); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "cp" || !slices.Equal(c.Args, []string{"--", "/etc/app.conf", "/etc/app.conf.new"}) {
		t.Errorf("argv = %s %q, want cp [-- src dst]", c.Name, c.Args)
	}
}

func TestManager_CopyTree_Escalated(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.CopyTree(context.Background(), "/srv/app", "/srv/app.bak"); err != nil {
		t.Fatalf("CopyTree: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Name != "cp" || !slices.Equal(c.Args, []string{"-a", "-T", "--", "/srv/app", "/srv/app.bak"}) {
		t.Errorf("argv = %s %q, want cp [-a -T -- src dst]", c.Name, c.Args)
	}
}

// CopyTree CREATES a subtree at dst — the create side of [SDK-8]. A tree copy
// into a protected prefix is refused before any command, exactly like Mkdir.
// (Copy, a single-file op, stays unguarded — consistent with WriteFile, whose
// whole purpose is writing single config files under /etc.)
func TestManager_CopyTree_Escalated_RefusesProtectedDest(t *testing.T) {
	fr, m := newEscalatedManager(t)
	for _, dst := range []string{"/etc/cron.d/evil", "/usr/lib/pm-test", "/home/alice/pm-test", "/var/lib/pm-test"} {
		if err := m.CopyTree(context.Background(), "/srv/src", dst); !errors.Is(err, ErrProtectedTarget) {
			t.Errorf("CopyTree(dst=%q) = %v, want ErrProtectedTarget", dst, err)
		}
	}
	mustCalls(t, fr, 0)
}

// Copy to a single file under /etc succeeds — the single-file path is
// governed by higher-layer policy, not the subtree guard (parity with
// WriteFile). This pins the deliberate asymmetry so a later change can't
// silently start refusing legitimate config copies.
func TestManager_Copy_Escalated_AllowsSingleFileUnderEtc(t *testing.T) {
	fr, m := newEscalatedManager(t)
	if err := m.Copy(context.Background(), "/etc/app.conf", "/etc/app.conf.new"); err != nil {
		t.Fatalf("Copy under /etc refused, want allowed (parity with WriteFile): %v", err)
	}
	mustCalls(t, fr, 1)
}

// WriteFileFrom on an escalated backend still streams via stdin — the shape
// is identical to WriteFile; only the source differs.
func TestManager_WriteFileFrom_Escalated_StreamsStdin(t *testing.T) {
	fr, m := newEscalatedManager(t)
	src := bytes.NewReader([]byte("streamed\n"))
	if err := m.WriteFileFrom(context.Background(), "/etc/pm-test.conf", src, WriteOptions{}); err != nil {
		t.Fatalf("WriteFileFrom: %v", err)
	}
	c := mustCalls(t, fr, 1)[0]
	if c.Stdin == nil {
		t.Fatal("no stdin on streamed escalated write")
	}
	data, err := io.ReadAll(c.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "streamed\n" {
		t.Errorf("stdin = %q", data)
	}
}
