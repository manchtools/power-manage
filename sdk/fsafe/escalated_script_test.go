//go:build linux

package fsafe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The escalated write script and the Exists predicate are shell text that the
// FakeRunner tier records but never executes. These tests run the real script
// against /bin/sh so their security semantics are actually proven — the guards
// exit before any chown, so no privilege is needed and the red→green flip is
// independent of the test runner's uid.

// runWriteScript executes escalatedWriteScript with the same positional
// contract as writeFileFromEscalated: $1 target, $2 mode, $3 owner (empty), $4
// backup. stdin is the new file content.
func runWriteScript(target, mode, backup, stdin string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", escalatedWriteScript, "sh", target, mode, "", backup)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.CombinedOutput()
}

// A symlink planted at the target must NOT be backed up through: cp -p would
// follow it and copy the referent (e.g. /etc/shadow) into the backup. The
// script must refuse — the escalated parity of the direct backend's O_NOFOLLOW
// target open.
func TestEscalatedWriteScript_RefusesSymlinkTargetBackup(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret") // stand-in for a readable root file
	if err := os.WriteFile(secret, []byte("TOPSECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.Symlink(secret, target); err != nil { // attacker plants a symlink
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "backup")

	out, err := runWriteScript(target, "0644", backup, "newcontent\n")
	if err == nil {
		t.Fatalf("script did not refuse a symlink target with a backup; output=%q", out)
	}
	if b, rerr := os.ReadFile(backup); rerr == nil && strings.Contains(string(b), "TOPSECRET") {
		t.Fatalf("secret leaked into the backup by following a symlink target: %q", b)
	}
}

// The fix must not over-refuse: a regular target is still backed up and then
// atomically replaced with the new content.
func TestEscalatedWriteScript_BacksUpRegularTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("OLD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "backup")

	if out, err := runWriteScript(target, "0644", backup, "NEW\n"); err != nil {
		t.Fatalf("script failed on a regular target: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(backup); string(b) != "OLD\n" {
		t.Errorf("backup = %q, want the old content preserved", b)
	}
	if b, _ := os.ReadFile(target); string(b) != "NEW\n" {
		t.Errorf("target = %q, want the new content written", b)
	}
}

// The escalated Exists predicate must report a dangling symlink as present, in
// parity with the direct backend's os.Lstat. Bare `test -e` derefs and would
// wrongly report absent — this pins the divergence the `|| -L` arm closes.
func TestExistsPredicate_DanglingSymlinkReportsExists(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nonexistent"), link); err != nil {
		t.Fatal(err)
	}

	// The predicate Exists actually invokes — reference the production const so
	// a change to it (e.g. back to bare `test -e`) trips this behavioral guard.
	pred := exec.Command("sh", "-c", existsPredicate, "sh", link)
	if err := pred.Run(); err != nil {
		t.Fatalf("exists predicate reported a dangling symlink as absent: %v", err)
	}
	// Pin the divergence being fixed: bare `test -e` alone returns false here.
	if err := exec.Command("test", "-e", link).Run(); err == nil {
		t.Fatal("precondition: `test -e <dangling>` unexpectedly succeeded — the divergence this test guards no longer holds")
	}
	// And the direct backend (os.Lstat) agrees the entry exists — the parity target.
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("os.Lstat(dangling) = %v, want it to report the entry present", err)
	}
}
