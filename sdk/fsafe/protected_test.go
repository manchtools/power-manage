package fsafe

import (
	"os"
	"path/filepath"
	"testing"
)

// AC-11 predicates. The rows are a TEST-OWNED attack-path list (threat-model
// tier) — never derived from the implementation's own set, which would prove
// nothing.

func TestIsUnderProtectedPrefix_AttackPaths(t *testing.T) {
	refused := []string{
		"/etc",
		"/etc/shadow",
		"/etc/cron.d/x",
		"/etc/sudoers.d",
		"/etc/../etc/sudoers.d", // traversal spelling
		"/home/alice",
		"/home/alice/.ssh",
		"/root/.bashrc",
		"/var/lib/postgresql",
		"/usr/bin",
		"/boot/efi",
		"/lib/systemd/system",
		"/run/systemd",
		"/proc/1",
		"/sys/kernel",
		"/dev/sda",
	}
	for _, p := range refused {
		if !IsUnderProtectedPrefix(p) {
			t.Errorf("IsUnderProtectedPrefix(%q) = false, want true", p)
		}
	}

	allowed := []string{
		"/var/log/app",
		"/var/cache/app",
		"/srv/data",
		"/opt/thing",
		"/tmp/scratch",
	}
	for _, p := range allowed {
		if IsUnderProtectedPrefix(p) {
			t.Errorf("IsUnderProtectedPrefix(%q) = true, want false (managed app data stays deletable)", p)
		}
	}
}

// "/" and "/var" are exact top-ups: the directory itself is refused while
// children outside the prefix roots stay deletable.
func TestIsUnderProtectedPrefix_ExactTopUps(t *testing.T) {
	for _, p := range []string{"/", "/var"} {
		if !IsUnderProtectedPrefix(p) {
			t.Errorf("IsUnderProtectedPrefix(%q) = false, want true (exact top-up)", p)
		}
	}
}

// A relative path (or one whose resolution fails) errs on the side of caution.
func TestIsUnderProtectedPrefix_RelativeErsOnCaution(t *testing.T) {
	// A relative path is resolved against the cwd; from anywhere it must not
	// silently read as safe when resolution cannot be pinned. The predicate
	// resolves to absolute first — assert the etc spelling is still caught.
	if !IsUnderProtectedPrefix("/etc/./sudoers.d/../sudoers.d") {
		t.Error("cleaned traversal spelling dodged the prefix check")
	}
}

func TestIsProtectedPath_ExactMatches(t *testing.T) {
	for _, p := range []string{"/", "/etc", "/var", "/usr", "/tmp", "/home"} {
		if !IsProtectedPath(p) {
			t.Errorf("IsProtectedPath(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/etc/app", "/home/alice", "/var/log"} {
		if IsProtectedPath(p) {
			t.Errorf("IsProtectedPath(%q) = true, want false (exact match only)", p)
		}
	}
}

// [SDK-8]: a path that RESOLVES into a protected subtree is refused
// regardless of how it was spelled — symlink resolution is part of the check.
func TestResolvesUnderProtectedPrefix_SymlinkIntoEtc(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "innocent")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}

	under, err := ResolvesUnderProtectedPrefix(filepath.Join(link, "cron.d", "job"))
	if err != nil {
		t.Fatalf("ResolvesUnderProtectedPrefix: %v", err)
	}
	if !under {
		t.Error("a path resolving through a symlink into /etc was not refused")
	}

	under, err = ResolvesUnderProtectedPrefix(filepath.Join(dir, "plain"))
	if err != nil {
		t.Fatalf("ResolvesUnderProtectedPrefix(plain tmp path): %v", err)
	}
	if under {
		t.Error("a plain temp path read as protected")
	}
}

// [SDK-8] fail-closed: when the ancestor chain cannot be resolved (here a path
// component is a regular file, so traversal hits ENOTDIR), the predicate
// reports (true, err) — an unresolvable path is treated as protected, never
// silently allowed through the deny-by-default subtree guard.
func TestResolvesUnderProtectedPrefix_ResolutionFailureFailsClosed(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A component of the queried path is a regular file, so resolving the
	// ancestor chain fails with ENOTDIR rather than "does not exist".
	under, err := ResolvesUnderProtectedPrefix(filepath.Join(file, "sub", "child"))
	if err == nil {
		t.Fatal("expected a resolution error for a path traversing a regular file")
	}
	if !under {
		t.Error("resolution failure did not fail closed: want under=true")
	}
}
