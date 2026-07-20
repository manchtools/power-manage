package fsafe

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ValidatePath is the chokepoint every privileged file op calls before exec:
// empty, NUL-bearing, and leading-dash paths must never reach argv.
func TestValidatePath(t *testing.T) {
	cases := []struct {
		name string
		path string
		ok   bool
	}{
		{"plain absolute", "/etc/app.conf", true},
		{"relative", "sub/file", true}, // minimal by design; absoluteness is the caller's rule
		{"empty", "", false},
		{"NUL byte", "/etc/a\x00b", false},
		{"leading dash", "-rf", false},
		{"leading dash path", "--preserve-root", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePath(tc.path)
			if tc.ok && err != nil {
				t.Fatalf("ValidatePath(%q) = %v, want nil", tc.path, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("ValidatePath(%q) = nil, want ErrInvalidPath", tc.path)
				}
				if !errors.Is(err, ErrInvalidPath) {
					t.Fatalf("ValidatePath(%q) = %v, want errors.Is(_, ErrInvalidPath)", tc.path, err)
				}
			}
		})
	}
}

// A managed mutation must never create a privileged executable: setuid and
// setgid are refused; sticky and plain permission bits pass.
func TestValidateMode(t *testing.T) {
	if err := validateMode(0o644 | os.ModeSetuid); !errors.Is(err, ErrUnsafeMode) {
		t.Errorf("setuid mode: err = %v, want ErrUnsafeMode", err)
	}
	if err := validateMode(0o755 | os.ModeSetgid); !errors.Is(err, ErrUnsafeMode) {
		t.Errorf("setgid mode: err = %v, want ErrUnsafeMode", err)
	}
	if err := validateMode(0o1777 | os.ModeSticky); err != nil {
		t.Errorf("sticky mode: err = %v, want nil", err)
	}
	if err := validateMode(0o600); err != nil {
		t.Errorf("plain mode: err = %v, want nil", err)
	}
}

// modeArg renders the octal string chmod expects, including the special bits
// whose Go bit positions differ from unix.
func TestModeArg(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		want string
	}{
		{0o644, "0644"},
		{0o600, "0600"},
		{0o755 | os.ModeSticky, "1755"},
		{0o755 | os.ModeSetgid, "2755"},
		{0o755 | os.ModeSetuid, "4755"},
		{0, "0000"},
	}
	for _, tc := range cases {
		if got := modeArg(tc.mode); got != tc.want {
			t.Errorf("modeArg(%v) = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestOwnership(t *testing.T) {
	cases := []struct{ owner, group, want string }{
		{"", "", ""},
		{"root", "", "root"},
		{"", "wheel", ":wheel"},
		{"root", "wheel", "root:wheel"},
	}
	for _, tc := range cases {
		if got := Ownership(tc.owner, tc.group); got != tc.want {
			t.Errorf("Ownership(%q, %q) = %q, want %q", tc.owner, tc.group, got, tc.want)
		}
	}
}

// ResolveAndValidatePath resolves symlinks in the existing parent chain so a
// symlinked directory cannot redirect a later write; relative paths are
// refused outright.
func TestResolveAndValidatePath(t *testing.T) {
	if _, err := ResolveAndValidatePath("relative/path"); err == nil {
		t.Error("relative path accepted, want error")
	}

	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveAndValidatePath(filepath.Join(link, "file.conf"))
	if err != nil {
		t.Fatalf("ResolveAndValidatePath through symlinked parent: %v", err)
	}
	// t.TempDir itself may live behind a symlink (e.g. /tmp on some hosts), so
	// compare against the fully resolved expectation.
	wantDir, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(wantDir, "file.conf"); got != want {
		t.Errorf("resolved = %q, want %q (symlinked parent resolved to its target)", got, want)
	}

	// Missing intermediate components: the existing ancestor is resolved, the
	// missing tail is preserved.
	got, err = ResolveAndValidatePath(filepath.Join(link, "missing", "deep", "file.conf"))
	if err != nil {
		t.Fatalf("ResolveAndValidatePath with missing tail: %v", err)
	}
	if want := filepath.Join(wantDir, "missing", "deep", "file.conf"); got != want {
		t.Errorf("resolved = %q, want %q (missing tail preserved under resolved parent)", got, want)
	}
}
