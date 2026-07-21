package pkg

import (
	"context"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

// Contract (gap #2): LocalPackageInfo(ctx, path) reads a package's CANONICAL
// name (plus version + arch where available) from a LOCAL package file already
// on disk, so the agent can resolve `IsInstalled(name)` / `Remove(name)` before
// an InstallLocal without re-implementing the introspection itself.
//
//   - It MUST validate the PATH first (ValidateLocalPackagePath: absolute, no
//     "..", no control chars) before the file ever reaches argv.
//   - The NAME the file reports is ATTACKER-INFLUENCED — a crafted .deb/.rpm can
//     embed any %{NAME}/Package value. LocalPackageInfo MUST re-validate that
//     name against the BACKEND'S package-name grammar before returning it, and
//     reject a flag-shaped (`-evil`) or metacharacter-bearing name. A bad name is
//     a rejection, NOT a silently-returned value that a later Remove(name) would
//     pass straight to the package manager as a flag.
//   - flatpak has no clean local-name introspection command, so it returns a
//     clear "not supported" error rather than guessing.
//
// Per backend: apt → `dpkg-deb -f <path> Package Version Architecture`;
// dnf/zypper → `rpm -qp --qf '%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}' <path>`;
// pacman → `pacman -Qp <path>` (prints "name version").

// TestLocalPackageInfo_AptHappyPath: a valid .deb file → the validated canonical
// name, version, and architecture, via an UNPRIVILEGED dpkg-deb read.
func TestLocalPackageInfo_AptHappyPath(t *testing.T) {
	m, f := aptM(t)
	// dpkg-deb -f with MULTIPLE fields emits a labeled "Field: value" stanza (NOT
	// bare values — that is only the single-field shape). The parse must read the
	// value, not the "Package:" label.
	ok(f, "Package: nginx\nVersion: 1.24.0-1ubuntu1\nArchitecture: amd64\n")
	info, err := m.LocalPackageInfo(context.Background(), "/tmp/nginx.deb")
	if err != nil {
		t.Fatalf("LocalPackageInfo err = %v", err)
	}
	if info.Name != "nginx" || info.Version != "1.24.0-1ubuntu1" || info.Arch != "amd64" {
		t.Errorf("info = %+v, want {nginx 1.24.0-1ubuntu1 amd64}", info)
	}
	c := f.Calls()[0]
	want := "dpkg-deb -f /tmp/nginx.deb Package Version Architecture"
	if argv(c) != want {
		t.Errorf("argv = %q, want %q", argv(c), want)
	}
	if c.Escalate {
		t.Error("reading a local package file is an unprivileged read; must NOT escalate")
	}
}

// TestLocalPackageInfo_RpmHappyPath: dnf and zypper both introspect a local .rpm
// via `rpm -qp --qf`, returning the validated name/version/arch.
func TestLocalPackageInfo_RpmHappyPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		mk   func(t *testing.T) (Manager, *exectest.FakeRunner)
	}{
		{"dnf", dnfM},
		{"zypper", zypperM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, f := tc.mk(t)
			// rpm -qp --qf '%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}'
			ok(f, "httpd\n2.4.57-5.fc39\nx86_64\n")
			info, err := m.LocalPackageInfo(context.Background(), "/tmp/httpd.rpm")
			if err != nil {
				t.Fatalf("LocalPackageInfo err = %v", err)
			}
			if info.Name != "httpd" || info.Version != "2.4.57-5.fc39" || info.Arch != "x86_64" {
				t.Errorf("info = %+v, want {httpd 2.4.57-5.fc39 x86_64}", info)
			}
			c := f.Calls()[0]
			if c.Name != "rpm" {
				t.Fatalf("command = %q, want rpm", c.Name)
			}
			joined := argv(c)
			for _, frag := range []string{"-qp", "--qf", "%{NAME}", "/tmp/httpd.rpm"} {
				if !strings.Contains(joined, frag) {
					t.Errorf("argv = %q, missing %q", joined, frag)
				}
			}
			if c.Escalate {
				t.Error("rpm -qp on a local file is an unprivileged read; must NOT escalate")
			}
		})
	}
}

// TestLocalPackageInfo_PacmanHappyPath: `pacman -Qp <path>` prints "name version"
// on one line.
func TestLocalPackageInfo_PacmanHappyPath(t *testing.T) {
	m, f := pacmanM(t)
	ok(f, "neovim 0.9.5-1\n")
	info, err := m.LocalPackageInfo(context.Background(), "/tmp/neovim.pkg.tar.zst")
	if err != nil {
		t.Fatalf("LocalPackageInfo err = %v", err)
	}
	if info.Name != "neovim" || info.Version != "0.9.5-1" {
		t.Errorf("info = %+v, want name=neovim version=0.9.5-1", info)
	}
	c := f.Calls()[0]
	want := "pacman -Qp /tmp/neovim.pkg.tar.zst"
	if argv(c) != want {
		t.Errorf("argv = %q, want %q", argv(c), want)
	}
	if c.Escalate {
		t.Error("pacman -Qp on a local file is an unprivileged read; must NOT escalate")
	}
}

// TestLocalPackageInfo_PacmanRejectsNamelessOutput: malformed `-Qp` output with a
// leading-whitespace version but no name token must be REJECTED (fail-closed
// parse) — TrimSpace+Fields would otherwise promote the version to Name. Derived
// from intent ("the first token IS the name; no name token => reject"), not from
// the parser under test.
func TestLocalPackageInfo_PacmanRejectsNamelessOutput(t *testing.T) {
	cases := map[string]string{
		"leading-space version": " 1.0-1\n",
		"leading-tab version":   "\t1.0-1\n",
		"whitespace only":       "   \n",
		"empty":                 "\n",
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			m, f := pacmanM(t)
			ok(f, out)
			info, err := m.LocalPackageInfo(context.Background(), "/tmp/x.pkg.tar.zst")
			if err == nil {
				t.Fatalf("accepted nameless -Qp output %q as info=%+v; want a no-name rejection", out, info)
			}
			if info != nil {
				t.Errorf("info = %+v, want nil on rejection", info)
			}
		})
	}
}

// TestLocalPackageInfo_FlatpakUnsupported: a flatpak bundle has no clean local
// name-introspection command, so the call returns a clear error and runs nothing.
func TestLocalPackageInfo_FlatpakUnsupported(t *testing.T) {
	m, f := flatpakM(t)
	info, err := m.LocalPackageInfo(context.Background(), "/tmp/app.flatpak")
	if err == nil {
		t.Fatal("flatpak LocalPackageInfo must return a not-supported error")
	}
	if info != nil {
		t.Errorf("info = %+v, want nil on the unsupported path", info)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "flatpak") {
		t.Errorf("error = %v, want it to name flatpak", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("unsupported backend ran %d commands, want 0", n)
	}
}

// TestLocalPackageInfo_RejectsBadPath: a non-absolute / traversing / control-char
// path is refused before the Runner — the path can never reach argv.
func TestLocalPackageInfo_RejectsBadPath(t *testing.T) {
	for _, mk := range []func(t *testing.T) (Manager, *exectest.FakeRunner){aptM, dnfM, zypperM, pacmanM} {
		m, f := mk(t)
		for _, path := range []string{
			"",              // empty
			"relative.deb",  // not absolute
			"/tmp/../etc/x", // traversal
			"/tmp/a\nb.deb", // control char
			"-rf",           // flag-shaped (and relative)
		} {
			_, err := m.LocalPackageInfo(context.Background(), path)
			if err == nil {
				t.Errorf("%T LocalPackageInfo(%q) = nil err, want path rejection", m, path)
			}
		}
		if n := len(f.Calls()); n != 0 {
			t.Errorf("%T ran %d commands on rejected paths, want 0", m, n)
		}
	}
}

// TestLocalPackageInfo_RejectsCraftedName is the security core: a crafted package
// file reports an adversarial %{NAME}/Package. LocalPackageInfo MUST reject it
// against the backend's name grammar rather than return it — a returned `-rf`
// would be reparsed as a flag by a later Remove/IsInstalled, and a returned
// `evil$(id)` could escape further handling. The wrong values are derived from
// the intent ("a package name starts alphanumeric, no flags, no metacharacters"),
// not from the validator under test.
func TestLocalPackageInfo_RejectsCraftedName(t *testing.T) {
	// Names a crafted file could embed that the backend's grammar must refuse.
	craftedNames := []string{
		"-rf",          // flag-shaped: leading dash → option injection
		"--eval=%x",    // rpm macro / flag injection
		"evil name",    // space → argv split
		"pkg;id",       // shell metacharacter
		"pkg$(whoami)", // command-substitution metacharacter
		"pkg|tee",      // pipe metacharacter
		"pkg`id`",      // backtick
		"",             // empty name
	}

	t.Run("apt rejects a crafted Package field", func(t *testing.T) {
		for _, bad := range craftedNames {
			m, f := aptM(t)
			// Multiple dpkg-deb fields are emitted as a labeled stanza.
			ok(f, "Package: "+bad+"\nVersion: 1.0\nArchitecture: amd64\n")
			info, err := m.LocalPackageInfo(context.Background(), "/tmp/evil.deb")
			if err == nil {
				t.Errorf("crafted Package %q: err = nil, want rejection (info=%+v)", bad, info)
			}
			if info != nil {
				t.Errorf("crafted Package %q: info = %+v, want nil", bad, info)
			}
		}
	})

	t.Run("dnf/zypper reject a crafted %{NAME}", func(t *testing.T) {
		for _, mk := range []func(t *testing.T) (Manager, *exectest.FakeRunner){dnfM, zypperM} {
			for _, bad := range craftedNames {
				m, f := mk(t)
				ok(f, bad+"\n2.4.57-5.fc39\nx86_64\n")
				info, err := m.LocalPackageInfo(context.Background(), "/tmp/evil.rpm")
				if err == nil {
					t.Errorf("%T crafted %%{NAME} %q: err = nil, want rejection (info=%+v)", m, bad, info)
				}
				if info != nil {
					t.Errorf("%T crafted %%{NAME} %q: info = %+v, want nil", m, bad, info)
				}
			}
		}
	})

	t.Run("pacman rejects a crafted name", func(t *testing.T) {
		// pacman -Qp output is space-delimited "name version", so the name is a
		// single token: a name with an embedded space is not representable, and an
		// empty/whitespace first field is the "no name" shape covered separately
		// below. Drive the single-token crafted names — the realistic threat (a
		// flag-shaped or metacharacter-bearing first token) — through field[0].
		for _, bad := range craftedNames {
			if bad == "" || strings.ContainsAny(bad, " ") {
				continue // not a single-token pacman name
			}
			m, f := pacmanM(t)
			ok(f, bad+" 1.0-1\n")
			info, err := m.LocalPackageInfo(context.Background(), "/tmp/evil.pkg.tar.zst")
			if err == nil {
				t.Errorf("pacman crafted name %q: err = nil, want rejection (info=%+v)", bad, info)
			}
			if info != nil {
				t.Errorf("pacman crafted name %q: info = %+v, want nil", bad, info)
			}
		}
	})

	t.Run("pacman rejects empty -Qp output (no name)", func(t *testing.T) {
		// A crafted/garbled package whose -Qp emits no name must be a rejection, not
		// a half-populated info — and must never promote the version into the name.
		for _, out := range []string{"", "\n", "   \n"} {
			m, f := pacmanM(t)
			ok(f, out)
			info, err := m.LocalPackageInfo(context.Background(), "/tmp/evil.pkg.tar.zst")
			if err == nil {
				t.Errorf("pacman empty -Qp %q: err = nil, want rejection (info=%+v)", out, info)
			}
			if info != nil {
				t.Errorf("pacman empty -Qp %q: info = %+v, want nil", out, info)
			}
		}
	})
}

// TestLocalPackageInfo_AcceptsRpmPlusName guards a real-world legitimate RPM name
// the apt/pacman grammar would reject but the RPM grammar allows ('+', e.g.
// libstdc++): dnf/zypper must validate with the RPM grammar, not the generic one,
// so a valid library package is not wrongly refused.
func TestLocalPackageInfo_AcceptsRpmPlusName(t *testing.T) {
	for _, mk := range []func(t *testing.T) (Manager, *exectest.FakeRunner){dnfM, zypperM} {
		m, f := mk(t)
		ok(f, "libstdc++\n13.2.1-4.fc39\nx86_64\n")
		info, err := m.LocalPackageInfo(context.Background(), "/tmp/libstdc++.rpm")
		if err != nil {
			t.Fatalf("%T legitimate '+'-bearing RPM name rejected: %v", m, err)
		}
		if info.Name != "libstdc++" {
			t.Errorf("%T info.Name = %q, want libstdc++", m, info.Name)
		}
	}
}

// TestLocalPackageInfo_RunnerErrorPropagates: a genuine read failure (binary
// missing, unreadable file → non-zero exit) surfaces as an error, never a
// half-populated info.
func TestLocalPackageInfo_ReadFailurePropagates(t *testing.T) {
	m, f := aptM(t)
	f.Push(pmexec.Result{ExitCode: 2, Stderr: "dpkg-deb: error: not a debian archive\n"}, nil)
	info, err := m.LocalPackageInfo(context.Background(), "/tmp/not-a.deb")
	if err == nil {
		t.Fatal("a non-zero dpkg-deb exit must surface as an error")
	}
	if info != nil {
		t.Errorf("info = %+v, want nil on read failure", info)
	}
}
