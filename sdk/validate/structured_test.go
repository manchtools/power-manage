package validate

import (
	"strings"
	"testing"
)

// The four line-oriented validators (sshd_config, sudoers, authorized_keys, NM
// keyfile) share one contract: the ONLY smuggle-able structural delimiter is
// the record separator (\n/\r/NUL, all control chars); `:`, `=`, `[`, `]`,
// `;`, and spaces are legitimate mid-value content and MUST NOT be rejected
// (over-constraint is an AC-15 defect). Each _Accepts row proves a
// format-appropriate value with those "delimiters" survives; each _Rejects row
// proves the record separator is refused.

func TestSSHDConfigValue_Accepts(t *testing.T) {
	// sshd values legitimately carry spaces (AllowUsers alice bob) and `=`.
	for _, in := range []string{"yes", "alice bob carol", "no", "prohibit-password", "/etc/ssh/x=1"} {
		assertAccept(t, SSHDConfigValue, in)
	}
}

func TestSSHDConfigValue_Rejects(t *testing.T) {
	for _, in := range []string{"yes\nPermitRootLogin yes", "a\rb", "x\x00y", "tab\there"} {
		assertReject(t, SSHDConfigValue, in)
	}
}

func TestSudoersValue_Accepts(t *testing.T) {
	// sudoers command specs carry spaces, `=`, `:`, `,` — all legitimate.
	for _, in := range []string{"ALL=(ALL) NOPASSWD: /usr/bin/systemctl", "wheel", "user1, user2"} {
		assertAccept(t, SudoersValue, in)
	}
}

func TestSudoersValue_Rejects(t *testing.T) {
	for _, in := range []string{
		"ALL\nattacker ALL=(ALL) NOPASSWD: ALL", "x\ry", "z\x00",
		`ALL=(ALL) NOPASSWD: /usr/bin/id\`, // trailing '\' → sudoers line continuation
	} {
		assertReject(t, SudoersValue, in)
	}
}

func TestAuthorizedKeysValue_Accepts(t *testing.T) {
	// A key line carries spaces (type, blob, comment) and `=` (base64 padding).
	for _, in := range []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host", "ssh-rsa AAAAB3Nza== comment"} {
		assertAccept(t, AuthorizedKeysValue, in)
	}
}

func TestAuthorizedKeysValue_Rejects(t *testing.T) {
	for _, in := range []string{"ssh-ed25519 AAAA\nssh-rsa ATTACKER", "key\rmore", "key\x00"} {
		assertReject(t, AuthorizedKeysValue, in)
	}
}

func TestNMConnectionValue_Accepts(t *testing.T) {
	// INI values carry `[`/`]`, `;`, `=`, spaces mid-value — none is an injector.
	for _, in := range []string{"Home [5G]", "a=b;c", "My Wifi Network", "key=val"} {
		assertAccept(t, NMConnectionValue, in)
	}
}

func TestNMConnectionValue_Rejects(t *testing.T) {
	for _, in := range []string{"name\n[connection]\nid=evil", "x\ry", "z\x00"} {
		assertReject(t, NMConnectionValue, in)
	}
}

func TestGECOSField_Accepts(t *testing.T) {
	// GECOS subfields are comma-separated, so a comma is legitimate content.
	for _, in := range []string{"Real Name", "Real Name, Room 5, x1234, y5678", "", "José"} {
		assertAccept(t, GECOSField, in)
	}
}

func TestGECOSField_Rejects(t *testing.T) {
	// `:` ends the GECOS field and starts the shell field (record injection);
	// control chars inject a whole new passwd line.
	for _, in := range []string{"Real\nroot:x:0:0::/:/bin/sh", "name:x", "a\x00b", "tab\there"} {
		assertReject(t, GECOSField, in)
	}
}

func TestGroupList_Accepts(t *testing.T) {
	for _, in := range []string{"wheel", "adm", "docker"} {
		assertAccept(t, GroupList, in)
	}
}

func TestGroupList_Rejects(t *testing.T) {
	// `,` is the `-G` list separator (injects a second group); `:` is the
	// /etc/group field separator; control injects a new group line.
	for _, in := range []string{"wheel,root", "grp:x", "a\nb", "g\x00"} {
		assertReject(t, GroupList, in)
	}
}

func TestDeb822URIField_Accepts(t *testing.T) {
	// apt's trust anchor is the signed Release file, not TLS: http with a
	// trusted key is a legitimate, long-standing configuration.
	for _, in := range []string{
		"https://deb.example.com/ubuntu",
		"http://archive.ubuntu.com/ubuntu",
		"https://deb.example.com/repo/$releasever",
	} {
		assertAccept(t, Deb822URIField, in)
	}
}

func TestDeb822URIField_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "-flag",
		"https://h/a https://evil/", // space starts a 2nd URI
		"https://user:pass@h/a",     // embedded credentials
		"https://",                  // no host
		"https://:443/a",            // port but no hostname
		"ftp://h/a", "file:///etc",  // non-http(s) scheme
		"https://h/a\nDeb-Src: evil", // newline injects a field
		"https://h/\ttab",
	} {
		assertReject(t, Deb822URIField, in)
	}
}

// Deb822Source cross-field: a flat repo (empty or "/"-suffixed Suites) MUST
// have no Components; a non-flat suite MUST have at least one. Each field must
// also be control/space-free (it lands on a Suites:/Components: line).
func TestDeb822Source_Accepts(t *testing.T) {
	for _, tc := range []struct {
		dist  string
		comps []string
	}{
		{"stable", []string{"main"}},
		{"bookworm", []string{"main", "contrib", "non-free"}},
		{"/", nil}, // explicit flat
		{"", nil},  // empty selects flat ("Suites: /")
	} {
		if err := Deb822Source(tc.dist, tc.comps); err != nil {
			t.Errorf("reject of valid deb822 (dist=%q comps=%v): %v", tc.dist, tc.comps, err)
		}
	}
}

func TestDeb822Source_Rejects(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dist  string
		comps []string
	}{
		{"flat-empty-with-comps", "", []string{"main"}},
		{"flat-slash-with-comps", "/", []string{"main"}},
		{"nonflat-no-comps", "stable", nil},
		{"control-in-dist", "sta\nble", []string{"main"}},
		{"space-in-component", "stable", []string{"main contrib"}},
		{"control-in-component", "stable", []string{"ma\x00in"}},
	} {
		if err := Deb822Source(tc.dist, tc.comps); err == nil {
			t.Errorf("%s: accepted invalid deb822 (dist=%q comps=%v), want rejection", tc.name, tc.dist, tc.comps)
		}
	}
}

func TestToolErrorNamesFile(t *testing.T) {
	const path = "/etc/apt/sources.list.d/corp.sources"
	for _, tc := range []struct {
		name   string
		stderr string
		path   string
		want   bool
	}{
		{"names the file", "E: Malformed entry in " + path + " (Component)", path, true},
		{"folded into error text", "apt-get update failed: " + path + ": No Suites entry", path, true},
		{"unrelated error", "E: Could not resolve 'deb.example.com'", path, false},
		{"empty stderr", "", path, false},
		{"empty path never matches", "some error", "", false},
		{"different file", "E: Malformed entry in /etc/apt/sources.list.d/other.sources", path, false},
	} {
		if got := ToolErrorNamesFile(tc.stderr, tc.path); got != tc.want {
			t.Errorf("%s: ToolErrorNamesFile(%q, %q) = %v, want %v", tc.name, tc.stderr, tc.path, got, tc.want)
		}
	}
}

// Guard the helper cap: a path that is a substring of an UNRELATED path in
// stderr should still be caught (fail-safe: over-rollback beats leaving a
// bricked file), but the empty-path guard must hold.
func TestToolErrorNamesFile_EmptyPathGuard(t *testing.T) {
	if ToolErrorNamesFile(strings.Repeat("x", 100), "") {
		t.Error("empty path must never match (would roll back on every tool error)")
	}
}
