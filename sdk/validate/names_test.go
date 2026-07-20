package validate

import (
	"errors"
	"strings"
	"testing"
)

// assertAccept fails if fn(in) errors — the value is a legitimate input the
// grammar must not reject (over-constraint is a real defect: [SDK-10]).
func assertAccept(t *testing.T, fn func(string) error, in string) {
	t.Helper()
	if err := fn(in); err != nil {
		t.Errorf("reject of a valid value %q: %v", in, err)
	}
}

// assertReject fails unless fn(in) returns an ErrInvalid-wrapped error — a
// malformed/hostile value must be refused, and via the shared sentinel so
// callers fail closed.
func assertReject(t *testing.T, fn func(string) error, in string) {
	t.Helper()
	err := fn(in)
	if err == nil {
		t.Errorf("accepted an invalid value %q, want rejection", in)
		return
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("value %q rejected with %v, want an ErrInvalid-wrapped error", in, err)
	}
}

func TestPackageName_Accepts(t *testing.T) {
	for _, in := range []string{
		"nginx", "gcc-c++", "org.videolan.VLC/x86_64/stable", "lib32:i386",
		"python3.12", "foo_bar", "a", strings.Repeat("p", 256),
	} {
		assertAccept(t, PackageName, in)
	}
}

func TestPackageName_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "-y", "--force", "=evil", " nginx", "foo bar", "pkg;rm -rf /",
		"pkg|cat", "`reboot`", "$(reboot)", "pkg\nmalicious", "pkg\x00", "pkg=1.2.3",
		"pkg*", "pkg?", strings.Repeat("p", 257),
	} {
		assertReject(t, PackageName, in)
	}
}

func TestRpmPackageName_Accepts(t *testing.T) {
	for _, in := range []string{"libstdc++", "kernel-core", "python3.12", "a"} {
		assertAccept(t, RpmPackageName, in)
	}
}

func TestRpmPackageName_Rejects(t *testing.T) {
	// Narrower than PackageName: no :/@~ (rpm names never carry them), so a
	// flatpak-style ref is correctly refused here.
	for _, in := range []string{
		"", "-e", "--eval=%{lua:os.execute('id')}", "org.videolan.VLC/x86_64",
		"lib:i386", "pkg name", "pkg\n", strings.Repeat("r", 257),
	} {
		assertReject(t, RpmPackageName, in)
	}
}

func TestRepoName_Accepts(t *testing.T) {
	for _, in := range []string{"fedora", "updates-testing", "rpmfusion.free", "a", strings.Repeat("r", 128)} {
		assertAccept(t, RepoName, in)
	}
}

func TestRepoName_Rejects(t *testing.T) {
	for _, in := range []string{"", "-x", "repo name", "repo/evil", "repo\n", "re:po", strings.Repeat("r", 129)} {
		assertReject(t, RepoName, in)
	}
}

func TestFlatpakRemoteName_Accepts(t *testing.T) {
	for _, in := range []string{"flathub", "gnome-nightly", "fedora.test", "a"} {
		assertAccept(t, FlatpakRemoteName, in)
	}
}

func TestFlatpakRemoteName_Rejects(t *testing.T) {
	for _, in := range []string{"", "--from=evil", "-x", "a b", "re\nmote", "a/b", strings.Repeat("f", 129)} {
		assertReject(t, FlatpakRemoteName, in)
	}
}

func TestGPGKeyRef_Accepts(t *testing.T) {
	for _, in := range []string{
		"https://download.example.com/RPM-GPG-KEY",
		"file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora",
		"/etc/pki/rpm-gpg/RPM-GPG-KEY-local",
	} {
		assertAccept(t, GPGKeyRef, in)
	}
}

func TestGPGKeyRef_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "-", "--import=/etc/shadow", "http://evil/key", "ext::sh -c id",
		"relative/key", "file://../../etc/passwd", "file:///etc/../shadow",
		"/etc/../etc/shadow", "https:///RPM-GPG-KEY", "https://a\nhttps://b",
		"https://legit/KEY https://evil/EVILKEY", // space → dnf gpgkey= list injection
		"https://user:pass@host/KEY",             // embedded credentials
		"https://:443/KEY",                       // port but no hostname
	} {
		assertReject(t, GPGKeyRef, in)
	}
}

// AC-15 over-constraint guard: package-manager template variables survive
// url.Parse and MUST be accepted — a strict URL grammar here is a false
// rejection that breaks every templated repo ([SDK-10]).
func TestRepoBaseURL_AcceptsTemplateVariables(t *testing.T) {
	for _, in := range []string{
		"https://dnf.example.com/fedora/$releasever",
		"https://arch.example.com/os/$arch",
		"https://mirror.example.com/repo/$basearch/os",
		"https://plain.example.com/repo",
	} {
		assertAccept(t, RepoBaseURL, in)
	}
}

func TestRepoBaseURL_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "http://insecure.example.com/repo", "ftp://example.com/repo",
		"file:///etc", "-o/tmp/x", "https://a\nb", "https://", "https://[::1", "not-a-url",
		"https://user:pass@dnf.example.com/repo", // embedded credentials
		"https://:443/repo",                      // port but no hostname
	} {
		assertReject(t, RepoBaseURL, in)
	}
}

func TestUsername_Accepts(t *testing.T) {
	for _, in := range []string{"deploy", "user_1", "svc-acct", "a", strings.Repeat("u", 32)} {
		assertAccept(t, Username, in)
	}
}

func TestUsername_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "Deploy", "1user", "-rf", "_priv", "user name", "user:x",
		"user\nroot", strings.Repeat("u", 33),
	} {
		assertReject(t, Username, in)
	}
}

func TestSystemdUnitName_Accepts(t *testing.T) {
	for _, in := range []string{"nginx.service", "sshd@1.socket", "foo-bar.timer", "multi-user.target", "data.mount"} {
		assertAccept(t, SystemdUnitName, in)
	}
}

func TestSystemdUnitName_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "nginx", "nginx.bogus", "-x.service", "a/b.service",
		"unit\n.service", ".service", strings.Repeat("u", 250) + ".service",
	} {
		assertReject(t, SystemdUnitName, in)
	}
}

func TestULIDPathID_Accepts(t *testing.T) {
	for _, in := range []string{
		"01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"01arz3ndektsv4rrffq69g5fav", // Crockford base32 is case-insensitive
		"7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
	} {
		assertAccept(t, ULIDPathID, in)
	}
}

func TestULIDPathID_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "01ARZ3NDEKTSV4RRFFQ69G5FA", // 25 chars
		"01ARZ3NDEKTSV4RRFFQ69G5FAVX", // 27 chars
		"01ARZ3NDEKTSV4RRFFQ69G5FAI",  // I not in Crockford
		"01ARZ3NDEKTSV4RRFFQ69G5FAL",  // L
		"01ARZ3NDEKTSV4RRFFQ69G5FAO",  // O
		"01ARZ3NDEKTSV4RRFFQ69G5FAU",  // U
		"01ARZ3NDEKTSV4RRFFQ69G5F/V",  // path separator
		"01ARZ3NDEKTSV4RRFFQ69G5FA!",
		"8" + strings.Repeat("Z", 25), // 26 Crockford chars but decodes to >128 bits
	} {
		assertReject(t, ULIDPathID, in)
	}
}
