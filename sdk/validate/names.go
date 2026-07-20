package validate

import (
	"net/url"
	"strings"

	"github.com/manchtools/power-manage/sdk/redos"
)

// [SDK-10] Intent grammars for operator strings that reach an argv operand or a
// config file. Every grammar's first character is alphanumeric (or a mandatory
// scheme/prefix) so a value can never be read as a command-line option, and
// none admit whitespace, NUL, or shell metacharacters. Grammars must NOT
// over-constrain legitimate inputs — see RepoBaseURL's template-variable accept.

// Grammars are anchored (^…$) so a match constrains the WHOLE string; a partial
// match is never enough. First char alphanumeric ⇒ no value is flag-shaped.
var (
	// PackageName: apt multiarch `:`, flatpak ref `/@~`, epoch/version `+`; max 256.
	rePackageName = redos.MustVet(`^[a-zA-Z0-9][a-zA-Z0-9._+:/@~-]{0,255}$`)
	// RpmPackageName: narrower — `+` for libstdc++, but no `:/@~`; max 256.
	reRpmPackageName = redos.MustVet(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,255}$`)
	// RepoName / FlatpakRemoteName: config-section / remote alias; max 128.
	reRepoName          = redos.MustVet(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	reFlatpakRemoteName = redos.MustVet(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	// SystemdUnitName body; the total-length cap and known-suffix set are below.
	reSystemdUnitName = redos.MustVet(`^[a-zA-Z0-9][a-zA-Z0-9:_.@-]*\.(service|socket|device|mount|automount|swap|target|path|timer|slice|scope)$`)
)

// systemdUnitNameMax is systemd's UNIT_NAME_MAX.
const systemdUnitNameMax = 256

// crockfordBase32 is the ULID alphabet — decimal digits plus A–Z with I, L, O,
// and U removed (they collide visually with 1/0/V). Case-insensitive.
const crockfordBase32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ulidLen is the fixed character length of a ULID.
const ulidLen = 26

// PackageName validates a system package name (apt/dnf/flatpak refs).
func PackageName(name string) error {
	return matchGrammar("package name", rePackageName, name)
}

// RpmPackageName validates an rpm `%{NAME}` — narrower than PackageName.
func RpmPackageName(name string) error {
	return matchGrammar("rpm package name", reRpmPackageName, name)
}

// RepoName validates a repository/config-section identifier.
func RepoName(name string) error {
	return matchGrammar("repo name", reRepoName, name)
}

// FlatpakRemoteName validates a flatpak remote alias.
func FlatpakRemoteName(name string) error {
	return matchGrammar("flatpak remote name", reFlatpakRemoteName, name)
}

// GPGKeyRef validates a GPG key reference: an https URL (host required), a
// file:// URL (empty host, absolute non-traversing path), or a bare absolute
// path. http, rpm `ext::`, relative, and traversing refs are refused — the ref
// becomes an argv operand to the package manager's key import.
func GPGKeyRef(ref string) error {
	if ref == "" {
		return invalidf("gpg key ref is empty")
	}
	if startsWithDash(ref) {
		return invalidf("gpg key ref %q is flag-shaped", ref)
	}
	if hasControlChar(ref) {
		return invalidf("gpg key ref contains a control character")
	}
	switch {
	case strings.HasPrefix(ref, "https://"):
		u, err := url.Parse(ref)
		if err != nil || u.Host == "" {
			return invalidf("gpg key ref %q is not a valid https URL", ref)
		}
		return nil
	case strings.HasPrefix(ref, "file://"):
		u, err := url.Parse(ref)
		if err != nil {
			return invalidf("gpg key ref %q is not a valid file URL", ref)
		}
		if u.Host != "" {
			return invalidf("gpg key ref %q: file:// host must be empty", ref)
		}
		if !strings.HasPrefix(u.Path, "/") || containsDotDot(u.Path) {
			return invalidf("gpg key ref %q: file path must be absolute and non-traversing", ref)
		}
		return nil
	case strings.HasPrefix(ref, "/"):
		if containsDotDot(ref) {
			return invalidf("gpg key ref %q traverses with '..'", ref)
		}
		return nil
	default:
		return invalidf("gpg key ref %q must be https://, file://, or an absolute path", ref)
	}
}

// RepoBaseURL validates a repository base URL. https is required and a host is
// mandatory, but the path is otherwise unconstrained: package-manager template
// variables ($releasever, $arch, $basearch) survive url.Parse and are
// intentionally accepted — a strict URL grammar there is a false rejection
// ([SDK-10] over-constraint clause, AC-15).
func RepoBaseURL(rawURL string) error {
	if rawURL == "" {
		return invalidf("repo base URL is empty")
	}
	if startsWithDash(rawURL) {
		return invalidf("repo base URL %q is flag-shaped", rawURL)
	}
	if hasControlOrSpace(rawURL) {
		return invalidf("repo base URL contains whitespace or a control character")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return invalidf("repo base URL %q is not parseable", rawURL)
	}
	if u.Scheme != "https" {
		return invalidf("repo base URL %q must use https", rawURL)
	}
	if u.Host == "" {
		return invalidf("repo base URL %q has no host", rawURL)
	}
	return nil
}

// Username validates a login name: starts with a lowercase letter, then only
// [a-z0-9_-], 1–32 chars. Leading-lowercase kills flag shapes; the charset
// excludes `:` (the passwd/chpasswd field separator) and newline (record
// injection). A byte loop, not a regex — the rule is that simple.
func Username(name string) error {
	if len(name) < 1 || len(name) > 32 {
		return invalidf("username must be 1–32 characters, got %d", len(name))
	}
	if c := name[0]; c < 'a' || c > 'z' {
		return invalidf("username %q must start with a lowercase letter", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return invalidf("username %q contains an illegal character", name)
		}
	}
	return nil
}

// SystemdUnitName validates `name.type` where type is a known unit suffix.
// Instance units (`foo@bar.service`) are allowed; the whole name is capped at
// systemd's UNIT_NAME_MAX and may not be flag-shaped or contain a path
// separator or control character (all excluded by the grammar).
func SystemdUnitName(name string) error {
	if name == "" {
		return invalidf("systemd unit name is empty")
	}
	if len(name) > systemdUnitNameMax {
		return invalidf("systemd unit name exceeds %d characters", systemdUnitNameMax)
	}
	if !reSystemdUnitName.MatchString(name) {
		return invalidf("systemd unit name %q is malformed or has an unknown type suffix", name)
	}
	return nil
}

// ULIDPathID validates that id is a 26-character Crockford-base32 string — the
// charset restriction [SDK-10] requires for any ID embedded in a filesystem
// path. Case-insensitive. It checks the charset and length, not full ULID
// timestamp validity (the spec asks for charset restriction, not a monotonic
// clock check).
func ULIDPathID(id string) error {
	if len(id) != ulidLen {
		return invalidf("ULID must be %d characters, got %d", ulidLen, len(id))
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A' // fold to uppercase
		}
		if strings.IndexByte(crockfordBase32, c) < 0 {
			return invalidf("ULID contains a non-Crockford-base32 character")
		}
	}
	return nil
}
