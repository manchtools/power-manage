package validate

import (
	"net/url"
	"path/filepath"
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
	// PackageVersion: cross-distro Debian/RPM/Arch version grammar; max 128.
	rePackageVersion = redos.MustVet(`^[a-zA-Z0-9][a-zA-Z0-9._+:~^-]{0,127}$`)
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

// PackageVersion validates a non-empty package version before it is composed
// into a package-manager operand. Empty means "latest" and remains valid.
func PackageVersion(version string) error {
	if version == "" {
		return nil
	}
	return matchGrammar("package version", rePackageVersion, version)
}

// LocalPackagePath validates a local package-file operand. It must be absolute,
// non-traversing, control-character-free, and therefore never flag-shaped.
func LocalPackagePath(path string) error {
	if path == "" {
		return invalidf("local package path is empty")
	}
	if hasControlChar(path) {
		return invalidf("local package path contains a control character")
	}
	if !filepath.IsAbs(path) || containsDotDot(path) {
		return invalidf("local package path must be absolute and non-traversing")
	}
	return nil
}

// SearchQuery validates a free-text package search operand. Its grammar stays
// intentionally broad, but option-shaped and control-bearing values are never
// allowed to reach argv.
func SearchQuery(query string) error {
	if startsWithDash(query) {
		return invalidf("search query is flag-shaped")
	}
	if hasControlChar(query) {
		return invalidf("search query contains a control character")
	}
	return nil
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

// GPGKeyRef validates a GPG key reference: an https URL (host required, no
// credentials), a file:// URL (empty host, absolute non-traversing path), or a
// bare absolute path. http, rpm `ext::`, relative, and traversing refs are
// refused — the ref becomes an argv operand to the package manager's key
// import. The ref is never echoed in errors: a URL form can embed a credential,
// and a dnf/zypper gpgkey= field is a whitespace-separated key LIST, so an
// embedded space would inject a second attacker-chosen signing key — hence
// whitespace, not just control characters, is refused.
func GPGKeyRef(ref string) error {
	if ref == "" {
		return invalidf("gpg key ref is empty")
	}
	if startsWithDash(ref) {
		return invalidf("gpg key ref is flag-shaped")
	}
	if hasControlOrSpace(ref) {
		return invalidf("gpg key ref contains whitespace or a control character")
	}
	switch {
	case strings.HasPrefix(ref, "https://"):
		u, err := url.Parse(ref)
		if err != nil || u.Hostname() == "" || u.User != nil {
			return invalidf("gpg key ref is not a valid https URL (host required, no credentials)")
		}
		return nil
	case strings.HasPrefix(ref, "file://"):
		u, err := url.Parse(ref)
		if err != nil {
			return invalidf("gpg key ref is not a valid file URL")
		}
		if u.Host != "" {
			return invalidf("gpg key ref: file:// host must be empty")
		}
		if !strings.HasPrefix(u.Path, "/") || containsDotDot(u.Path) {
			return invalidf("gpg key ref: file path must be absolute and non-traversing")
		}
		return nil
	case strings.HasPrefix(ref, "/"):
		if containsDotDot(ref) {
			return invalidf("gpg key ref traverses with '..'")
		}
		return nil
	default:
		return invalidf("gpg key ref must be https://, file://, or an absolute path")
	}
}

// RepoBaseURL validates a repository base URL. https is required, a real host is
// mandatory (u.Hostname(), so "https://:443/x" is refused), and no credentials
// may be embedded (the URL is written into a world-readable repo file). The
// path is otherwise unconstrained: package-manager template variables
// ($releasever, $arch, $basearch) survive url.Parse and are intentionally
// accepted — a strict URL grammar there is a false rejection ([SDK-10]
// over-constraint clause, AC-15). The URL is never echoed: it can carry a
// user:pass@ credential.
func RepoBaseURL(rawURL string) error {
	if rawURL == "" {
		return invalidf("repo base URL is empty")
	}
	if startsWithDash(rawURL) {
		return invalidf("repo base URL is flag-shaped")
	}
	if hasControlOrSpace(rawURL) {
		return invalidf("repo base URL contains whitespace or a control character")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return invalidf("repo base URL is not parseable")
	}
	if u.Scheme != "https" {
		return invalidf("repo base URL must use https")
	}
	if u.Hostname() == "" || u.User != nil {
		return invalidf("repo base URL has no host or embeds credentials")
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
// path. Case-insensitive. It checks the charset, length, and 128-bit range, not
// full ULID timestamp validity (the spec asks for charset restriction, not a
// monotonic clock check).
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
	// 26 Crockford symbols hold 130 bits, but a ULID is 128; the first symbol
	// carries only the top 2 bits, so it must be 0–7. A first symbol of 8–Z
	// (8ZZ…Z and up) decodes to >2^128-1 — not a representable ULID (max is
	// 7ZZ…Z). First char is always a decimal digit here, so no case fold needed.
	if id[0] < '0' || id[0] > '7' {
		return invalidf("ULID overflows 128 bits (first character exceeds 7)")
	}
	return nil
}
