package validate

import (
	"net/url"
	"strings"
)

// [SDK-11] Values written into a structured file. Each validator rejects the
// control characters that let one field inject additional lines/records
// (\n/\r/NUL) AND its format's own structural delimiters, BEFORE the value is
// written. Cross-field validators catch a file that is malformed even though
// every field is individually valid.

// The line-oriented config formats (sshd_config, sudoers, authorized_keys, NM
// keyfile) share one threat model: the ONLY smuggle-able structural delimiter
// is the record separator — a newline, CR, or NUL, all control characters.
// Every other "delimiter" those formats use (`:`, `=`, `[`, `]`, `;`, spaces)
// is legitimate mid-value content read to end-of-line, so rejecting it would
// be an over-constraint (AC-15). rejectControl is therefore their whole check;
// the named wrappers exist so a call site reads by format and each can document
// its own reasoning.
func rejectControl(field, v string) error {
	if hasControlChar(v) {
		return invalidf("%s contains a control character (record-separator injection)", field)
	}
	return nil
}

// SSHDConfigValue validates a value written into an sshd_config directive.
// Spaces (AllowUsers alice bob) and `=` are legitimate; only \n/\r/NUL — which
// would split one directive into several — are refused. sshd_config has no
// escape syntax, so this is the only defense.
func SSHDConfigValue(v string) error { return rejectControl("sshd_config value", v) }

// SudoersValue validates a value written into a sudoers rule. Command specs
// carry spaces, `=`, `:`, and `,` legitimately; a newline would append an
// unauthorized rule, so the record separator is the sole rejection.
func SudoersValue(v string) error { return rejectControl("sudoers value", v) }

// AuthorizedKeysValue validates one authorized_keys line. The type, blob, and
// comment are space-separated (all legitimate); an embedded newline would
// splice in an attacker's key (extra principals, command=/restrict= overrides),
// so \n/\r/NUL are fatal.
func AuthorizedKeysValue(v string) error { return rejectControl("authorized_keys entry", v) }

// NMConnectionValue validates a value in a NetworkManager keyfile (INI). A
// value carries `[`, `]`, `;`, `=`, and spaces as literal content (GKeyFile
// reads to end-of-line); only a newline could inject a new `[section]`, so the
// control-char check is the whole guard.
func NMConnectionValue(v string) error { return rejectControl("NetworkManager value", v) }

// GECOSField validates the passwd GECOS (comment) field. `:` ends the field and
// begins the shell field — a record injection — so it is refused along with all
// control characters. The `,` GECOS subfield separator is legitimate content
// and is deliberately allowed.
func GECOSField(v string) error {
	if hasControlChar(v) {
		return invalidf("GECOS field contains a control character")
	}
	if strings.ContainsRune(v, ':') {
		return invalidf("GECOS field contains ':' (passwd field separator)")
	}
	return nil
}

// GroupList validates a single group name destined for a `-G`/passwd context.
// `,` is the `-G` list separator (a comma would inject a second group) and `:`
// is the /etc/group field separator; both are refused with control characters.
func GroupList(v string) error {
	if hasControlChar(v) {
		return invalidf("group name contains a control character")
	}
	if i := strings.IndexAny(v, ":,"); i >= 0 {
		return invalidf("group name contains a %q separator (group-list injection)", v[i])
	}
	return nil
}

// Deb822URIField validates a URI written into a deb822 apt source. apt's trust
// anchor is the gpg-signed Release file, not TLS, so http is a legitimate,
// long-standing transport — but ftp/file and other schemes are not, a space
// starts a second URI on the line, embedded credentials leak into a
// world-readable sources file, and control characters inject additional
// deb822 fields. Template variables ($releasever) survive url.Parse and are
// accepted.
func Deb822URIField(v string) error {
	if v == "" {
		return invalidf("deb822 URI is empty")
	}
	if startsWithDash(v) {
		return invalidf("deb822 URI %q is flag-shaped", v)
	}
	if hasControlOrSpace(v) {
		return invalidf("deb822 URI contains whitespace or a control character")
	}
	u, err := url.Parse(v)
	if err != nil {
		return invalidf("deb822 URI %q is not parseable", v)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return invalidf("deb822 URI %q must use http or https", v)
	}
	if u.Host == "" {
		return invalidf("deb822 URI %q has no host", v)
	}
	if u.User != nil {
		return invalidf("deb822 URI %q must not embed credentials", v)
	}
	return nil
}

// Deb822Source cross-field-validates a deb822 apt source's Suites/Components.
// A flat repository — an empty distribution (rendered "Suites: /") or one that
// ends in "/" — MUST carry no components; a non-flat suite MUST carry at least
// one. Either half individually valid does not make the composed stanza
// parseable, and apt bricks fleet-wide on a malformed sources file (#302), so
// the combination is checked before any write. Each field must also be free of
// control characters and spaces, which would inject additional deb822 lines or
// components.
func Deb822Source(distribution string, components []string) error {
	if hasControlOrSpace(distribution) {
		return invalidf("deb822 Suites %q contains whitespace or a control character", distribution)
	}
	for _, c := range components {
		if c == "" {
			return invalidf("deb822 Components contains an empty entry")
		}
		if hasControlOrSpace(c) {
			return invalidf("deb822 Component %q contains whitespace or a control character", c)
		}
	}
	flat := distribution == "" || strings.HasSuffix(distribution, "/")
	switch {
	case flat && len(components) > 0:
		return invalidf("deb822 flat repository (Suites %q) must not declare Components", distribution)
	case !flat && len(components) == 0:
		return invalidf("deb822 suite %q requires at least one Component", distribution)
	}
	return nil
}

// ToolErrorNamesFile reports whether a system tool's diagnostic output names
// writtenPath — the [SDK-11] rollback trigger. The caller folds the tool's
// error, stdout, and stderr into toolOutput; a substring match means the tool
// rejected the file the SDK just wrote, so the caller rolls it back and fails
// the operation rather than leaving a broken file in place reporting success.
//
// ponytail: plain substring match. Its ceiling is a false-positive when the
// path appears in output for an unrelated reason — acceptable, because the
// fail-safe direction is to over-roll-back rather than leave a bricked config.
// An empty writtenPath never matches (a substring of every string), so it can
// never turn a routine tool error into a spurious rollback.
func ToolErrorNamesFile(toolOutput, writtenPath string) bool {
	if writtenPath == "" {
		return false
	}
	return strings.Contains(toolOutput, writtenPath)
}
