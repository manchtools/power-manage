package validate

import (
	"os"
	"strings"

	"github.com/manchtools/power-manage/sdk/redos"
)

// [SDK-12] System-object references validated before they reach an argv operand
// or a filesystem path join.

// reLUKSDevicePath restricts a device path to an absolute /dev/ entry with a
// safe charset. The mandatory "/dev/" prefix means it can never be flag-shaped;
// the charset admits no whitespace or shell metacharacter. `..` traversal is
// checked separately (the charset alone would accept "/dev/../etc"). Covers
// /dev/sdaN, /dev/nvme…, /dev/mapper/…, /dev/disk/by-*.
var reLUKSDevicePath = redos.MustVet(`^/dev/[a-zA-Z0-9/_.\-]+$`)

// flatpakAppIDMax is flatpak's application-ID length ceiling (D-Bus name max).
const flatpakAppIDMax = 255

// LUKSDevicePath validates a LUKS device path before it becomes a cryptsetup
// argv operand: absolute /dev/ prefix, safe charset, no `..` traversal.
func LUKSDevicePath(path string) error {
	if !reLUKSDevicePath.MatchString(path) || containsDotDot(path) {
		return invalidf("LUKS device path %q must be an absolute /dev/ path with no '..'", path)
	}
	return nil
}

// FlatpakAppID validates a flatpak application ID before it is joined into an
// install/data path. The ID is reverse-DNS: two or more `.`-separated elements,
// each starting with a letter or underscore and continuing with letters,
// digits, `_`, or `-` (flatpak maps `-` to `_` for the D-Bus name). This
// deliberately drops the `/`, `@`, `~`, `+`, and `:` that the generic package
// grammar admits — a `/` here would let the ID escape its path join, which is
// exactly what [SDK-12] guards. A byte-checked element walk, not one nested-
// quantifier regex, so there is no ReDoS surface to vet.
func FlatpakAppID(id string) error {
	if len(id) == 0 || len(id) > flatpakAppIDMax {
		return invalidf("flatpak app ID must be 1–%d characters, got %d", flatpakAppIDMax, len(id))
	}
	elements := strings.Split(id, ".")
	if len(elements) < 2 {
		return invalidf("flatpak app ID %q must be reverse-DNS (at least two elements)", id)
	}
	for _, e := range elements {
		if !validFlatpakElement(e) {
			return invalidf("flatpak app ID %q has a malformed element %q", id, e)
		}
	}
	return nil
}

// validFlatpakElement reports whether e is one reverse-DNS element: non-empty,
// first byte [A-Za-z_], remaining bytes [A-Za-z0-9_-]. An empty element (from a
// leading/trailing/doubled `.`) fails the first-byte check.
func validFlatpakElement(e string) bool {
	if e == "" {
		return false
	}
	if c := e[0]; !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_') {
		return false
	}
	for i := 1; i < len(e); i++ {
		c := e[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// readLoginShells is the host seam for /etc/shells. It returns the non-comment,
// non-blank shell paths; tests override it so membership checks are
// host-independent.
var readLoginShells = func() ([]string, error) {
	b, err := os.ReadFile("/etc/shells")
	if err != nil {
		return nil, err
	}
	var shells []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		shells = append(shells, line)
	}
	return shells, nil
}

// LoginShell validates that shell is an approved interactive login shell: an
// absolute, control-character-free path that is listed verbatim in
// /etc/shells. It fails CLOSED — an unreadable /etc/shells or an unlisted shell
// is rejected, never accepted — because a missing allow-list must not read as
// "any shell goes" ([SDK-12], AC-15).
func LoginShell(shell string) error {
	if !strings.HasPrefix(shell, "/") {
		return invalidf("login shell %q must be an absolute path", shell)
	}
	if hasControlChar(shell) {
		return invalidf("login shell contains a control character")
	}
	shells, err := readLoginShells()
	if err != nil {
		return invalidf("cannot verify login shell against /etc/shells: %v", err)
	}
	for _, s := range shells {
		if s == shell {
			return nil
		}
	}
	return invalidf("login shell %q is not listed in /etc/shells", shell)
}
