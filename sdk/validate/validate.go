// Package validate is the SDK's shared intent-grammar library ([SDK-10..12]):
// one grammar consumed by both server and agent for every operator string that
// reaches an argv operand or a structured config file. The validators are pure
// mechanism — they decide only whether a value is well-formed, never policy
// (who may use it). A malformed value is refused BEFORE it can reach a command
// or a file, so option injection, control-character smuggling, and path-join
// escapes never leave this boundary.
package validate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalid is the single errors.Is-matchable sentinel every validator wraps,
// so a caller can fail closed on "any validation failure" while the wrapped
// message names the specific field and reason.
var ErrInvalid = errors.New("validate: invalid value")

// invalidf wraps ErrInvalid with a specific reason. The value itself is only
// echoed by callers that know it carries no secret; validators name the field
// and the violated rule, never a credential.
func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// matchGrammar returns nil iff s matches the anchored grammar re, else an
// ErrInvalid naming the field. re is compiled once at package init through the
// redos chokepoint (G-4/[SDK-6]).
func matchGrammar(field string, re *regexp.Regexp, s string) error {
	if !re.MatchString(s) {
		return invalidf("%s %q is malformed", field, s)
	}
	return nil
}

// hasControlChar reports whether s contains a C0 control character (below
// U+0020) or DEL (U+007F). A plain space (0x20) is NOT a control character —
// callers that must also reject whitespace use hasControlOrSpace. This is the
// [SDK-11] "reject \n/\r/control before write" core.
func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// hasControlOrSpace reports whether s contains any character at or below space
// (0x20 — space, tab, newline, CR included) or DEL. Used where even a single
// embedded space is a structural injection (e.g. a deb822 URI list, where a
// space starts a second URI).
func hasControlOrSpace(s string) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// startsWithDash reports whether s would be read as a command-line option
// rather than an operand. Every argv-bound grammar refuses it structurally
// (the SDK never relies on the callee's `--` handling alone).
func startsWithDash(s string) bool {
	return strings.HasPrefix(s, "-")
}

// containsDotDot reports whether s has a `..` path component in any position —
// a traversal escape for anything that becomes a filesystem path.
func containsDotDot(s string) bool {
	for _, part := range strings.Split(s, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
