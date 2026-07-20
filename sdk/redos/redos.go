// Package redos vets regular expressions against catastrophic-backtracking
// shapes before they reach a regex engine ([SDK-6], SPEC-004). Any pattern a
// consumer supplies at runtime goes through Vet or Compile; package-level
// literals go through MustVet, which keeps the SDK's regexp construction
// behind one chokepoint (the G-4 guard bans direct regexp constructors
// elsewhere in the module).
//
// The detector is intentionally conservative — it rejects on structural
// heuristics rather than trying to evaluate catastrophic-backtracking risk
// (undecidable in general). False positives are acceptable: a rejected
// pattern returns a clean error and the caller rephrases. False negatives
// are not: a pathological pattern that slips through can hang whatever
// backtracking engine ultimately evaluates it and deny service.
package redos

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ErrPathological is returned (wrapped, with the structural reason) for a
// pattern whose shape is known to drive backtracking engines into
// catastrophic behavior. errors.Is-matchable so callers can distinguish
// "rejected by policy" from a plain syntax error.
var ErrPathological = errors.New("pathological regex pattern")

// Vet rejects pattern when it has a known catastrophic-backtracking shape.
// Rules (each independently disqualifying):
//   - nested quantifier on a group: `(...)*`, `(...)+`, `(...){n,}` where the
//     group — or ANY group nested inside it — contains its own unbounded
//     quantifier. Classic `(a+)+`, `(a*)*`, `(a{1,})+`; the nested state
//     propagates upward on group close so `((a+))+` is caught too.
//   - alternation under an unbounded quantifier: `(a|a)+`, `(a|ab)+` —
//     flagged by any `|` inside (or nested inside) a quantified group.
//   - bounded `{n}`/`{n,m}` repetition of a group containing an unbounded
//     quantifier — `(.*a){11}` is degree-N polynomial even though "bounded";
//     the upper bound drives the worst case, flagged when it is >= 2.
//   - more than 5 unbounded quantifiers (`*`, `+`, `{n,}`) total — catches
//     staircase patterns that compound without nesting.
//
// Bracket expressions `[...]` are opaque to every rule: metacharacters inside
// a class are literals, so `[)]` closes no group and `[+]` is no quantifier —
// in BOTH directions, `([)]+)+` is still caught as `(x+)+` and `a[+]b` costs
// no quantifier budget.
func Vet(pattern string) error {
	if reason := pathologicalReason(pattern); reason != "" {
		return fmt.Errorf("%w: %s", ErrPathological, reason)
	}
	return nil
}

// Compile is Vet followed by regexp.Compile: the one runtime-pattern
// constructor SDK code uses. Rejection — structural or syntactic — is an
// error, never a panic.
func Compile(pattern string) (*regexp.Regexp, error) {
	if err := Vet(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(pattern)
}

// MustVet is the package-level-literal form: it vets and compiles, panicking
// on either failure. Use it exactly where regexp.MustCompile would be used —
// a bad literal fails loudly on the first test run.
func MustVet(pattern string) *regexp.Regexp {
	if err := Vet(pattern); err != nil {
		panic(err)
	}
	return regexp.MustCompile(pattern)
}

// pathologicalReason returns a non-empty reason string when the pattern is
// rejected, "" when it passes.
func pathologicalReason(p string) string {
	// Count unbounded quantifiers — `*`, `+`, `{n,}`. `\` escapes the
	// following metachar so we skip a pair when we see one.
	unbounded := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			i++
			continue
		}
		switch c {
		case '[':
			i = skipClass(p, i)
		case '*', '+':
			unbounded++
		case '{':
			if quantifierUnbounded(p[i:]) {
				unbounded++
			}
		}
	}
	if unbounded > 5 {
		return "too many unbounded quantifiers (max 5)"
	}

	// Walk groups and look for nested-quantifier / alternation-under-
	// quantifier shapes.
	depth := 0
	type groupState struct {
		start         int
		hasAlt        bool
		hasInnerQuant bool
	}
	var stack []groupState
	for i := 0; i < len(p); i++ {
		c := p[i]
		// Skip escapes — `\(` and `\|` are literal characters, not regex metas.
		if c == '\\' && i+1 < len(p) {
			i++
			continue
		}
		switch c {
		case '[':
			i = skipClass(p, i)
		case '(':
			stack = append(stack, groupState{start: i})
			depth++
		case ')':
			if depth == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			depth--
			// Propagate the closed group's quantifier/alternation state up to its
			// parent, so an outer quantifier still sees an unbounded quantifier or
			// alternation nested one level deeper — `((a+))+`, `((a|ab))+`,
			// `((.*a)){2}` would otherwise bypass the guard.
			if len(stack) > 0 {
				if top.hasInnerQuant {
					stack[len(stack)-1].hasInnerQuant = true
				}
				if top.hasAlt {
					stack[len(stack)-1].hasAlt = true
				}
			}
			// Is the closing paren followed by an unbounded quantifier?
			if i+1 < len(p) {
				next := p[i+1]
				if next == '*' || next == '+' || (next == '{' && quantifierUnbounded(p[i+1:])) {
					if top.hasInnerQuant {
						return "nested unbounded quantifier (catastrophic backtracking shape)"
					}
					if top.hasAlt {
						return "alternation under unbounded quantifier (catastrophic backtracking shape)"
					}
				}
				// Bounded `{n}`/`{n,m}` repetition of a group that itself contains
				// an unbounded quantifier is degree-N polynomial backtracking —
				// `(.*a){11}` is catastrophic even though `{11}` is "bounded". The
				// UPPER bound drives the worst case, so `(.*a){1,11}` is just as
				// bad as `(.*a){11}` (lo=1 is irrelevant). Flag when the max
				// repetition count is >= 2. (Alternation under a BOUNDED repeat is
				// fine — bounded branching — so only hasInnerQuant qualifies.)
				if next == '{' && top.hasInnerQuant {
					if _, hi, ok := boundedRepeatBounds(p[i+1:]); ok && hi >= 2 {
						return "bounded repetition of an unbounded group (catastrophic backtracking shape)"
					}
				}
			}
		case '|':
			if depth > 0 {
				stack[len(stack)-1].hasAlt = true
			}
		case '*', '+':
			if depth > 0 {
				stack[len(stack)-1].hasInnerQuant = true
			}
		case '{':
			if j := strings.IndexByte(p[i:], '}'); j > 0 && quantifierUnbounded(p[i:]) {
				if depth > 0 {
					stack[len(stack)-1].hasInnerQuant = true
				}
				i += j
			}
		}
	}
	return ""
}

// skipClass returns the index of the ']' closing the bracket expression that
// opens at p[i] — the scanners route every '[' through here so class content
// never reaches their metachar switches (a ')' inside `[)]` is a literal, not
// the group close; a '+' inside `[+]` is no quantifier). Honors the class
// grammar: optional leading '^', a ']' immediately after `[` or `[^` is a
// literal member (`[]]`, `[^]]`), and `\]` does not terminate. An unterminated
// class consumes the rest of the pattern — it cannot compile anyway, so no
// pathological shape is lost.
func skipClass(p string, i int) int {
	j := i + 1
	if j < len(p) && p[j] == '^' {
		j++
	}
	if j < len(p) && p[j] == ']' {
		j++
	}
	for ; j < len(p); j++ {
		if p[j] == '\\' && j+1 < len(p) {
			j++
			continue
		}
		if p[j] == ']' {
			return j
		}
	}
	return len(p) - 1
}

// boundedRepeatBounds parses a BOUNDED `{n}` or `{n,m}` token starting at p[0]
// and returns (lo, hi, ok). For `{n}`, lo==hi==n. Returns ok=false for a
// non-quantifier, a malformed token, or an unbounded `{n,}` (those are handled
// by quantifierUnbounded). The HI bound is what drives worst-case backtracking
// when the repeated group contains an unbounded quantifier — `(...){1,1000}`
// can still try up to 1000 repetitions.
func boundedRepeatBounds(p string) (lo, hi int, ok bool) {
	if len(p) == 0 || p[0] != '{' {
		return 0, 0, false
	}
	j := strings.IndexByte(p, '}')
	if j <= 0 {
		return 0, 0, false
	}
	body := p[1:j]
	if strings.HasSuffix(body, ",") {
		return 0, 0, false // `{n,}` — unbounded
	}
	k := strings.IndexByte(body, ',')
	if k < 0 {
		// `{n}` — lo == hi == n
		n, err := strconv.Atoi(strings.TrimSpace(body))
		if err != nil {
			return 0, 0, false
		}
		return n, n, true
	}
	// `{n,m}` — lo = n, hi = m
	n, err := strconv.Atoi(strings.TrimSpace(body[:k]))
	if err != nil {
		return 0, 0, false
	}
	m, err := strconv.Atoi(strings.TrimSpace(body[k+1:]))
	if err != nil {
		return 0, 0, false
	}
	return n, m, true
}

// quantifierUnbounded reports whether a `{n,m?}` token starting at p[0] is
// unbounded — `{n,}` is unbounded; `{n}` and `{n,m}` are bounded.
func quantifierUnbounded(p string) bool {
	if len(p) == 0 || p[0] != '{' {
		return false
	}
	j := strings.IndexByte(p, '}')
	if j <= 0 {
		return false
	}
	body := p[1:j]
	if !strings.Contains(body, ",") {
		return false // `{n}` — bounded
	}
	parts := strings.SplitN(body, ",", 2)
	return len(parts) == 2 && parts[1] == "" // `{n,}` — unbounded
}
