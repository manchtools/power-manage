package exec

// EndOfOptions is the POSIX "--" token. Everything after it on a
// command line is treated as an operand, never an option.
const EndOfOptions = "--"

// SeparatePositionals builds an argv slice that places positionals
// after an explicit EndOfOptions ("--") separator, so a value that
// happens to be flag-shaped (a package name like "-e", a flatpak
// remote like "--from") can never be reparsed by the invoked program
// as an option ([SDK-4]). The "--" is ALWAYS inserted, even when there
// are no positionals — terminating the option list is harmless and
// keeps the invariant unconditional (callers never have to reason
// about the empty case).
//
// The result is a freshly-allocated slice; the caller's flags slice is
// never aliased or appended into, so a reused flag list stays
// pristine across calls.
func SeparatePositionals(flags []string, positionals ...string) []string {
	out := make([]string, 0, len(flags)+1+len(positionals))
	out = append(out, flags...)
	out = append(out, EndOfOptions)
	out = append(out, positionals...)
	return out
}
