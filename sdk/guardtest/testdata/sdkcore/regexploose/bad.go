package regexploose

import "regexp"

// Planted violations: a bare MustCompile at a package var and a Compile
// inside a function, both outside the redos chokepoint.
var loose = regexp.MustCompile(`(a+)+$`)

func compileAt(p string) (*regexp.Regexp, error) {
	return regexp.Compile(p)
}
