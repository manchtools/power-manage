package regexploose

import "regexp"

type probe struct{}

// Planted violation: a compile inside a method — keyed by the
// receiver-qualified decl identity (probe.rx), which cannot collide with a
// same-named package var (review finding, PR #20).
func (probe) rx(p string) (*regexp.Regexp, error) {
	return regexp.Compile(p)
}
