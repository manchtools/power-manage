package redos

import "regexp"

// The chokepoint itself compiles vetted patterns — allowed by prefix.
func Vetted(p string) (*regexp.Regexp, error) { return regexp.Compile(p) }
