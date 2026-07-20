package regexploose

import re "regexp"

// Planted violation: the import alias and the POSIX variant must not evade.
func posixToo(p string) (*re.Regexp, error) {
	return re.CompilePOSIX(p)
}
