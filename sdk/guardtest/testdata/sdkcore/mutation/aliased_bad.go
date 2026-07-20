package mutation

import xos "os"

// Planted violation: the alias must not hide the mutation.
func aliasedBad(path string) error { return xos.RemoveAll(path) }
