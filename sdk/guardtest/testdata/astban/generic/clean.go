package generic

import g "example.com/registry"

// Clean: a different symbol from the same package is not the banned one.
func other() { g.Keep[int]() }
