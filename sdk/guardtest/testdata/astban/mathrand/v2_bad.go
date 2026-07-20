package mathrand

import "math/rand/v2"

// Planted violation for the v2 family: the module path differs from
// math/rand, so a v1-only ban misses it — and it must stay UNflagged by
// the v1 scan (path-exact matching, not prefix).
func pickV2() int { return rand.IntN(10) }
