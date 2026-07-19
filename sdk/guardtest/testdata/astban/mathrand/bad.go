package mathrand

import "math/rand"

// Planted violation: math/rand outside the jitter allowlist.
func pick() int { return rand.Intn(10) }
