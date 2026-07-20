package hashout

import "crypto/sha256"

// Planted violation: a hash construction outside the crypto package.
func digest(b []byte) [32]byte { return sha256.Sum256(b) }
