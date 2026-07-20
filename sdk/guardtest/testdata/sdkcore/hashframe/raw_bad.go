package hashframe

import "crypto/sha256"

// Planted: a raw digest over a hand-concatenated, unframed preimage.
func digest(a, b []byte) [32]byte {
	return sha256.Sum256(append(a, b...))
}
