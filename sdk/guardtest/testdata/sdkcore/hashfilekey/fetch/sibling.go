package fetch

import "crypto/sha256"

// Sibling in the SAME package — the file-key must NOT leak to it.
func other(b []byte) [32]byte { return sha256.Sum256(b) }
