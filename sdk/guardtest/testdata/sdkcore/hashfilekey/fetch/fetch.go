package fetch

import "crypto/sha256"

// Exempt: this is the one file-keyed sanctioned digest-verification site.
func pin(b []byte) [32]byte { return sha256.Sum256(b) }
