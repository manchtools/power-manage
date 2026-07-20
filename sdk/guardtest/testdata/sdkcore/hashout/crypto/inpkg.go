package crypto

import "crypto/sha256"

// The crypto package itself builds hashes — allowed by prefix; the M5
// framing guard enforces the lp/domain helper per construction here.
func Digest(b []byte) [32]byte { return sha256.Sum256(b) }
