package fetch

import "crypto/subtle"

// The exemption still names this file for crypto/sha256, but the import is
// gone — the orphan check must flag the stale exemption.
func eq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
