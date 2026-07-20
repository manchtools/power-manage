package hashframe

import "crypto/subtle"

// Decoy: a constant-time compare is not a hash construction, so it is neither
// discovered nor flagged.
func eq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
