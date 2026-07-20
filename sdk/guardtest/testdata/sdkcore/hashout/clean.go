package hashout

import "crypto/subtle"

// Clean: constant-time compare is not a hash construction.
func eq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
