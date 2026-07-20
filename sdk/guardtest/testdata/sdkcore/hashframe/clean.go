package hashframe

import "crypto/hkdf"

// framePreimage stands in for the package's length-prefix/domain helper; it is
// not itself a hash construction (no hash callee), so it is never flagged.
func framePreimage(domain string, parts ...[]byte) []byte { return nil }

// Clean: the salt is assembled through the framing helper before HKDF, so the
// derivation's preimage is length-prefixed and domain-separated.
func deriveClean(secret []byte, info string, a, b []byte) ([]byte, error) {
	salt := framePreimage("d", a, b)
	return hkdf.Key(nil, secret, salt, info, 32)
}
