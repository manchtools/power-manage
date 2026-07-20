package hashframe

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// Planted: an HKDF derivation whose salt bypasses the framing helper.
func derive(secret, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, info, 32)
}
