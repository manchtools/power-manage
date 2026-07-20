package hashout

import (
	"crypto/hmac"
	"crypto/sha512"
)

// Planted violations: hmac and sha512 outside the crypto package.
func mac(key, msg []byte) []byte {
	m := hmac.New(sha512.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
