package hashframe

import . "crypto/hkdf"

// Planted: a dot-imported KDF construction still bypasses the framing helper.
func deriveDot(secret, salt []byte, info string) ([]byte, error) {
	return Key(nil, secret, salt, info, 32)
}
