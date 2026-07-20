package hashframe

import kdf "crypto/hkdf"

// Planted: an aliased KDF import does not hide the missing framing helper.
func deriveAliased(secret, salt []byte, info string) ([]byte, error) {
	return kdf.Key(nil, secret, salt, info, 32)
}
