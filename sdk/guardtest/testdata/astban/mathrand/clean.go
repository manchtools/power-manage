package mathrand

import "crypto/rand"

// Clean: crypto/rand for anything security-relevant.
func token(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}
