package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

const (
	keyLen   = 32 // AES-256
	nonceLen = 12 // GCM standard 96-bit nonce
	tagLen   = 16 // GCM authentication tag
)

// SealWithAAD seals plaintext under a 32-byte AES-256 key with mandatory,
// non-empty AAD (SDK-13). Empty plaintext and a non-32-byte key are rejected;
// the AAD is required (no naked AEAD calls). A fresh random 96-bit nonce is
// drawn from randReader, and the output is nonce(12)‖ciphertext‖tag(16). A
// crypto/rand read error is wrapped and returned — never a predictable nonce.
func SealWithAAD(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, ErrInvalidKey
	}
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	// dst == nonce, so the result is nonce‖ct‖tag with the nonce prepended.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// OpenWithAAD reverses SealWithAAD. Key and AAD are validated identically to
// seal; a blob too short to carry nonce+tag is rejected with
// ErrMalformedCiphertext before any AEAD work. A blob that authenticates but
// decrypts to an empty plaintext is rejected with ErrEmptyPlaintext —
// symmetric with seal (SDK-14). Any authentication failure returns an error
// and no plaintext (fail closed).
func OpenWithAAD(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, ErrInvalidKey
	}
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	if len(ciphertext) < nonceLen+tagLen {
		return nil, ErrMalformedCiphertext
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, sealed := ciphertext[:nonceLen], ciphertext[nonceLen:]
	pt, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	if len(pt) == 0 {
		return nil, ErrEmptyPlaintext
	}
	return pt, nil
}

// newGCM builds an AES-256-GCM AEAD from a validated 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new GCM: %w", err)
	}
	return gcm, nil
}
