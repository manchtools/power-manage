package seal

import (
	"crypto/ecdh"
	"errors"
	"fmt"
)

const X25519PublicKeySize = 32

var (
	// ErrInvalidX25519PublicKey marks a malformed public-key encoding.
	ErrInvalidX25519PublicKey = errors.New("seal: invalid X25519 public key")
	// ErrLowOrderX25519PublicKey marks an encoded point that cannot derive a
	// usable shared secret.
	ErrLowOrderX25519PublicKey = errors.New("seal: X25519 public key is low-order")
)

// ValidateX25519PublicKey rejects malformed and low-order public keys that
// cannot produce a usable shared secret. It is the shared enrollment and
// renewal boundary for device-directed sealing keys.
func ValidateX25519PublicKey(encoded []byte) error {
	if len(encoded) != X25519PublicKeySize {
		return fmt.Errorf("%w: must be exactly %d bytes", ErrInvalidX25519PublicKey, X25519PublicKeySize)
	}
	publicKey, err := ecdh.X25519().NewPublicKey(encoded)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidX25519PublicKey, err)
	}
	// A fixed validation-only scalar is sufficient to detect X25519 low-order
	// points. No derived bytes are used as key material or exposed.
	privateBytes := make([]byte, X25519PublicKeySize)
	privateBytes[0] = 1
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return fmt.Errorf("seal: initialize X25519 validation key: %w", err)
	}
	if _, err := privateKey.ECDH(publicKey); err != nil {
		return ErrLowOrderX25519PublicKey
	}
	return nil
}
