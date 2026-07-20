package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"io"
)

const x25519KeyLen = 32

// sealSaltDomain is the domain tag for the HKDF salt preimage. Versioned so a
// future framing change is a new tag, not a silent reinterpretation.
const sealSaltDomain = "pm-seal-salt:v1"

// Sealed is the sealed-transport output. It maps 1:1 to contract SealedBlob's
// two byte fields: EphemeralPublicKey (32 bytes) and Ciphertext (the AEAD blob
// nonce(12)‖ct‖tag(16)).
type Sealed struct {
	EphemeralPublicKey []byte
	Ciphertext         []byte
}

// GenerateX25519 mints a recipient X25519 keypair from randReader. A read error
// is wrapped and returned with no key — never a predictable key (AC-17).
func GenerateX25519() (*ecdh.PrivateKey, error) {
	return generateX25519()
}

// generateX25519 reads 32 bytes from the RNG seam and builds an X25519 private
// key via NewPrivateKey (X25519 clamps internally). It deliberately avoids
// ecdh.X25519().GenerateKey(randReader), which in Go 1.26 ignores its reader
// argument (internal FIPS DRBG) and so cannot honor the seam or propagate a
// read failure.
func generateX25519() (*ecdh.PrivateKey, error) {
	var b [x25519KeyLen]byte
	if _, err := io.ReadFull(randReader, b[:]); err != nil {
		return nil, fmt.Errorf("crypto: read X25519 private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(b[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: new X25519 private key: %w", err)
	}
	return priv, nil
}

// ParseX25519PublicKey accepts exactly the 32-byte X25519 encoding.
func ParseX25519PublicKey(raw []byte) (*ecdh.PublicKey, error) {
	if len(raw) != x25519KeyLen {
		return nil, fmt.Errorf("crypto: X25519 public key must be %d bytes, got %d", x25519KeyLen, len(raw))
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse X25519 public key: %w", err)
	}
	return pub, nil
}

// SealToPublicKey seals plaintext to a recipient X25519 public key under
// X25519+HKDF-SHA256+AES-256-GCM (SDK-14, AC-16). The info string and AAD are
// mandatory domain-separation inputs; empty info, aad, or plaintext are
// rejected. A fresh ephemeral keypair is drawn per call, so two seals of the
// same plaintext differ. Fail closed: any RNG or ECDH failure returns no output.
func SealToPublicKey(recipient *ecdh.PublicKey, plaintext, aad []byte, info string) (Sealed, error) {
	// Fail closed on a nil key rather than panicking inside ECDH.
	if recipient == nil {
		return Sealed{}, fmt.Errorf("crypto: recipient public key is nil")
	}
	if info == "" {
		return Sealed{}, ErrInfoRequired
	}
	if len(plaintext) == 0 {
		return Sealed{}, ErrEmptyPlaintext
	}
	if len(aad) == 0 {
		return Sealed{}, ErrAADRequired
	}
	eph, err := generateX25519()
	if err != nil {
		return Sealed{}, err
	}
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return Sealed{}, fmt.Errorf("crypto: ECDH: %w", err)
	}
	ephPub := eph.PublicKey().Bytes()
	key, err := deriveSealKey(shared, ephPub, recipient.Bytes(), info)
	if err != nil {
		return Sealed{}, err
	}
	ct, err := SealWithAAD(key, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{EphemeralPublicKey: ephPub, Ciphertext: ct}, nil
}

// OpenWithPrivateKey reverses SealToPublicKey with the recipient private key.
// info and aad are mandatory (symmetric with seal); the ephemeral key and
// ciphertext are validated before any ECDH. It recomputes the identical HKDF
// key and delegates to OpenWithAAD, so a wrong key, AAD, info, or any tamper
// fails authentication and returns no plaintext (fail closed).
func OpenWithPrivateKey(priv *ecdh.PrivateKey, sealed Sealed, aad []byte, info string) ([]byte, error) {
	// Fail closed on a nil key rather than panicking inside ECDH/PublicKey.
	if priv == nil {
		return nil, fmt.Errorf("crypto: recipient private key is nil")
	}
	if info == "" {
		return nil, ErrInfoRequired
	}
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	ephPub, err := ParseX25519PublicKey(sealed.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	if len(sealed.Ciphertext) < nonceLen+tagLen {
		return nil, ErrMalformedCiphertext
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("crypto: ECDH: %w", err)
	}
	key, err := deriveSealKey(shared, ephPub.Bytes(), priv.PublicKey().Bytes(), info)
	if err != nil {
		return nil, err
	}
	return OpenWithAAD(key, sealed.Ciphertext, aad)
}

// deriveSealKey derives the 32-byte AES-256 key from the ECDH shared secret via
// HKDF-SHA256. The salt binds both public keys through the length-prefixed
// framing chokepoint; info is the domain-separation label.
func deriveSealKey(shared, ephPub, recipientPub []byte, info string) ([]byte, error) {
	salt := framePreimage(sealSaltDomain, ephPub, recipientPub)
	key, err := hkdf.Key(sha256.New, shared, salt, info, keyLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: HKDF: %w", err)
	}
	return key, nil
}
