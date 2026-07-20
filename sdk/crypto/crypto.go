// Package crypto is the SDK's sole seal/open implementation (SPEC-004
// [SDK-13, SDK-14]): AES-256-GCM AEAD, X25519+HKDF-SHA256 sealed transport,
// constant-time compares, and length-prefixed/domain-separated preimage
// framing. Stdlib crypto/* only; imports nothing in-repo (INV-19).
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

// Error sentinels — the API surface the tests pin via errors.Is.
var (
	// ErrInvalidKey is returned when the symmetric key is not exactly 32 bytes.
	ErrInvalidKey = errors.New("crypto: key must be 32 bytes (AES-256)")
	// ErrAADRequired is returned when the AAD is empty (domain separation is
	// mandatory; no naked AEAD calls).
	ErrAADRequired = errors.New("crypto: AAD is required (domain separation; no naked AEAD calls)")
	// ErrEmptyPlaintext is returned when plaintext is empty — rejected
	// symmetrically at seal AND open (SDK-14/WIRE-25).
	ErrEmptyPlaintext = errors.New("crypto: plaintext must be non-empty")
	// ErrInfoRequired is returned when the HKDF info string is empty (mandatory
	// domain separation; no naked seal calls).
	ErrInfoRequired = errors.New("crypto: HKDF info is required (domain separation; no naked seal calls)")
	// ErrMalformedCiphertext is returned when a ciphertext is too short to carry
	// its prepended nonce and tag.
	ErrMalformedCiphertext = errors.New("crypto: ciphertext too short")
)

// randReader is the single RNG seam. Nonce reads go through io.ReadFull against
// it, and keygen reads 32 bytes from it (never ecdh.GenerateKey, which in
// Go 1.26 ignores its reader argument). Tests override it with a failing reader
// to prove crypto/rand errors propagate rather than degrade to a predictable
// nonce/key (AC-17).
var randReader io.Reader = rand.Reader

// framePreimage builds a length-prefixed, domain-separated hash/MAC preimage
// ([SDK-13]: "every hash/MAC preimage is length-prefixed and domain-separated,
// always"). The domain tag and each part are written as uvarint(len)‖bytes, so
// no two distinct (domain, parts) inputs collide by re-splitting a boundary —
// this is the one framing chokepoint (the HKDF salt constructor).
func framePreimage(domain string, parts ...[]byte) []byte {
	var buf []byte
	var lp [binary.MaxVarintLen64]byte
	put := func(b []byte) {
		n := binary.PutUvarint(lp[:], uint64(len(b)))
		buf = append(buf, lp[:n]...)
		buf = append(buf, b...)
	}
	put([]byte(domain))
	for _, p := range parts {
		put(p)
	}
	return buf
}

// constantTimeEqual reports whether a and b are equal, in constant time — the
// only secret/MAC compare primitive (AC-17). GCM tag verification is already
// constant-time inside cipher.AEAD.Open; this covers compares the SDK makes
// itself.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
