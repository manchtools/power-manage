package aad

// SealNoAAD is the planted violation: an exported seal entry without an
// aad parameter.
func SealNoAAD(key, plaintext []byte) []byte { return append(key, plaintext...) }

// OpenWithAAD is the conforming shape and must stay clean.
func OpenWithAAD(key, ciphertext, aad []byte) ([]byte, error) { return nil, nil }

// sealInternal is unexported — outside the exported-surface population.
func sealInternal(key []byte) []byte { return key }

// Digest is exported but neither seal nor open — outside the population.
func Digest(b []byte) []byte { return b }
