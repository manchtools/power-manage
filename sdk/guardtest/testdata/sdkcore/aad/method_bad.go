package aad

type box struct{}

// Seal on a method without aad is a violation too — methods are exported
// surface.
func (box) Seal(plaintext []byte) []byte { return plaintext }

// OpenRenamed carries additional data under another name — flagged, fail
// closed: the surface contract is the parameter named aad.
func OpenRenamed(key, ciphertext, additionalData []byte) ([]byte, error) { return nil, nil }
