package aad

// Sealer declares a nil-AAD API at the interface level — flagged (review
// finding, PR #20); an interface method IS exported surface.
type Sealer interface {
	Seal(plaintext []byte) []byte
}

// AADSealer is the conforming interface shape and must stay clean.
type AADSealer interface {
	SealWithAAD(plaintext, aad []byte) []byte
}

// helper's unexported method is outside the exported-surface population.
type helper interface {
	digest(b []byte) []byte
}
