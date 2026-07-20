package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
)

const (
	gcmNonceLen = 12
	gcmTagLen   = 16
)

// key32 returns a fresh random 32-byte AES-256 key using the real RNG (never
// the package randReader seam), so key material is independent of any injected
// RNG failure under test.
func key32(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return k
}

// gcmSealRaw independently builds a wire-layout AES-256-GCM blob
// (nonce(12)||ct||tag(16)) with stdlib crypto — NOT a reimplementation for
// round-trip use. It exists only to manufacture a VALID ciphertext for inputs
// that SealWithAAD itself refuses to produce (an empty plaintext), so the
// open-side rejection can be tested symmetrically.
func gcmSealRaw(t *testing.T, key, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad)
}

// AC-16: SealWithAAD → OpenWithAAD round-trips a non-empty plaintext under a
// 32-byte key and non-empty AAD; the ciphertext never contains the plaintext
// verbatim; the output is exactly nonce(12)||ct||tag(16).
func TestSealWithAAD_RoundTrip(t *testing.T) {
	key := key32(t)
	pt := []byte("super secret credential")
	aad := []byte("pm-agent:credentials:v1")

	ct, err := SealWithAAD(key, pt, aad)
	if err != nil {
		t.Fatalf("SealWithAAD: %v", err)
	}
	if want := gcmNonceLen + len(pt) + gcmTagLen; len(ct) != want {
		t.Errorf("sealed length = %d, want %d (nonce||ct||tag)", len(ct), want)
	}
	if bytes.Contains(ct, pt) {
		t.Error("ciphertext contains the plaintext verbatim")
	}
	got, err := OpenWithAAD(key, ct, aad)
	if err != nil {
		t.Fatalf("OpenWithAAD: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("round-trip = %q, want %q", got, pt)
	}
}

// AC-16 / [SDK-14] (rejection row "Seal/open with empty ... plaintext"): the
// behavior change from the predecessor — SealWithAAD REJECTS an empty (nil and
// zero-length) plaintext with ErrEmptyPlaintext instead of round-tripping it.
func TestSealWithAAD_RejectsEmptyPlaintext(t *testing.T) {
	key := key32(t)
	aad := []byte("domain")
	for _, pt := range [][]byte{nil, {}} {
		if _, err := SealWithAAD(key, pt, aad); !errors.Is(err, ErrEmptyPlaintext) {
			t.Errorf("SealWithAAD empty plaintext (%v): err = %v, want ErrEmptyPlaintext", pt, err)
		}
	}
}

// AC-16 (rejection row "empty ... key"): a key that is not exactly 32 bytes is
// rejected at seal with ErrInvalidKey — the wrong case violates the real
// 32-byte AES-256 constraint.
func TestSealWithAAD_RejectsBadKeyLength(t *testing.T) {
	aad := []byte("d")
	pt := []byte("x")
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := SealWithAAD(make([]byte, n), pt, aad); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("SealWithAAD %d-byte key: err = %v, want ErrInvalidKey", n, err)
		}
	}
}

// AC-16 (rejection row "empty AAD"): domain-separation AAD is mandatory; a
// nil/empty AAD is rejected at seal with ErrAADRequired (no naked AEAD call).
func TestSealWithAAD_RejectsEmptyAAD(t *testing.T) {
	key := key32(t)
	pt := []byte("x")
	for _, aad := range [][]byte{nil, {}} {
		if _, err := SealWithAAD(key, pt, aad); !errors.Is(err, ErrAADRequired) {
			t.Errorf("SealWithAAD empty AAD (%v): err = %v, want ErrAADRequired", aad, err)
		}
	}
}

// AC-16 / [SDK-14] SYMMETRY: a ciphertext that authenticates and decrypts to an
// EMPTY plaintext is rejected by OpenWithAAD with ErrEmptyPlaintext — the same
// value seal refuses, open must also refuse. The blob is forged with stdlib GCM
// because SealWithAAD will not produce it.
func TestOpenWithAAD_RejectsEmptyPlaintext(t *testing.T) {
	key := key32(t)
	aad := []byte("domain")
	blob := gcmSealRaw(t, key, []byte{}, aad) // valid AEAD of empty plaintext
	if _, err := OpenWithAAD(key, blob, aad); !errors.Is(err, ErrEmptyPlaintext) {
		t.Errorf("OpenWithAAD of a valid empty-plaintext blob: err = %v, want ErrEmptyPlaintext", err)
	}
}

// AC-16 (rejection row "empty AAD", open side): OpenWithAAD rejects a nil/empty
// AAD with ErrAADRequired — symmetric with seal.
func TestOpenWithAAD_RejectsEmptyAAD(t *testing.T) {
	key := key32(t)
	for _, aad := range [][]byte{nil, {}} {
		if _, err := OpenWithAAD(key, make([]byte, 64), aad); !errors.Is(err, ErrAADRequired) {
			t.Errorf("OpenWithAAD empty AAD (%v): err = %v, want ErrAADRequired", aad, err)
		}
	}
}

// AC-16 (rejection row "empty ... key", open side): OpenWithAAD rejects a key
// that is not 32 bytes with ErrInvalidKey — symmetric with seal.
func TestOpenWithAAD_RejectsBadKeyLength(t *testing.T) {
	aad := []byte("d")
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := OpenWithAAD(make([]byte, n), make([]byte, 64), aad); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("OpenWithAAD %d-byte key: err = %v, want ErrInvalidKey", n, err)
		}
	}
}

// AC-16 (fail closed on AAD mismatch): opening under a DIFFERENT AAD than was
// sealed fails authentication and returns no plaintext.
func TestOpenWithAAD_WrongAADFails(t *testing.T) {
	key := key32(t)
	ct, err := SealWithAAD(key, []byte("x"), []byte("domain-A"))
	if err != nil {
		t.Fatalf("SealWithAAD: %v", err)
	}
	pt, err := OpenWithAAD(key, ct, []byte("domain-B"))
	if err == nil {
		t.Fatalf("open under a different AAD succeeded, returned %q; want authentication failure", pt)
	}
	if pt != nil {
		t.Errorf("open returned %q alongside an error; must return no plaintext (fail closed)", pt)
	}
}

// AC-16 (fail closed on wrong key): opening under a different key than was
// sealed fails and returns no plaintext.
func TestOpenWithAAD_WrongKeyFails(t *testing.T) {
	aad := []byte("d")
	ct, err := SealWithAAD(key32(t), []byte("x"), aad)
	if err != nil {
		t.Fatalf("SealWithAAD: %v", err)
	}
	pt, err := OpenWithAAD(key32(t), ct, aad)
	if err == nil {
		t.Fatalf("open under a different key succeeded, returned %q; want failure", pt)
	}
	if pt != nil {
		t.Errorf("open returned %q alongside an error; must return no plaintext", pt)
	}
}

// AC-16 (rejection row, malformed input): a ciphertext too short to carry both
// a 12-byte nonce and a 16-byte tag is rejected up front with the precise
// ErrMalformedCiphertext, not a generic downstream auth error.
func TestOpenWithAAD_RejectsMalformedCiphertext(t *testing.T) {
	key := key32(t)
	aad := []byte("d")
	// 27 = one byte short of nonce(12)+tag(16).
	for _, n := range []int{0, 4, gcmNonceLen, gcmNonceLen + gcmTagLen - 1} {
		if _, err := OpenWithAAD(key, make([]byte, n), aad); !errors.Is(err, ErrMalformedCiphertext) {
			t.Errorf("OpenWithAAD %d-byte ciphertext: err = %v, want ErrMalformedCiphertext", n, err)
		}
	}
}

// AC-16 (tamper): flipping a single ciphertext/tag byte makes OpenWithAAD fail
// authentication and return no plaintext.
func TestOpenWithAAD_RejectsTamperedCiphertext(t *testing.T) {
	key := key32(t)
	aad := []byte("d")
	ct, err := SealWithAAD(key, []byte("hello world"), aad)
	if err != nil {
		t.Fatalf("SealWithAAD: %v", err)
	}
	if len(ct) < gcmNonceLen+gcmTagLen+1 {
		t.Fatalf("seal produced a %d-byte blob; too short to tamper meaningfully", len(ct))
	}
	ct[len(ct)-1] ^= 0xff // flip a tag byte
	if pt, err := OpenWithAAD(key, ct, aad); err == nil {
		t.Fatalf("tampered ciphertext opened successfully, returned %q; want authentication failure", pt)
	}
}

// AC-16 (nonce freshness): two seals of identical (key, plaintext, aad) yield
// different outputs — a fresh random nonce per call, never a reused nonce
// (catastrophic for GCM).
func TestSealWithAAD_NonceIsRandomPerCall(t *testing.T) {
	key := key32(t)
	pt := []byte("identical plaintext")
	aad := []byte("identical aad")
	a, err := SealWithAAD(key, pt, aad)
	if err != nil {
		t.Fatalf("SealWithAAD a: %v", err)
	}
	b, err := SealWithAAD(key, pt, aad)
	if err != nil {
		t.Fatalf("SealWithAAD b: %v", err)
	}
	if len(a) == 0 || len(b) == 0 {
		t.Fatalf("seal produced empty output (%d, %d bytes)", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Error("two seals of identical input are byte-identical — the nonce is not random (nonce reuse)")
	}
}

// AC-17: with the RNG seam forced to fail, SealWithAAD returns the wrapped read
// error (errors.Is the injected sentinel) and emits no output — never a
// predictable nonce.
func TestSealWithAAD_RngFailurePropagates(t *testing.T) {
	withFailingRNG(t)
	out, err := SealWithAAD(key32(t), []byte("pt"), []byte("aad"))
	if !errors.Is(err, errRNG) {
		t.Errorf("SealWithAAD under RNG failure: err = %v, want it to wrap the injected RNG error", err)
	}
	if out != nil {
		t.Errorf("SealWithAAD emitted %d bytes under RNG failure; must emit no output", len(out))
	}
}
