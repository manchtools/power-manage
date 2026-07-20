package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

// testInfo is a REPRESENTATIVE mandated info string, used here as a plain
// string parameter. The SDK stays proto-free: the real caller reads the
// versioned constant from contract/seal and passes it in. Using the literal
// value pins that SealToPublicKey/OpenWithPrivateKey treat info as an opaque
// domain-separation tag.
const testInfo = "power-manage-lps-password:v1"

// genRecipient mints a recipient keypair with the real RNG directly (NOT the
// package's GenerateX25519, which has its own tests), so the sealed-transport
// tests do not depend on that function's implementation.
func genRecipient(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recipient: %v", err)
	}
	return priv
}

// realEphemeralPub returns a valid 32-byte X25519 public key so that malformed
// input tests can exercise the Ciphertext-length path with an ephemeral key
// that actually parses and ECDHs.
func realEphemeralPub(t *testing.T) []byte {
	t.Helper()
	return genRecipient(t).PublicKey().Bytes()
}

// AC-16: SealToPublicKey → OpenWithPrivateKey round-trips the exact plaintext
// under X25519+HKDF-SHA256+AES-256-GCM with a mandated info string and AAD
// context.
func TestSealToPublicKey_RoundTrip(t *testing.T) {
	priv := genRecipient(t)
	pt := []byte("s3cret-rotated-password")
	aad := []byte("device|action|user")

	sealed, err := SealToPublicKey(priv.PublicKey(), pt, aad, testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	got, err := OpenWithPrivateKey(priv, sealed, aad, testInfo)
	if err != nil {
		t.Fatalf("OpenWithPrivateKey: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("round-trip = %q, want %q", got, pt)
	}
}

// AC-16 (interop / SealedBlob mapping): the sealed output carries an exactly
// 32-byte ephemeral public key and a Ciphertext of at least nonce(12)+tag(16)+1
// bytes.
func TestSealToPublicKey_SealedLayout(t *testing.T) {
	priv := genRecipient(t)
	sealed, err := SealToPublicKey(priv.PublicKey(), []byte("x"), []byte("a"), testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	if len(sealed.EphemeralPublicKey) != 32 {
		t.Errorf("EphemeralPublicKey = %d bytes, want 32", len(sealed.EphemeralPublicKey))
	}
	if min := gcmNonceLen + gcmTagLen + 1; len(sealed.Ciphertext) < min {
		t.Errorf("Ciphertext = %d bytes, want >= %d (nonce||ct||tag with >=1 plaintext byte)", len(sealed.Ciphertext), min)
	}
}

// AC-16 / [SDK-14] (rejection row "empty ... plaintext", seal side): empty
// plaintext is rejected at SealToPublicKey with ErrEmptyPlaintext.
func TestSealToPublicKey_RejectsEmptyPlaintext(t *testing.T) {
	priv := genRecipient(t)
	aad := []byte("a")
	for _, pt := range [][]byte{nil, {}} {
		if _, err := SealToPublicKey(priv.PublicKey(), pt, aad, testInfo); !errors.Is(err, ErrEmptyPlaintext) {
			t.Errorf("SealToPublicKey empty plaintext (%v): err = %v, want ErrEmptyPlaintext", pt, err)
		}
	}
}

// AC-16 (rejection row "empty AAD", seal side): empty AAD rejected at
// SealToPublicKey with ErrAADRequired.
func TestSealToPublicKey_RejectsEmptyAAD(t *testing.T) {
	priv := genRecipient(t)
	pt := []byte("x")
	for _, aad := range [][]byte{nil, {}} {
		if _, err := SealToPublicKey(priv.PublicKey(), pt, aad, testInfo); !errors.Is(err, ErrAADRequired) {
			t.Errorf("SealToPublicKey empty AAD (%v): err = %v, want ErrAADRequired", aad, err)
		}
	}
}

// AC-16 (rejection row, domain separation): empty info string rejected at
// SealToPublicKey with ErrInfoRequired (no naked seal call).
func TestSealToPublicKey_RejectsEmptyInfo(t *testing.T) {
	priv := genRecipient(t)
	if _, err := SealToPublicKey(priv.PublicKey(), []byte("x"), []byte("a"), ""); !errors.Is(err, ErrInfoRequired) {
		t.Errorf("SealToPublicKey empty info: err = %v, want ErrInfoRequired", err)
	}
}

// AC-16 (rejection row "empty AAD", open side): empty AAD rejected at
// OpenWithPrivateKey with ErrAADRequired — symmetric with seal.
func TestOpenWithPrivateKey_RejectsEmptyAAD(t *testing.T) {
	priv := genRecipient(t)
	sealed, err := SealToPublicKey(priv.PublicKey(), []byte("x"), []byte("a"), testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	for _, aad := range [][]byte{nil, {}} {
		if _, err := OpenWithPrivateKey(priv, sealed, aad, testInfo); !errors.Is(err, ErrAADRequired) {
			t.Errorf("OpenWithPrivateKey empty AAD (%v): err = %v, want ErrAADRequired", aad, err)
		}
	}
}

// AC-16 (rejection row, domain separation, open side): empty info rejected at
// OpenWithPrivateKey with ErrInfoRequired — symmetric with seal.
func TestOpenWithPrivateKey_RejectsEmptyInfo(t *testing.T) {
	priv := genRecipient(t)
	sealed, err := SealToPublicKey(priv.PublicKey(), []byte("x"), []byte("a"), testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	if _, err := OpenWithPrivateKey(priv, sealed, []byte("a"), ""); !errors.Is(err, ErrInfoRequired) {
		t.Errorf("OpenWithPrivateKey empty info: err = %v, want ErrInfoRequired", err)
	}
}

// AC-16 (fail closed): opening with a DIFFERENT recipient private key fails and
// returns no plaintext.
func TestOpenWithPrivateKey_WrongPrivateKeyFails(t *testing.T) {
	priv := genRecipient(t)
	sealed, err := SealToPublicKey(priv.PublicKey(), []byte("s3cret"), []byte("a"), testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	other := genRecipient(t)
	if pt, err := OpenWithPrivateKey(other, sealed, []byte("a"), testInfo); err == nil {
		t.Fatalf("opened with the wrong private key, returned %q; want failure", pt)
	}
}

// AC-16 (fail closed on AAD mismatch): opening under a different AAD than was
// sealed fails and returns no plaintext.
func TestOpenWithPrivateKey_WrongAADFails(t *testing.T) {
	priv := genRecipient(t)
	sealed, err := SealToPublicKey(priv.PublicKey(), []byte("s3cret"), []byte("device|action|user"), testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	if pt, err := OpenWithPrivateKey(priv, sealed, []byte("device|action|OTHER"), testInfo); err == nil {
		t.Fatalf("opened under the wrong AAD, returned %q; want failure", pt)
	}
}

// AC-16 (fail closed, domain separation): opening under a different info string
// derives a different HKDF key, so the open fails and returns no plaintext.
func TestOpenWithPrivateKey_WrongInfoFails(t *testing.T) {
	priv := genRecipient(t)
	sealed, err := SealToPublicKey(priv.PublicKey(), []byte("s3cret"), []byte("a"), testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	if pt, err := OpenWithPrivateKey(priv, sealed, []byte("a"), "power-manage-other-domain:v1"); err == nil {
		t.Fatalf("opened under the wrong info string, returned %q; want failure", pt)
	}
}

// AC-16 (tamper): flipping a byte of the ephemeral public key makes the open
// fail (a different ECDH shared secret → different key → auth failure).
func TestOpenWithPrivateKey_TamperedEphemeralPublicKeyFails(t *testing.T) {
	priv := genRecipient(t)
	sealed, err := SealToPublicKey(priv.PublicKey(), []byte("s3cret"), []byte("a"), testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	if len(sealed.EphemeralPublicKey) == 0 {
		t.Fatalf("seal produced an empty ephemeral public key; cannot tamper")
	}
	tampered := Sealed{
		EphemeralPublicKey: bytes.Clone(sealed.EphemeralPublicKey),
		Ciphertext:         bytes.Clone(sealed.Ciphertext),
	}
	tampered.EphemeralPublicKey[0] ^= 0x01
	if pt, err := OpenWithPrivateKey(priv, tampered, []byte("a"), testInfo); err == nil {
		t.Fatalf("opened a tampered ephemeral key, returned %q; want failure", pt)
	}
}

// AC-16 (tamper): flipping a byte of the ciphertext makes the open fail
// authentication and return no plaintext.
func TestOpenWithPrivateKey_TamperedCiphertextFails(t *testing.T) {
	priv := genRecipient(t)
	sealed, err := SealToPublicKey(priv.PublicKey(), []byte("s3cret"), []byte("a"), testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	if len(sealed.Ciphertext) == 0 {
		t.Fatalf("seal produced an empty ciphertext; cannot tamper")
	}
	tampered := Sealed{
		EphemeralPublicKey: bytes.Clone(sealed.EphemeralPublicKey),
		Ciphertext:         bytes.Clone(sealed.Ciphertext),
	}
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0x01
	if pt, err := OpenWithPrivateKey(priv, tampered, []byte("a"), testInfo); err == nil {
		t.Fatalf("opened a tampered ciphertext, returned %q; want failure", pt)
	}
}

// AC-16 (malformed input): a Sealed whose Ciphertext is too short to carry a
// nonce and tag is rejected with ErrMalformedCiphertext (the ephemeral key is a
// real, parseable 32-byte value so the length path, not the parse path, fires).
func TestOpenWithPrivateKey_RejectsMalformedCiphertext(t *testing.T) {
	priv := genRecipient(t)
	for _, n := range []int{0, 4, gcmNonceLen, gcmNonceLen + gcmTagLen - 1} {
		sealed := Sealed{EphemeralPublicKey: realEphemeralPub(t), Ciphertext: make([]byte, n)}
		if _, err := OpenWithPrivateKey(priv, sealed, []byte("a"), testInfo); !errors.Is(err, ErrMalformedCiphertext) {
			t.Errorf("OpenWithPrivateKey %d-byte ciphertext: err = %v, want ErrMalformedCiphertext", n, err)
		}
	}
}

// AC-16 (malformed input): a Sealed whose EphemeralPublicKey is not 32 bytes is
// rejected with an error and no plaintext.
func TestOpenWithPrivateKey_RejectsBadEphemeralKeyLength(t *testing.T) {
	priv := genRecipient(t)
	for _, n := range []int{0, 31, 33} {
		sealed := Sealed{
			EphemeralPublicKey: make([]byte, n),
			Ciphertext:         make([]byte, gcmNonceLen+gcmTagLen+1),
		}
		if pt, err := OpenWithPrivateKey(priv, sealed, []byte("a"), testInfo); err == nil {
			t.Errorf("OpenWithPrivateKey %d-byte ephemeral key: opened, returned %q; want error", n, pt)
		}
	}
}

// AC-16 (fresh ephemeral per seal): sealing the same plaintext to the same
// recipient twice yields different blobs AND different ephemeral public keys.
func TestSealToPublicKey_OutputsDiffer(t *testing.T) {
	priv := genRecipient(t)
	pt := []byte("same-plaintext")
	aad := []byte("same-aad")
	a, err := SealToPublicKey(priv.PublicKey(), pt, aad, testInfo)
	if err != nil {
		t.Fatalf("seal a: %v", err)
	}
	b, err := SealToPublicKey(priv.PublicKey(), pt, aad, testInfo)
	if err != nil {
		t.Fatalf("seal b: %v", err)
	}
	if len(a.Ciphertext) == 0 || len(a.EphemeralPublicKey) == 0 {
		t.Fatalf("seal produced empty output (eph %d, ct %d bytes)", len(a.EphemeralPublicKey), len(a.Ciphertext))
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Error("two seals of the same plaintext produced identical ciphertext — nonce or ephemeral key reused")
	}
	if bytes.Equal(a.EphemeralPublicKey, b.EphemeralPublicKey) {
		t.Error("two seals produced identical ephemeral public keys — ephemeral key reused")
	}
}

// AC-16: ParseX25519PublicKey accepts exactly 32 bytes and round-trips the
// encoding.
func TestParseX25519PublicKey_RoundTrip(t *testing.T) {
	raw := genRecipient(t).PublicKey().Bytes()
	pub, err := ParseX25519PublicKey(raw)
	if err != nil {
		t.Fatalf("ParseX25519PublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("ParseX25519PublicKey returned a nil key with no error")
	}
	if !bytes.Equal(pub.Bytes(), raw) {
		t.Error("parsed key does not round-trip its encoding")
	}
}

// AC-16 (correct/absent/wrong): ParseX25519PublicKey rejects any input that is
// not exactly 32 bytes.
func TestParseX25519PublicKey_RejectsNon32(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if pub, err := ParseX25519PublicKey(make([]byte, n)); err == nil {
			t.Errorf("ParseX25519PublicKey accepted %d bytes, returned %v; want error", n, pub)
		}
	}
}

// AC-16: GenerateX25519 returns a usable recipient keypair (non-nil private key
// whose public key encodes to 32 bytes).
func TestGenerateX25519_ReturnsUsableKeypair(t *testing.T) {
	priv, err := GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	if priv == nil {
		t.Fatal("GenerateX25519 returned a nil private key with no error")
	}
	if got := len(priv.PublicKey().Bytes()); got != 32 {
		t.Errorf("public key = %d bytes, want 32", got)
	}
}

// AC-17: with the RNG seam forced to fail, GenerateX25519 returns the wrapped
// read error and no key — never a predictable key.
func TestGenerateX25519_RngFailurePropagates(t *testing.T) {
	withFailingRNG(t)
	priv, err := GenerateX25519()
	if !errors.Is(err, errRNG) {
		t.Errorf("GenerateX25519 under RNG failure: err = %v, want it to wrap the injected RNG error", err)
	}
	if priv != nil {
		t.Error("GenerateX25519 returned a key under RNG failure; must return none")
	}
}

// AC-17: with the RNG seam forced to fail, SealToPublicKey (ephemeral keygen)
// returns the wrapped read error and emits no output.
func TestSealToPublicKey_RngFailurePropagates(t *testing.T) {
	recipient := genRecipient(t).PublicKey() // minted before the RNG is broken
	withFailingRNG(t)
	sealed, err := SealToPublicKey(recipient, []byte("pt"), []byte("aad"), testInfo)
	if !errors.Is(err, errRNG) {
		t.Errorf("SealToPublicKey under RNG failure: err = %v, want it to wrap the injected RNG error", err)
	}
	if sealed.EphemeralPublicKey != nil || sealed.Ciphertext != nil {
		t.Errorf("SealToPublicKey emitted output under RNG failure: eph=%x ct=%x; must emit none", sealed.EphemeralPublicKey, sealed.Ciphertext)
	}
}
