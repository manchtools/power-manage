package crypto

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"testing"
)

// --- shared RNG-failure seam (AC-17) ---------------------------------------
//
// errRNG is the sentinel a failingReader returns; tests assert it PROPAGATES
// (errors.Is) out of every crypto/rand consumer, proving the read error is
// wrapped and returned rather than swallowed into a predictable nonce/key.
var errRNG = errors.New("crypto_test: injected crypto/rand failure")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errRNG }

// withFailingRNG swaps the package randReader seam for a reader that always
// errors, restoring the real reader when the test ends.
func withFailingRNG(t *testing.T) {
	t.Helper()
	prev := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = prev })
}

// --- framePreimage ([SDK-13], AC-16) ---------------------------------------

// AC-16 / [SDK-13]: length-prefix framing. Two distinct part-lists whose naive
// concatenation collides ("a"+"bc" == "ab"+"c") must produce different
// preimages — otherwise a salt built from two public keys could be forged by
// re-splitting the boundary.
func TestFramePreimage_LengthPrefixDisambiguates(t *testing.T) {
	a := framePreimage("pm-seal-salt:v1", []byte("a"), []byte("bc"))
	b := framePreimage("pm-seal-salt:v1", []byte("ab"), []byte("c"))
	if bytes.Equal(a, b) {
		t.Errorf("frame(a|bc) == frame(ab|c) = %x: length-prefix framing did not disambiguate the part boundary", a)
	}
}

// AC-16 / [SDK-13]: domain separation. The same parts under a different domain
// tag must produce a different preimage, so two hashing surfaces never derive
// the same value.
func TestFramePreimage_DomainSeparates(t *testing.T) {
	a := framePreimage("pm-seal-salt:v1", []byte("x"))
	b := framePreimage("pm-other-domain:v1", []byte("x"))
	if bytes.Equal(a, b) {
		t.Errorf("frame under two different domains produced identical preimage %x", a)
	}
}

// AC-16 / [SDK-13]: the DOMAIN tag is length-prefixed too, so a part can never
// be absorbed into the domain to forge a collision. framePreimage("a", {0})
// must differ from the single-argument domain "a\x01\x00" — its naive
// concatenation, which collides only if the domain is written unframed.
// Regression for the CodeRabbit domain-framing finding.
func TestFramePreimage_DomainBoundaryDisambiguates(t *testing.T) {
	withPart := framePreimage("a", []byte{0})
	domainOnly := framePreimage("a\x01\x00")
	if bytes.Equal(withPart, domainOnly) {
		t.Errorf("frame(\"a\",{0}) == frame(\"a\\x01\\x00\") = %x: the domain tag is not length-prefixed — a part can be absorbed into the domain", withPart)
	}
}

// --- constantTimeEqual (AC-17) ---------------------------------------------

// AC-17: the secret/MAC compare primitive matches subtle.ConstantTimeCompare
// semantics — equal → true; any single-byte difference or length mismatch →
// false; two empty inputs → true.
func TestConstantTimeEqual_MatchesSubtleSemantics(t *testing.T) {
	cases := []struct {
		name string
		a, b []byte
	}{
		{"equal", []byte("secret-token-value"), []byte("secret-token-value")},
		{"one byte differs", []byte("secret-token-value"), []byte("secret-token-valuE")},
		{"length differs", []byte("secret"), []byte("secret-token-value")},
		{"both empty", []byte{}, []byte{}},
	}
	for _, c := range cases {
		want := subtle.ConstantTimeCompare(c.a, c.b) == 1
		if got := constantTimeEqual(c.a, c.b); got != want {
			t.Errorf("%s: constantTimeEqual(%q,%q) = %v, want %v (subtle semantics)", c.name, c.a, c.b, got, want)
		}
	}
}
