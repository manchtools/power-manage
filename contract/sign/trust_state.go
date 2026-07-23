package sign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
)

// TrustStateSignatureDomain separates CA-continuity confirmations from every
// command and result signature domain.
const TrustStateSignatureDomain = "power-manage:trust-state:v1"

const sha256FingerprintSize = sha256.Size

// TrustStateClaim is the exact state a certificate-authenticated agent or
// gateway confirms after durably adopting a published trust bundle.
type TrustStateClaim struct {
	ReporterClass                  string
	ClaimedClass                   string
	ReporterCertificateFingerprint []byte
	Generation                     uint64
	Revision                       uint64
	RootFingerprints               [][]byte
	CRLIssuerFingerprint           []byte
	CRLSequence                    uint64
}

// TrustStatePreimage returns the length-prefixed, domain-separated signing
// input for a CA-continuity confirmation.
func TrustStatePreimage(claim TrustStateClaim) ([]byte, error) {
	if err := validateTrustStateClaim(claim, true); err != nil {
		return nil, err
	}
	return trustStatePreimage(claim), nil
}

// SignTrustState signs an exact CA-continuity claim with the reporter's
// currently authenticated identity key.
func SignTrustState(key crypto.Signer, claim TrustStateClaim) ([]byte, error) {
	if err := ValidateSigningKey(key); err != nil {
		return nil, err
	}
	preimage, err := TrustStatePreimage(claim)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(preimage)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign trust-state preimage: %w", err)
	}
	return signature, nil
}

// VerifyTrustState verifies a CA-continuity claim under the public key from
// the exact certificate whose fingerprint is covered by the claim.
func VerifyTrustState(publicKey crypto.PublicKey, claim TrustStateClaim, signature []byte) error {
	if err := ValidateSigningKey(publicKey); err != nil {
		return err
	}
	if len(signature) == 0 {
		return fmt.Errorf("trust-state signature is empty")
	}
	if err := validateTrustStateClaim(claim, false); err != nil {
		return err
	}

	preimage := trustStatePreimage(claim)
	digest := sha256.Sum256(preimage)
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		var parsed struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
			return fmt.Errorf("trust-state signature is malformed")
		}
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return fmt.Errorf("trust-state signature is invalid")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("trust-state signature is invalid: %w", err)
		}
	default:
		return fmt.Errorf("unsupported trust-state verification key type %T", publicKey)
	}
	return validateTrustStateClaim(claim, true)
}

func validateTrustStateClaim(claim TrustStateClaim, rejectForbiddenReceipt bool) error {
	if claim.ReporterClass != "agent" && claim.ReporterClass != "gateway" {
		return fmt.Errorf("reporter class must be agent or gateway")
	}
	if claim.ClaimedClass != "agent" && claim.ClaimedClass != "gateway" {
		return fmt.Errorf("claimed class must be agent or gateway")
	}
	if len(claim.ReporterCertificateFingerprint) != sha256FingerprintSize {
		return fmt.Errorf("reporter certificate fingerprint must be a SHA-256 fingerprint")
	}
	if claim.Generation == 0 {
		return fmt.Errorf("generation must be greater than zero")
	}
	if claim.Revision == 0 {
		return fmt.Errorf("revision must be greater than zero")
	}
	if len(claim.RootFingerprints) < 1 || len(claim.RootFingerprints) > 2 {
		return fmt.Errorf("root fingerprints must contain one or two entries")
	}
	for index, fingerprint := range claim.RootFingerprints {
		if len(fingerprint) != sha256FingerprintSize {
			return fmt.Errorf("root fingerprint %d must be a SHA-256 fingerprint", index)
		}
		for earlier := 0; earlier < index; earlier++ {
			if bytes.Equal(fingerprint, claim.RootFingerprints[earlier]) {
				return fmt.Errorf("root fingerprints must be distinct")
			}
		}
	}

	requiresReceipt := claim.ReporterClass == "gateway" && claim.ClaimedClass == "agent"
	hasIssuer := len(claim.CRLIssuerFingerprint) != 0
	hasSequence := claim.CRLSequence != 0
	if hasIssuer != hasSequence || (hasIssuer && len(claim.CRLIssuerFingerprint) != sha256FingerprintSize) {
		return fmt.Errorf("crl receipt requires a SHA-256 issuer fingerprint and non-zero sequence")
	}
	if requiresReceipt && !hasIssuer {
		return fmt.Errorf("crl receipt is required when a gateway confirms agent trust")
	}
	if rejectForbiddenReceipt && !requiresReceipt && hasIssuer {
		return fmt.Errorf("crl receipt is forbidden for this reporter and claimed class")
	}
	return nil
}

func trustStatePreimage(claim TrustStateClaim) []byte {
	var buffer bytes.Buffer
	lp(&buffer, []byte(TrustStateSignatureDomain))
	lp(&buffer, []byte(claim.ReporterClass))
	lp(&buffer, []byte(claim.ClaimedClass))
	lp(&buffer, claim.ReporterCertificateFingerprint)
	lp(&buffer, uint64Bytes(claim.Generation))
	lp(&buffer, uint64Bytes(claim.Revision))
	lp(&buffer, uint64Bytes(uint64(len(claim.RootFingerprints))))
	for _, fingerprint := range claim.RootFingerprints {
		lp(&buffer, fingerprint)
	}
	lp(&buffer, claim.CRLIssuerFingerprint)
	lp(&buffer, uint64Bytes(claim.CRLSequence))
	return buffer.Bytes()
}

func uint64Bytes(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}
