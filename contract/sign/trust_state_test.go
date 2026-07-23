package sign_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/contract/sign"
)

func TestTrustStateSignature_BindsExactClassBundleAndIssuerReceipt(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate trust-state signing key: %v", err)
	}
	firstRoot := sha256.Sum256([]byte("first root DER"))
	secondRoot := sha256.Sum256([]byte("second root DER"))
	issuer := sha256.Sum256([]byte("successor issuer DER"))
	reporterCertificate := sha256.Sum256([]byte("exact reporter certificate DER"))
	claim := sign.TrustStateClaim{
		ReporterClass: "gateway", ClaimedClass: "agent",
		Generation: 7, Revision: 3,
		ReporterCertificateFingerprint: reporterCertificate[:],
		RootFingerprints:               [][]byte{firstRoot[:], secondRoot[:]},
		CRLIssuerFingerprint:           issuer[:], CRLSequence: 11,
	}
	signature, err := sign.SignTrustState(key, claim)
	if err != nil {
		t.Fatalf("SignTrustState: %v", err)
	}
	if err := sign.VerifyTrustState(&key.PublicKey, claim, signature); err != nil {
		t.Fatalf("VerifyTrustState: %v", err)
	}

	tests := []struct {
		name    string
		wantErr string
		mutate  func(*sign.TrustStateClaim)
	}{
		{name: "reporter class", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) { c.ReporterClass = "agent" }},
		{name: "reporter certificate", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) { c.ReporterCertificateFingerprint[0] ^= 0xff }},
		{name: "claimed class", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) { c.ClaimedClass = "gateway" }},
		{name: "generation", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) { c.Generation++ }},
		{name: "revision", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) { c.Revision++ }},
		{name: "root ordering", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) {
			c.RootFingerprints[0], c.RootFingerprints[1] = c.RootFingerprints[1], c.RootFingerprints[0]
		}},
		{name: "root fingerprint", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) { c.RootFingerprints[0][0] ^= 0xff }},
		{name: "issuer fingerprint", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) { c.CRLIssuerFingerprint[0] ^= 0xff }},
		{name: "CRL sequence", wantErr: "trust-state signature is invalid", mutate: func(c *sign.TrustStateClaim) { c.CRLSequence++ }},
		{name: "missing receipt", wantErr: "crl receipt", mutate: func(c *sign.TrustStateClaim) { c.CRLIssuerFingerprint = nil; c.CRLSequence = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneTrustStateClaim(claim)
			test.mutate(&changed)
			if err := sign.VerifyTrustState(&key.PublicKey, changed, signature); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("VerifyTrustState error = %v; want %q", err, test.wantErr)
			}
		})
	}

	preimage, err := sign.TrustStatePreimage(claim)
	if err != nil {
		t.Fatalf("TrustStatePreimage: %v", err)
	}
	if bytes.Contains(preimage, []byte(sign.ActionSignatureDomain)) ||
		!bytes.Contains(preimage, []byte(sign.TrustStateSignatureDomain)) {
		t.Fatalf("trust-state preimage domain separation = %q; want only %q", preimage, sign.TrustStateSignatureDomain)
	}
}

func TestTrustStateSignature_RejectsAbsentMalformedAndWrongShapeClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate trust-state signing key: %v", err)
	}
	fingerprint := sha256.Sum256([]byte("root"))
	reporterCertificate := sha256.Sum256([]byte("reporter certificate"))
	valid := sign.TrustStateClaim{
		ReporterClass: "agent", ClaimedClass: "gateway", Generation: 1, Revision: 1,
		ReporterCertificateFingerprint: reporterCertificate[:],
		RootFingerprints:               [][]byte{fingerprint[:]},
	}
	tests := []struct {
		name    string
		wantErr string
		mutate  func(*sign.TrustStateClaim)
	}{
		{name: "absent reporter class", wantErr: "reporter class", mutate: func(c *sign.TrustStateClaim) { c.ReporterClass = "" }},
		{name: "unknown reporter class", wantErr: "reporter class", mutate: func(c *sign.TrustStateClaim) { c.ReporterClass = "operator" }},
		{name: "absent reporter certificate fingerprint", wantErr: "reporter certificate fingerprint", mutate: func(c *sign.TrustStateClaim) { c.ReporterCertificateFingerprint = nil }},
		{name: "short reporter certificate fingerprint", wantErr: "reporter certificate fingerprint", mutate: func(c *sign.TrustStateClaim) { c.ReporterCertificateFingerprint = []byte{1} }},
		{name: "absent claimed class", wantErr: "claimed class", mutate: func(c *sign.TrustStateClaim) { c.ClaimedClass = "" }},
		{name: "zero generation", wantErr: "generation", mutate: func(c *sign.TrustStateClaim) { c.Generation = 0 }},
		{name: "zero revision", wantErr: "revision", mutate: func(c *sign.TrustStateClaim) { c.Revision = 0 }},
		{name: "absent roots", wantErr: "root fingerprints", mutate: func(c *sign.TrustStateClaim) { c.RootFingerprints = nil }},
		{name: "too many roots", wantErr: "root fingerprints", mutate: func(c *sign.TrustStateClaim) {
			c.RootFingerprints = append(c.RootFingerprints, fingerprint[:], fingerprint[:])
		}},
		{name: "short root fingerprint", wantErr: "root fingerprint", mutate: func(c *sign.TrustStateClaim) { c.RootFingerprints[0] = []byte{1} }},
		{name: "duplicate roots", wantErr: "root fingerprints", mutate: func(c *sign.TrustStateClaim) { c.RootFingerprints = append(c.RootFingerprints, c.RootFingerprints[0]) }},
		{name: "sequence without issuer", wantErr: "crl receipt", mutate: func(c *sign.TrustStateClaim) { c.CRLSequence = 1 }},
		{name: "issuer without sequence", wantErr: "crl receipt", mutate: func(c *sign.TrustStateClaim) { c.CRLIssuerFingerprint = fingerprint[:] }},
		{name: "unauthorized gateway CRL receipt", wantErr: "crl receipt", mutate: func(c *sign.TrustStateClaim) {
			c.CRLIssuerFingerprint = fingerprint[:]
			c.CRLSequence = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim := cloneTrustStateClaim(valid)
			test.mutate(&claim)
			if _, err := sign.SignTrustState(key, claim); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("SignTrustState error = %v; want %q", err, test.wantErr)
			}
		})
	}
	leaf := cloneTrustStateClaim(valid)
	leaf.ClaimedClass = leaf.ReporterClass
	if _, err := sign.SignTrustState(key, leaf); err != nil {
		t.Fatalf("SignTrustState rejected the reporter's same-class successor-leaf adoption: %v", err)
	}
	signature, err := sign.SignTrustState(key, valid)
	if err != nil {
		t.Fatalf("sign valid trust-state claim: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong verification key: %v", err)
	}
	for _, test := range []struct {
		name      string
		signature []byte
		key       *ecdsa.PublicKey
		wantErr   string
	}{
		{name: "absent signature", signature: nil, key: &key.PublicKey, wantErr: "signature is empty"},
		{name: "malformed signature", signature: []byte("not ASN.1"), key: &key.PublicKey, wantErr: "signature is malformed"},
		{name: "wrong key", signature: signature, key: &otherKey.PublicKey, wantErr: "signature is invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := sign.VerifyTrustState(test.key, valid, test.signature); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("VerifyTrustState error = %v; want %q", err, test.wantErr)
			}
		})
	}
}

func cloneTrustStateClaim(value sign.TrustStateClaim) sign.TrustStateClaim {
	roots := value.RootFingerprints
	value.RootFingerprints = make([][]byte, len(value.RootFingerprints))
	for index := range value.RootFingerprints {
		value.RootFingerprints[index] = bytes.Clone(roots[index])
	}
	value.CRLIssuerFingerprint = bytes.Clone(value.CRLIssuerFingerprint)
	value.ReporterCertificateFingerprint = bytes.Clone(value.ReporterCertificateFingerprint)
	return value
}
