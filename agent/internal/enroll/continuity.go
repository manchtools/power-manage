package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
)

// StoredTrustBundle is one exact, independently versioned CA-class
// publication. TransitionCertificateDER is proof only and is never installed
// in a TLS root or intermediate pool.
type StoredTrustBundle struct {
	Generation               uint64   `json:"generation"`
	Revision                 uint64   `json:"revision"`
	RootCertificateDER       [][]byte `json:"root_certificate_der"`
	TransitionCertificateDER []byte   `json:"transition_certificate_der,omitempty"`
}

// PendingTrustConfirmation is the exact signed state retained until the
// control plane acknowledges one independently retryable class claim.
type PendingTrustConfirmation struct {
	Generation           uint64   `json:"generation"`
	Revision             uint64   `json:"revision"`
	RootFingerprints     [][]byte `json:"root_fingerprints"`
	CRLIssuerFingerprint []byte   `json:"crl_issuer_fingerprint,omitempty"`
	CRLSequence          uint64   `json:"crl_sequence,omitempty"`
	Signature            []byte   `json:"signature"`
}

func storedTrustBundle(message *powermanagev1.CATrustBundle, legacyRoot []byte, current StoredTrustBundle, now time.Time) (StoredTrustBundle, error) {
	if message == nil {
		if len(legacyRoot) == 0 {
			return StoredTrustBundle{}, errors.New("enroll: CA root bundle is absent")
		}
		generation, revision := current.Generation, current.Revision
		if generation == 0 {
			generation, revision = 1, 1
		}
		message = &powermanagev1.CATrustBundle{
			Generation: generation, Revision: revision, RootCertificateDer: [][]byte{legacyRoot},
		}
	}
	bundle := StoredTrustBundle{
		Generation: message.GetGeneration(), Revision: message.GetRevision(),
		RootCertificateDER:       cloneTrustDERList(message.GetRootCertificateDer()),
		TransitionCertificateDER: bytes.Clone(message.GetTransitionCertificateDer()),
	}
	if err := validateTrustBundle(current, bundle, now); err != nil {
		return StoredTrustBundle{}, err
	}
	return bundle, nil
}

func validateTrustBundle(current, next StoredTrustBundle, now time.Time) error {
	if next.Generation == 0 {
		return errors.New("enroll: CA bundle generation must be greater than zero")
	}
	if next.Revision == 0 {
		return errors.New("enroll: CA bundle revision must be greater than zero")
	}
	if len(next.RootCertificateDER) < 1 || len(next.RootCertificateDER) > 2 {
		return errors.New("enroll: CA root bundle must contain one or two roots")
	}
	roots := make([]*x509.Certificate, len(next.RootCertificateDER))
	for index, der := range next.RootCertificateDER {
		root, err := parseContinuityRoot(der, now)
		if err != nil {
			return fmt.Errorf("enroll: root certificate %d: %w", index, err)
		}
		roots[index] = root
		for earlier := 0; earlier < index; earlier++ {
			if bytes.Equal(roots[earlier].Raw, root.Raw) {
				return errors.New("enroll: CA root bundle contains a duplicate root")
			}
		}
	}
	if len(roots) == 1 && len(next.TransitionCertificateDER) != 0 {
		return errors.New("enroll: unchanged single-root bundle must not carry a transition proof")
	}
	if len(roots) == 2 {
		if len(next.TransitionCertificateDER) == 0 {
			return errors.New("enroll: dual-root bundle is missing its transition proof")
		}
		if err := validateTransitionProof(roots[0], roots[1], next.TransitionCertificateDER, now); err != nil {
			return err
		}
	}

	if current.Generation == 0 {
		return nil
	}
	if next.Generation < current.Generation {
		return errors.New("enroll: CA bundle generation rollback")
	}
	if next.Generation == current.Generation && next.Revision < current.Revision {
		return errors.New("enroll: CA bundle revision rollback")
	}
	if next.Generation == current.Generation && next.Revision == current.Revision {
		if !equalStoredTrustBundles(current, next) {
			return errors.New("enroll: CA bundle version reused for different contents")
		}
		return nil
	}
	if next.Generation > current.Generation {
		if len(current.RootCertificateDER) == 0 {
			return errors.New("enroll: current CA bundle has no roots to transition from")
		}
		if len(next.RootCertificateDER) != 2 ||
			!bytes.Equal(next.RootCertificateDER[0], current.RootCertificateDER[len(current.RootCertificateDER)-1]) {
			return errors.New("enroll: new CA generation lacks a transition proof from the exact pending root")
		}
		return nil
	}
	// A higher revision within one generation is an abort or retirement
	// normalization: it prunes to one already trusted root and carries no proof.
	if len(next.RootCertificateDER) != 1 || !containsExactDER(current.RootCertificateDER, next.RootCertificateDER[0]) {
		return errors.New("enroll: higher CA revision must normalize to an already trusted root")
	}
	return nil
}

func parseContinuityRoot(der []byte, now time.Time) (*x509.Certificate, error) {
	if now.IsZero() {
		return nil, errors.New("validation clock is zero")
	}
	root, err := parseExactCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("is not exact DER: %w", err)
	}
	if !root.IsCA {
		return nil, errors.New("is not a CA")
	}
	if !root.BasicConstraintsValid {
		return nil, errors.New("has invalid basic constraints")
	}
	if root.MaxPathLen != 0 || !root.MaxPathLenZero {
		return nil, errors.New("has an invalid path length")
	}
	if root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return nil, errors.New("has invalid key usage")
	}
	if len(root.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("has an unsupported critical extension")
	}
	if err := sign.ValidateSigningKey(root.PublicKey); err != nil {
		return nil, fmt.Errorf("has an invalid public key: %w", err)
	}
	if now.Before(root.NotBefore) {
		return nil, errors.New("is not yet valid")
	}
	if now.After(root.NotAfter) {
		return nil, errors.New("is expired")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("is not self-signed: %w", err)
	}
	return root, nil
}

func validateTransitionProof(current, successor *x509.Certificate, der []byte, now time.Time) error {
	if now.IsZero() {
		return errors.New("enroll: transition-proof validation clock is zero")
	}
	proof, err := parseExactCertificate(der)
	if err != nil {
		return fmt.Errorf("enroll: transition proof is not exact DER: %w", err)
	}
	if now.Before(proof.NotBefore) {
		return errors.New("enroll: transition proof is not yet valid")
	}
	if now.After(proof.NotAfter) {
		return errors.New("enroll: transition proof is expired")
	}
	if !bytes.Equal(proof.RawSubject, successor.RawSubject) {
		return errors.New("enroll: transition proof subject does not match root order")
	}
	if !publicKeysEqual(proof.PublicKey, successor.PublicKey) {
		return errors.New("enroll: transition proof public key does not match successor")
	}
	if publicKeysEqual(current.PublicKey, successor.PublicKey) {
		return errors.New("enroll: successor authority reused the current public key")
	}
	if !bytes.Equal(proof.SubjectKeyId, successor.SubjectKeyId) {
		return errors.New("enroll: transition proof subject key identifier drift")
	}
	if !proof.BasicConstraintsValid {
		return errors.New("enroll: transition proof has invalid basic constraints")
	}
	if !proof.IsCA {
		return errors.New("enroll: transition proof is not a CA")
	}
	if proof.MaxPathLen != successor.MaxPathLen || proof.MaxPathLenZero != successor.MaxPathLenZero {
		return errors.New("enroll: transition proof path length drift")
	}
	if proof.KeyUsage != successor.KeyUsage {
		return errors.New("enroll: transition proof key usage drift")
	}
	if len(proof.UnhandledCriticalExtensions) != 0 {
		return errors.New("enroll: transition proof has an unsupported critical extension")
	}
	if !bytes.Equal(proof.RawIssuer, current.RawSubject) {
		return errors.New("enroll: transition proof issuer does not match current root")
	}
	if !bytes.Equal(proof.AuthorityKeyId, current.SubjectKeyId) {
		return errors.New("enroll: transition proof authority key identifier drift")
	}
	if err := proof.CheckSignatureFrom(current); err != nil {
		return fmt.Errorf("enroll: transition proof signature is invalid: %w", err)
	}
	return nil
}

func selectIssuingRoot(certificateDER []byte, bundle StoredTrustBundle) ([]byte, error) {
	certificate, err := parseExactCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("enroll: parse issued certificate: %w", err)
	}
	for _, der := range bundle.RootCertificateDER {
		root, parseErr := parseExactCertificate(der)
		if parseErr == nil && certificate.CheckSignatureFrom(root) == nil {
			return bytes.Clone(der), nil
		}
	}
	return nil, errors.New("enroll: issued certificate is not signed by the published agent root bundle")
}

func validateSeparatedTrustBundles(agent, gateway StoredTrustBundle) error {
	for _, agentDER := range agent.RootCertificateDER {
		agentRoot, err := parseExactCertificate(agentDER)
		if err != nil {
			return err
		}
		for _, gatewayDER := range gateway.RootCertificateDER {
			gatewayRoot, err := parseExactCertificate(gatewayDER)
			if err != nil {
				return err
			}
			if bytes.Equal(agentRoot.Raw, gatewayRoot.Raw) || publicKeysEqual(agentRoot.PublicKey, gatewayRoot.PublicKey) {
				return errors.New("enroll: agent and gateway certificate authorities are not distinct")
			}
		}
	}
	return nil
}

func newPendingTrustConfirmation(bundle CredentialBundle, claimedClass string, trust StoredTrustBundle) (*PendingTrustConfirmation, error) {
	reporterFingerprint := sha256.Sum256(bundle.CertificateDER)
	claim := sign.TrustStateClaim{
		ReporterClass: "agent", ClaimedClass: claimedClass,
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		Generation:                     trust.Generation, Revision: trust.Revision,
		RootFingerprints: fingerprintsForRoots(trust.RootCertificateDER),
	}
	signature, err := sign.SignTrustState(bundle.PrivateKey, claim)
	if err != nil {
		return nil, fmt.Errorf("enroll: sign %s trust-state confirmation: %w", claimedClass, err)
	}
	return &PendingTrustConfirmation{
		Generation: claim.Generation, Revision: claim.Revision,
		RootFingerprints:     cloneTrustDERList(claim.RootFingerprints),
		CRLIssuerFingerprint: bytes.Clone(claim.CRLIssuerFingerprint),
		CRLSequence:          claim.CRLSequence,
		Signature:            bytes.Clone(signature),
	}, nil
}

func (c *Client) sendPendingConfirmations(ctx context.Context, bundle *CredentialBundle) error {
	var firstErr error
	for _, item := range []struct {
		claimed string
		pending **PendingTrustConfirmation
	}{
		{claimed: "agent", pending: &bundle.PendingAgentTrustConfirmation},
		{claimed: "gateway", pending: &bundle.PendingGatewayTrustConfirmation},
	} {
		if *item.pending == nil {
			continue
		}
		request, err := pendingTrustRequest(*bundle, item.claimed, *item.pending)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("enroll: validate pending %s trust confirmation: %w", item.claimed, err)
			}
			continue
		}
		if _, err := c.remote.ConfirmAgentTrustState(ctx, connect.NewRequest(request)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		acknowledged := *item.pending
		*item.pending = nil
		if err := c.store.Replace(ctx, *bundle); err != nil {
			*item.pending = acknowledged
			if firstErr == nil {
				firstErr = fmt.Errorf("enroll: clear acknowledged %s trust confirmation: %w", item.claimed, err)
			}
		}
	}
	return firstErr
}

func pendingTrustRequest(bundle CredentialBundle, claimedClass string, pending *PendingTrustConfirmation) (*powermanagev1.ConfirmTrustStateRequest, error) {
	if pending == nil {
		return nil, errors.New("pending trust confirmation is nil")
	}
	certificate, err := parseExactCertificate(bundle.CertificateDER)
	if err != nil {
		return nil, fmt.Errorf("pending reporter certificate: %w", err)
	}
	reporterFingerprint := sha256.Sum256(bundle.CertificateDER)
	claim := sign.TrustStateClaim{
		ReporterClass: "agent", ClaimedClass: claimedClass,
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		Generation:                     pending.Generation, Revision: pending.Revision,
		RootFingerprints:     cloneTrustDERList(pending.RootFingerprints),
		CRLIssuerFingerprint: bytes.Clone(pending.CRLIssuerFingerprint),
		CRLSequence:          pending.CRLSequence,
	}
	if err := sign.VerifyTrustState(certificate.PublicKey, claim, pending.Signature); err != nil {
		return nil, fmt.Errorf("pending trust-state signature: %w", err)
	}
	return &powermanagev1.ConfirmTrustStateRequest{
		CertificateDer: bytes.Clone(bundle.CertificateDER), ClaimedClass: claimedClass,
		Generation: pending.Generation, Revision: pending.Revision,
		RootFingerprints:     cloneTrustDERList(pending.RootFingerprints),
		CrlIssuerFingerprint: bytes.Clone(pending.CRLIssuerFingerprint),
		CrlSequence:          pending.CRLSequence,
		Signature:            bytes.Clone(pending.Signature),
	}, nil
}

func validatePendingTrustConfirmations(bundle CredentialBundle) error {
	for claimedClass, pending := range map[string]*PendingTrustConfirmation{
		"agent": bundle.PendingAgentTrustConfirmation, "gateway": bundle.PendingGatewayTrustConfirmation,
	} {
		if pending == nil {
			continue
		}
		if _, err := pendingTrustRequest(bundle, claimedClass, pending); err != nil {
			return err
		}
	}
	return nil
}

func validateCredentialContinuity(bundle CredentialBundle, now time.Time) error {
	agentAbsent := bundle.AgentTrustBundle.Generation == 0 && len(bundle.AgentTrustBundle.RootCertificateDER) == 0
	gatewayAbsent := bundle.GatewayTrustBundle.Generation == 0 && len(bundle.GatewayTrustBundle.RootCertificateDER) == 0
	if agentAbsent && gatewayAbsent {
		if bundle.PendingAgentTrustConfirmation != nil || bundle.PendingGatewayTrustConfirmation != nil {
			return errors.New("enroll: pending trust confirmation has no stored CA bundle")
		}
		return nil
	}
	if agentAbsent || gatewayAbsent {
		return errors.New("enroll: agent and gateway CA bundles must be stored atomically")
	}
	if err := validateTrustBundle(StoredTrustBundle{}, bundle.AgentTrustBundle, now); err != nil {
		return fmt.Errorf("agent trust bundle: %w", err)
	}
	if err := validateTrustBundle(StoredTrustBundle{}, bundle.GatewayTrustBundle, now); err != nil {
		return fmt.Errorf("gateway trust bundle: %w", err)
	}
	if !containsExactDER(bundle.AgentTrustBundle.RootCertificateDER, bundle.CertificateAuthorityDER) {
		return errors.New("enroll: active agent issuer is absent from the stored trust bundle")
	}
	if !containsExactDER(bundle.GatewayTrustBundle.RootCertificateDER, bundle.GatewayCertificateAuthorityDER) {
		return errors.New("enroll: compatibility gateway root is absent from the stored trust bundle")
	}
	if err := validateSeparatedTrustBundles(bundle.AgentTrustBundle, bundle.GatewayTrustBundle); err != nil {
		return err
	}
	return nil
}

func fingerprintsForRoots(roots [][]byte) [][]byte {
	fingerprints := make([][]byte, len(roots))
	for index, root := range roots {
		fingerprint := sha256.Sum256(root)
		fingerprints[index] = bytes.Clone(fingerprint[:])
	}
	return fingerprints
}

func cloneTrustDERList(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = bytes.Clone(values[index])
	}
	return result
}

func containsExactDER(values [][]byte, wanted []byte) bool {
	return slices.ContainsFunc(values, func(value []byte) bool { return bytes.Equal(value, wanted) })
}

func equalStoredTrustBundles(first, second StoredTrustBundle) bool {
	if first.Generation != second.Generation || first.Revision != second.Revision ||
		!bytes.Equal(first.TransitionCertificateDER, second.TransitionCertificateDER) || len(first.RootCertificateDER) != len(second.RootCertificateDER) {
		return false
	}
	for index := range first.RootCertificateDER {
		if !bytes.Equal(first.RootCertificateDER[index], second.RootCertificateDER[index]) {
			return false
		}
	}
	return true
}
