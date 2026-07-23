package gateway

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/sign"
)

// GatewayTrustBundle is one exact CA-class publication plus, for agent roots
// only, the issuer-scoped CRL receipt that a gateway must enforce.
type GatewayTrustBundle struct {
	Generation               uint64
	Revision                 uint64
	RootCertificateDER       [][]byte
	TransitionCertificateDER []byte
	CRLIssuerFingerprint     []byte
	CRLSequence              uint64
}

// PendingTrustConfirmation retains one exact signed gateway-reporter claim
// until both remote acknowledgement and atomic serving-state publication.
type PendingTrustConfirmation struct {
	Generation           uint64
	Revision             uint64
	RootFingerprints     [][]byte
	CRLIssuerFingerprint []byte
	CRLSequence          uint64
	Signature            []byte
}

// Renew replaces a gateway's per-boot leaf under the currently published key,
// atomically publishes both class bundles, and then confirms the durable state.
func (c *EnrollmentClient) Renew(ctx context.Context, current Identity) (Identity, error) {
	if c == nil || dependencyNil(c.remote) || dependencyNil(c.publisher) || len(c.expectedDNSNames) == 0 || c.now == nil {
		return current, errors.New("gateway: renewal client is not wired")
	}
	if ctx == nil {
		return current, errors.New("gateway: nil renewal context")
	}
	if err := ctx.Err(); err != nil {
		return current, err
	}
	if err := validateCurrentGatewayIdentity(current, c.expectedDNSNames, c.now()); err != nil {
		return current, fmt.Errorf("gateway: validate current identity: %w", err)
	}
	resumed, err := c.resumeGatewayConfirmations(ctx, current)
	if err != nil {
		return current, err
	}
	current = resumed

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, current.PrivateKey)
	if err != nil {
		return current, fmt.Errorf("gateway: create renewal certificate signing request: %w", err)
	}
	response, err := c.remote.RenewGateway(ctx, connect.NewRequest(&powermanagev1.RenewGatewayRequest{
		CertificateDer: bytes.Clone(current.CertificateDER), CertificateSigningRequestDer: csrDER,
	}))
	if err != nil {
		return current, fmt.Errorf("gateway: PkiService renewal: %w", err)
	}
	if response == nil || response.Msg == nil {
		return current, errors.New("gateway: PkiService returned an empty renewal response")
	}
	if response.Msg.GetAgentTrustBundle() == nil {
		return current, errors.New("gateway: renewal response is missing the agent trust bundle")
	}
	if response.Msg.GetGatewayTrustBundle() == nil {
		return current, errors.New("gateway: renewal response is missing the gateway trust bundle")
	}
	now := c.now()
	agentTrust, err := gatewayStoredTrustBundle(response.Msg.GetAgentTrustBundle(), current.AgentTrustBundle, now)
	if err != nil {
		return current, fmt.Errorf("gateway: validate agent trust bundle: %w", err)
	}
	if err := validateGatewayCRLReceipt(agentTrust, true); err != nil {
		return current, err
	}
	if err := validateGatewayCRLIssuerPublished(agentTrust); err != nil {
		return current, err
	}
	gatewayTrust, err := gatewayStoredTrustBundle(response.Msg.GetGatewayTrustBundle(), current.GatewayTrustBundle, now)
	if err != nil {
		return current, fmt.Errorf("gateway: validate gateway trust bundle: %w", err)
	}
	if err := validateGatewayCRLReceipt(gatewayTrust, false); err != nil {
		return current, err
	}
	issuerDER, gatewayID, err := validateRenewedGatewayCertificate(
		response.Msg.GetCertificateDer(), current.PrivateKey, current.GatewayID,
		c.expectedDNSNames, gatewayTrust, now,
	)
	if err != nil {
		return current, err
	}
	replacement := Identity{
		GatewayID: gatewayID, CertificateDER: bytes.Clone(response.Msg.GetCertificateDer()),
		CertificateAuthorityDER: issuerDER, DNSNames: slices.Clone(c.expectedDNSNames),
		PrivateKey: current.PrivateKey, AgentTrustBundle: agentTrust, GatewayTrustBundle: gatewayTrust,
	}
	replacement.PendingGatewayTrustConfirmation, err = newGatewayPendingConfirmation(replacement, "gateway", gatewayTrust)
	if err != nil {
		return current, err
	}
	replacement.PendingAgentTrustConfirmation, err = newGatewayPendingConfirmation(replacement, "agent", agentTrust)
	if err != nil {
		return current, err
	}
	if err := c.publisher.Publish(ctx, replacement); err != nil {
		return current, fmt.Errorf("gateway: publish renewed serving identity: %w", err)
	}
	cleared, err := c.resumeGatewayConfirmations(ctx, replacement)
	if err != nil {
		return replacement, err
	}
	return cleared, nil
}

func (c *EnrollmentClient) resumeGatewayConfirmations(ctx context.Context, value Identity) (Identity, error) {
	items := []struct {
		claimed string
		pending *PendingTrustConfirmation
	}{
		{claimed: "gateway", pending: value.PendingGatewayTrustConfirmation},
		{claimed: "agent", pending: value.PendingAgentTrustConfirmation},
	}
	requests := make([]*powermanagev1.ConfirmTrustStateRequest, 0, 2)
	for _, item := range items {
		if item.pending == nil {
			continue
		}
		request, err := gatewayPendingRequest(value, item.claimed, item.pending)
		if err != nil {
			return value, fmt.Errorf("gateway: validate pending %s trust confirmation: %w", item.claimed, err)
		}
		requests = append(requests, request)
	}
	if len(requests) == 0 {
		return value, nil
	}
	var firstErr error
	for _, request := range requests {
		if _, err := c.remote.ConfirmGatewayTrustState(ctx, connect.NewRequest(request)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return value, firstErr
	}
	cleared := value
	cleared.PendingGatewayTrustConfirmation = nil
	cleared.PendingAgentTrustConfirmation = nil
	if err := c.publisher.Publish(ctx, cleared); err != nil {
		return value, fmt.Errorf("gateway: clear acknowledged trust confirmations: %w", err)
	}
	return cleared, nil
}

func validateCurrentGatewayIdentity(value Identity, expectedDNSNames []string, now time.Time) error {
	if dependencyNil(value.PrivateKey) {
		return errors.New("gateway identity has a nil private key")
	}
	if value.GatewayID == "" || !slices.Equal(value.DNSNames, expectedDNSNames) {
		return errors.New("gateway identity does not match configured identity")
	}
	if _, err := validateEnrollmentResponse(
		value.CertificateDER, value.CertificateAuthorityDER, value.PrivateKey.Public(), expectedDNSNames, now,
	); err != nil {
		return err
	}
	if err := validateGatewayTrustBundle(GatewayTrustBundle{}, value.AgentTrustBundle, now); err != nil {
		return fmt.Errorf("agent trust bundle: %w", err)
	}
	if err := validateGatewayTrustBundle(GatewayTrustBundle{}, value.GatewayTrustBundle, now); err != nil {
		return fmt.Errorf("gateway trust bundle: %w", err)
	}
	if err := validateGatewayCRLReceipt(value.AgentTrustBundle, true); err != nil {
		return err
	}
	if err := validateGatewayCRLReceipt(value.GatewayTrustBundle, false); err != nil {
		return err
	}
	for claimed, pending := range map[string]*PendingTrustConfirmation{
		"agent": value.PendingAgentTrustConfirmation, "gateway": value.PendingGatewayTrustConfirmation,
	} {
		if pending != nil {
			if _, err := gatewayPendingRequest(value, claimed, pending); err != nil {
				return fmt.Errorf("pending %s confirmation: %w", claimed, err)
			}
		}
	}
	return nil
}

func gatewayStoredTrustBundle(message *powermanagev1.CATrustBundle, current GatewayTrustBundle, now time.Time) (GatewayTrustBundle, error) {
	next := GatewayTrustBundle{
		Generation: message.GetGeneration(), Revision: message.GetRevision(),
		RootCertificateDER:       cloneGatewayTrustDER(message.GetRootCertificateDer()),
		TransitionCertificateDER: bytes.Clone(message.GetTransitionCertificateDer()),
		CRLIssuerFingerprint:     bytes.Clone(message.GetCrlIssuerFingerprint()),
		CRLSequence:              message.GetCrlSequence(),
	}
	if err := validateGatewayTrustBundle(current, next, now); err != nil {
		return GatewayTrustBundle{}, err
	}
	if current.Generation == next.Generation && current.Revision == next.Revision && len(current.CRLIssuerFingerprint) != 0 {
		if !bytes.Equal(current.CRLIssuerFingerprint, next.CRLIssuerFingerprint) {
			return GatewayTrustBundle{}, errors.New("crl issuer changed without a trust-bundle version change")
		}
		if next.CRLSequence < current.CRLSequence {
			return GatewayTrustBundle{}, errors.New("crl sequence rollback")
		}
	}
	return next, nil
}

func validateGatewayTrustBundle(current, next GatewayTrustBundle, now time.Time) error {
	if next.Generation == 0 {
		return errors.New("ca bundle generation must be greater than zero")
	}
	if next.Revision == 0 {
		return errors.New("ca bundle revision must be greater than zero")
	}
	if len(next.RootCertificateDER) < 1 || len(next.RootCertificateDER) > 2 {
		return errors.New("ca root bundle must contain one or two roots")
	}
	roots := make([]*x509.Certificate, len(next.RootCertificateDER))
	for index, der := range next.RootCertificateDER {
		root, err := parseGatewayContinuityRoot(der, now)
		if err != nil {
			return fmt.Errorf("root certificate %d: %w", index, err)
		}
		roots[index] = root
		for earlier := 0; earlier < index; earlier++ {
			if bytes.Equal(roots[earlier].Raw, root.Raw) {
				return errors.New("ca root bundle contains a duplicate root")
			}
		}
	}
	if len(roots) == 1 && len(next.TransitionCertificateDER) != 0 {
		return errors.New("unchanged single-root bundle must not carry a transition proof")
	}
	if len(roots) == 2 {
		if len(next.TransitionCertificateDER) == 0 {
			return errors.New("dual-root bundle is missing its transition proof")
		}
		if err := validateGatewayTransitionProof(roots[0], roots[1], next.TransitionCertificateDER, now); err != nil {
			return err
		}
	}
	if current.Generation == 0 {
		return nil
	}
	if next.Generation < current.Generation {
		return errors.New("ca bundle generation rollback")
	}
	if next.Generation == current.Generation && next.Revision < current.Revision {
		return errors.New("ca bundle revision rollback")
	}
	if next.Generation == current.Generation && next.Revision == current.Revision {
		if !equalGatewayTrustBundles(current, next) {
			return errors.New("ca bundle version reused for different contents")
		}
		return nil
	}
	if next.Generation > current.Generation {
		if len(next.RootCertificateDER) != 2 ||
			!bytes.Equal(next.RootCertificateDER[0], current.RootCertificateDER[len(current.RootCertificateDER)-1]) {
			return errors.New("new CA generation lacks a transition proof from the exact current root")
		}
		return nil
	}
	if len(next.RootCertificateDER) != 1 || !containsGatewayDER(current.RootCertificateDER, next.RootCertificateDER[0]) {
		return errors.New("higher CA revision must normalize to an already trusted root")
	}
	return nil
}

func parseGatewayContinuityRoot(der []byte, now time.Time) (*x509.Certificate, error) {
	root, err := parseExactCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("is not exact DER: %w", err)
	}
	if !root.BasicConstraintsValid {
		return nil, errors.New("has invalid basic constraints")
	}
	if !root.IsCA {
		return nil, errors.New("is not a CA")
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

func validateGatewayTransitionProof(current, successor *x509.Certificate, der []byte, now time.Time) error {
	proof, err := parseExactCertificate(der)
	if err != nil {
		return fmt.Errorf("transition proof is not exact DER: %w", err)
	}
	if now.Before(proof.NotBefore) {
		return errors.New("transition proof is not yet valid")
	}
	if now.After(proof.NotAfter) {
		return errors.New("transition proof is expired")
	}
	if !bytes.Equal(proof.RawSubject, successor.RawSubject) {
		return errors.New("transition proof subject does not match root order")
	}
	if !samePublicKey(proof.PublicKey, successor.PublicKey) {
		return errors.New("transition proof public key does not match successor")
	}
	if samePublicKey(current.PublicKey, successor.PublicKey) {
		return errors.New("successor authority reused the current public key")
	}
	if !bytes.Equal(proof.SubjectKeyId, successor.SubjectKeyId) {
		return errors.New("transition proof subject key identifier drift")
	}
	if !proof.BasicConstraintsValid {
		return errors.New("transition proof has invalid basic constraints")
	}
	if !proof.IsCA {
		return errors.New("transition proof is not a CA")
	}
	if proof.MaxPathLen != successor.MaxPathLen || proof.MaxPathLenZero != successor.MaxPathLenZero {
		return errors.New("transition proof path length drift")
	}
	if proof.KeyUsage != successor.KeyUsage {
		return errors.New("transition proof key usage drift")
	}
	if len(proof.UnhandledCriticalExtensions) != 0 {
		return errors.New("transition proof has an unsupported critical extension")
	}
	if !bytes.Equal(proof.RawIssuer, current.RawSubject) {
		return errors.New("transition proof issuer does not match current root")
	}
	if !bytes.Equal(proof.AuthorityKeyId, current.SubjectKeyId) {
		return errors.New("transition proof authority key identifier drift")
	}
	if err := proof.CheckSignatureFrom(current); err != nil {
		return fmt.Errorf("transition proof signature is invalid: %w", err)
	}
	return nil
}

func validateGatewayCRLReceipt(bundle GatewayTrustBundle, required bool) error {
	hasIssuer := len(bundle.CRLIssuerFingerprint) != 0
	hasSequence := bundle.CRLSequence != 0
	if hasIssuer != hasSequence || (hasIssuer && len(bundle.CRLIssuerFingerprint) != sha256.Size) {
		return errors.New("gateway: agent CRL receipt requires an exact issuer fingerprint and sequence")
	}
	if required && !hasIssuer {
		return errors.New("gateway: agent trust bundle is missing its CRL receipt")
	}
	if !required && hasIssuer {
		return errors.New("gateway: gateway trust bundle carries a forbidden CRL receipt")
	}
	return nil
}

func validateGatewayCRLIssuerPublished(bundle GatewayTrustBundle) error {
	for _, root := range bundle.RootCertificateDER {
		fingerprint := sha256.Sum256(root)
		if bytes.Equal(fingerprint[:], bundle.CRLIssuerFingerprint) {
			return nil
		}
	}
	return errors.New("gateway: agent CRL issuer is absent from the published root bundle")
}

func validateRenewedGatewayCertificate(
	certificateDER []byte,
	privateKey crypto.Signer,
	expectedGatewayID string,
	expectedDNSNames []string,
	bundle GatewayTrustBundle,
	now time.Time,
) ([]byte, string, error) {
	certificate, err := parseExactCertificate(certificateDER)
	if err != nil {
		return nil, "", fmt.Errorf("gateway: parse issued certificate: %w", err)
	}
	if !samePublicKey(certificate.PublicKey, privateKey.Public()) {
		return nil, "", errors.New("gateway: issued certificate public key mismatch")
	}
	class, gatewayID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return nil, "", fmt.Errorf("gateway: issued certificate identity is invalid: %w", err)
	}
	if class != identity.GatewayClass {
		return nil, "", errors.New("gateway: issued certificate class is not gateway")
	}
	if gatewayID != expectedGatewayID {
		return nil, "", errors.New("gateway: issued certificate identity changed")
	}
	if now.Before(certificate.NotBefore) {
		return nil, "", errors.New("gateway: issued certificate is not yet valid")
	}
	if now.After(certificate.NotAfter) {
		return nil, "", errors.New("gateway: issued certificate is expired")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		certificate.NotAfter.Sub(certificate.NotBefore) != gatewayCertificateLifetime || !exactGatewayEKUs(certificate.ExtKeyUsage) {
		return nil, "", errors.New("gateway: issued certificate usage or profile is invalid")
	}
	if err := identity.RequireDNSAndURISANs(certificate); err != nil {
		return nil, "", fmt.Errorf("gateway: issued certificate profile is invalid: %w", err)
	}
	if !slices.Equal(certificate.DNSNames, expectedDNSNames) {
		return nil, "", errors.New("gateway: issued certificate DNS names differ from configured identity")
	}
	for _, rootDER := range bundle.RootCertificateDER {
		root, parseErr := parseExactCertificate(rootDER)
		if parseErr == nil && certificate.CheckSignatureFrom(root) == nil {
			return bytes.Clone(rootDER), gatewayID, nil
		}
	}
	return nil, "", errors.New("gateway: issued certificate issuer is outside the published gateway root bundle")
}

func newGatewayPendingConfirmation(value Identity, claimed string, bundle GatewayTrustBundle) (*PendingTrustConfirmation, error) {
	reporterFingerprint := sha256.Sum256(value.CertificateDER)
	claim := sign.TrustStateClaim{
		ReporterClass: "gateway", ClaimedClass: claimed,
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		Generation:                     bundle.Generation, Revision: bundle.Revision,
		RootFingerprints:     gatewayTrustFingerprints(bundle.RootCertificateDER),
		CRLIssuerFingerprint: bytes.Clone(bundle.CRLIssuerFingerprint),
		CRLSequence:          bundle.CRLSequence,
	}
	signature, err := sign.SignTrustState(value.PrivateKey, claim)
	if err != nil {
		return nil, fmt.Errorf("gateway: sign %s trust-state confirmation: %w", claimed, err)
	}
	return &PendingTrustConfirmation{
		Generation: claim.Generation, Revision: claim.Revision,
		RootFingerprints:     cloneGatewayTrustDER(claim.RootFingerprints),
		CRLIssuerFingerprint: bytes.Clone(claim.CRLIssuerFingerprint),
		CRLSequence:          claim.CRLSequence,
		Signature:            bytes.Clone(signature),
	}, nil
}

func gatewayPendingRequest(value Identity, claimed string, pending *PendingTrustConfirmation) (*powermanagev1.ConfirmTrustStateRequest, error) {
	certificate, err := parseExactCertificate(value.CertificateDER)
	if err != nil {
		return nil, err
	}
	reporterFingerprint := sha256.Sum256(value.CertificateDER)
	claim := sign.TrustStateClaim{
		ReporterClass: "gateway", ClaimedClass: claimed,
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		Generation:                     pending.Generation, Revision: pending.Revision,
		RootFingerprints:     cloneGatewayTrustDER(pending.RootFingerprints),
		CRLIssuerFingerprint: bytes.Clone(pending.CRLIssuerFingerprint),
		CRLSequence:          pending.CRLSequence,
	}
	if err := sign.VerifyTrustState(certificate.PublicKey, claim, pending.Signature); err != nil {
		return nil, err
	}
	return &powermanagev1.ConfirmTrustStateRequest{
		CertificateDer: bytes.Clone(value.CertificateDER), ClaimedClass: claimed,
		Generation: pending.Generation, Revision: pending.Revision,
		RootFingerprints:     cloneGatewayTrustDER(pending.RootFingerprints),
		CrlIssuerFingerprint: bytes.Clone(pending.CRLIssuerFingerprint),
		CrlSequence:          pending.CRLSequence,
		Signature:            bytes.Clone(pending.Signature),
	}, nil
}

func gatewayTrustFingerprints(roots [][]byte) [][]byte {
	result := make([][]byte, len(roots))
	for index, root := range roots {
		fingerprint := sha256.Sum256(root)
		result[index] = bytes.Clone(fingerprint[:])
	}
	return result
}

func cloneGatewayTrustDER(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = bytes.Clone(values[index])
	}
	return result
}

func containsGatewayDER(values [][]byte, wanted []byte) bool {
	return slices.ContainsFunc(values, func(value []byte) bool { return bytes.Equal(value, wanted) })
}

func equalGatewayTrustBundles(first, second GatewayTrustBundle) bool {
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
