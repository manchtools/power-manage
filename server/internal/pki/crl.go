package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/sdk/nilcheck"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	// DefaultCRLMaxAge is the signed-list lifetime consumed by gateway
	// cold-boot policy.
	DefaultCRLMaxAge    = 7 * 24 * time.Hour
	crlStateCASAttempts = 16
)

// CRLPublisher distributes one durable signed CRL to connected gateways.
type CRLPublisher interface {
	Publish(context.Context, store.SignedCRL) error
}

// CRLIssuer materializes event-derived revocations into monotonic signed CRLs.
type CRLIssuer struct {
	eventStore      *store.Store
	authorities     *Authorities
	publisher       CRLPublisher
	rotationManager *RotationManager
	now             func() time.Time
}

// NewCRLIssuer validates the production, state, and distribution seams.
func NewCRLIssuer(eventStore *store.Store, authorities *Authorities, publisher CRLPublisher) (*CRLIssuer, error) {
	if eventStore == nil {
		return nil, errors.New("pki: nil CRL event store")
	}
	if authorities == nil || authorities.agentCA.certificate == nil || authorities.agentCA.signer == nil ||
		authorities.gatewayCA.certificate == nil || authorities.gatewayCA.signer == nil {
		return nil, errors.New("pki: CRL authorities are not wired")
	}
	if nilcheck.Interface(publisher) {
		return nil, errors.New("pki: CRL publisher is not wired")
	}
	return &CRLIssuer{eventStore: eventStore, authorities: authorities, publisher: publisher, now: time.Now}, nil
}

// WorkHandlers returns the exact durable-work registry owned by CRL issuance.
func (i *CRLIssuer) WorkHandlers() map[string]store.WorkHandler {
	if i == nil {
		return nil
	}
	return map[string]store.WorkHandler{
		store.PublishAgentCRLWorkKind:   i.HandleAgentCRLWork,
		store.PublishGatewayCRLWorkKind: i.HandleGatewayCRLWork,
	}
}

// HandleAgentCRLWork validates durable work before issuing an agent CRL.
func (i *CRLIssuer) HandleAgentCRLWork(ctx context.Context, item store.WorkItem) error {
	return i.handleCRLWork(ctx, item, store.PublishAgentCRLWorkKind, "device", "agent", store.CertificateClassAgent)
}

// HandleGatewayCRLWork validates durable work before issuing a gateway CRL.
func (i *CRLIssuer) HandleGatewayCRLWork(ctx context.Context, item store.WorkItem) error {
	return i.handleCRLWork(ctx, item, store.PublishGatewayCRLWorkKind, "gateway", "gateway", store.CertificateClassGateway)
}

func (i *CRLIssuer) handleCRLWork(
	ctx context.Context,
	item store.WorkItem,
	wantKind string,
	wantStreamType string,
	workClass string,
	certificateClass store.CertificateClass,
) error {
	if err := i.validateWiring(); err != nil {
		return err
	}
	if ctx == nil {
		return fmt.Errorf("pki: nil %s CRL work context", workClass)
	}
	if item.Kind != wantKind || item.PayloadVersion != 1 || !bytes.Equal(item.Payload, []byte(`{}`)) ||
		item.SourceStreamType != wantStreamType || !identity.IsCanonicalULID(item.SourceStreamID) || item.SourceStreamVersion < 2 {
		return fmt.Errorf("pki: invalid %s CRL work item", workClass)
	}
	_, err := i.issue(ctx, certificateClass, store.CRLSource{
		StreamType: item.SourceStreamType, StreamID: item.SourceStreamID, StreamVersion: item.SourceStreamVersion,
	})
	return err
}

// EnsureCurrent issues the initial empty CRL when a class has no publication.
func (i *CRLIssuer) EnsureCurrent(ctx context.Context, class store.CertificateClass) (store.SignedCRL, error) {
	if err := i.validateWiring(); err != nil {
		return store.SignedCRL{}, err
	}
	if ctx == nil {
		return store.SignedCRL{}, errors.New("pki: nil ensure-current CRL context")
	}
	return i.issue(ctx, class, store.CRLSource{})
}

func (i *CRLIssuer) issue(
	ctx context.Context,
	class store.CertificateClass,
	source store.CRLSource,
) (store.SignedCRL, error) {
	return i.sign(ctx, class, source)
}

func (i *CRLIssuer) sign(
	ctx context.Context,
	class store.CertificateClass,
	source store.CRLSource,
) (store.SignedCRL, error) {
	var result store.SignedCRL
	err := i.withCRLIssuerFence(ctx, class, func() error {
		issuerFingerprint, authority, active, err := i.crlAuthority(ctx, class, source)
		if err != nil {
			return err
		}
		if !active {
			return nil
		}
		// The shared class fence spans this entire callback, including every CAS
		// attempt and its commit, so rotation cannot invalidate this authority.
		for attempt := range crlStateCASAttempts {
			if err := ctx.Err(); err != nil {
				return err
			}
			current, err := i.eventStore.LatestCRL(ctx, class, issuerFingerprint)
			if err != nil {
				return err
			}
			if source == (store.CRLSource{}) && current.Sequence > 0 {
				result = current
				return nil
			}
			if source.StreamVersion > 0 {
				receiptSequence, found, err := i.eventStore.CRLWorkReceipt(ctx, class, issuerFingerprint, source)
				if err != nil {
					return err
				}
				if found {
					if current.Sequence < receiptSequence {
						return errors.New("pki: CRL state precedes its durable work receipt")
					}
					if current.Sequence > receiptSequence {
						result = current
						return nil
					}
					if current.Source != source {
						result = current
						return nil
					}
					if err := i.publisher.Publish(ctx, current); err != nil {
						return fmt.Errorf("pki: republish %s CRL: %w", class, err)
					}
					result = current
					return nil
				}
			}
			revocations, err := i.eventStore.CertificateRevocations(ctx, class)
			if err != nil {
				return err
			}
			issuedAt := i.now().UTC().Truncate(time.Second)
			if issuedAt.IsZero() {
				return errors.New("pki: CRL clock returned zero time")
			}
			if current.IssuedAt.After(issuedAt) {
				issuedAt = current.IssuedAt
			}
			sequence := current.Sequence + 1
			entries, coveredSources, err := revocationListEntriesForIssuer(revocations, authority)
			if err != nil {
				return err
			}
			template := &x509.RevocationList{
				RevokedCertificateEntries: entries,
				Number:                    big.NewInt(sequence),
				ThisUpdate:                issuedAt,
				NextUpdate:                issuedAt.Add(DefaultCRLMaxAge),
			}
			var der []byte
			switch class {
			case store.CertificateClassAgent:
				if i.rotationManager == nil {
					der, err = i.authorities.SignAgentRevocationList(template)
				} else {
					der, err = i.authorities.signRevocationListForIssuer(class, issuerFingerprint, template)
				}
			case store.CertificateClassGateway:
				if i.rotationManager == nil {
					der, err = i.authorities.SignGatewayRevocationList(template)
				} else {
					der, err = i.authorities.signRevocationListForIssuer(class, issuerFingerprint, template)
				}
			default:
				return errors.New("pki: invalid CRL certificate class")
			}
			if err != nil {
				return err
			}
			if err := validateIssuedCRL(der, authority, class, sequence, issuedAt, len(entries)); err != nil {
				return err
			}
			stored, err := i.eventStore.CompareAndSwapCRL(ctx, class, issuerFingerprint, current.Sequence, der, issuedAt, source)
			if err != nil {
				return err
			}
			if !stored {
				if err := waitForCRLCASRetry(ctx, attempt); err != nil {
					return err
				}
				continue
			}
			for _, coveredSource := range coveredSources {
				if err := i.eventStore.RecordCoveredCRLWorkReceipt(
					ctx, class, issuerFingerprint, coveredSource, sequence,
				); err != nil {
					return err
				}
			}
			result = store.SignedCRL{
				Class: class, IssuerFingerprint: issuerFingerprint,
				Sequence: sequence, DER: slices.Clone(der), IssuedAt: issuedAt, Source: source,
			}
			if err := i.publisher.Publish(ctx, result); err != nil {
				return fmt.Errorf("pki: publish %s CRL: %w", class, err)
			}
			return nil
		}
		return errors.New("pki: CRL state remained contended")
	})
	if err != nil {
		return store.SignedCRL{}, err
	}
	return result, nil
}

func (i *CRLIssuer) withCRLIssuerFence(
	ctx context.Context,
	class store.CertificateClass,
	action func() error,
) error {
	if action == nil {
		return errors.New("pki: nil CRL issuer action")
	}
	if i.rotationManager == nil {
		return action()
	}
	return i.rotationManager.withCRLIssuerFence(ctx, class, action)
}

func (i *CRLIssuer) crlAuthority(
	ctx context.Context,
	class store.CertificateClass,
	source store.CRLSource,
) ([sha256.Size]byte, *x509.Certificate, bool, error) {
	if i.rotationManager == nil {
		authority, ok := i.authorities.currentAuthority(class)
		if !ok {
			return [sha256.Size]byte{}, nil, false, errors.New("pki: current CRL authority is not wired")
		}
		return [sha256.Size]byte{}, authority.certificate, true, nil
	}
	snapshot, err := i.rotationManager.Snapshot(ctx, class)
	if err != nil {
		return [sha256.Size]byte{}, nil, false, err
	}
	rootDER := snapshot.IssuingRootDER
	if source.StreamVersion > 0 {
		revocations, err := i.eventStore.CertificateRevocations(ctx, class)
		if err != nil {
			return [sha256.Size]byte{}, nil, false, err
		}
		rootDER = nil
		for _, revocation := range revocations {
			if revocation.SourceStreamType != source.StreamType || revocation.SourceStreamID != source.StreamID ||
				revocation.SourceStreamVersion != source.StreamVersion {
				continue
			}
			certificate, err := parseExactCertificate(revocation.CertificateDER)
			if err != nil {
				return [sha256.Size]byte{}, nil, false, err
			}
			for _, candidate := range activeCRLRoots(snapshot) {
				root, err := parseExactCertificate(candidate)
				if err == nil && certificate.CheckSignatureFrom(root) == nil {
					rootDER = candidate
					break
				}
			}
			break
		}
		if len(rootDER) == 0 {
			return [sha256.Size]byte{}, nil, false, nil
		}
	}
	fingerprint := sha256.Sum256(rootDER)
	authority, ok := i.authorities.authorityForIssuer(class, fingerprint)
	if !ok {
		return [sha256.Size]byte{}, nil, false, errors.New("pki: active CRL authority is not wired")
	}
	return fingerprint, authority.certificate, true, nil
}

func waitForCRLCASRetry(ctx context.Context, attempt int) error {
	delay := time.Millisecond << min(attempt, 6)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (i *CRLIssuer) validateWiring() error {
	if i == nil || i.eventStore == nil || i.authorities == nil || nilcheck.Interface(i.publisher) || i.now == nil {
		return errors.New("pki: CRL issuer is not wired")
	}
	return nil
}

func revocationListEntries(revocations []store.CertificateRevocation) ([]x509.RevocationListEntry, error) {
	entries := make([]x509.RevocationListEntry, 0, len(revocations))
	for _, revocation := range revocations {
		if len(revocation.SerialNumber) == 0 || revocation.RevokedAt.IsZero() {
			return nil, errors.New("pki: invalid projected certificate revocation")
		}
		serial := new(big.Int).SetBytes(revocation.SerialNumber)
		if serial.Sign() <= 0 {
			return nil, errors.New("pki: revoked certificate serial is not positive")
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revocation.RevokedAt.UTC().Truncate(time.Second),
			ReasonCode:     revocation.ReasonCode,
		})
	}
	return entries, nil
}

func revocationListEntriesForIssuer(
	revocations []store.CertificateRevocation,
	authority *x509.Certificate,
) ([]x509.RevocationListEntry, []store.CRLSource, error) {
	if authority == nil {
		return nil, nil, errors.New("pki: CRL authority is missing")
	}
	filtered := make([]store.CertificateRevocation, 0, len(revocations))
	sources := make([]store.CRLSource, 0, len(revocations))
	for _, revocation := range revocations {
		certificate, err := parseExactCertificate(revocation.CertificateDER)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: parse revoked certificate: %w", err)
		}
		if bytes.Equal(revocation.IssuerIdentifier, authority.SubjectKeyId) && certificate.CheckSignatureFrom(authority) == nil {
			filtered = append(filtered, revocation)
			sources = append(sources, store.CRLSource{
				StreamType: revocation.SourceStreamType, StreamID: revocation.SourceStreamID,
				StreamVersion: revocation.SourceStreamVersion,
			})
		}
	}
	entries, err := revocationListEntries(filtered)
	return entries, sources, err
}

func validateIssuedCRL(
	der []byte,
	authority *x509.Certificate,
	class store.CertificateClass,
	sequence int64,
	issuedAt time.Time,
	entryCount int,
) error {
	list, err := parseExactRevocationList(der)
	if err != nil {
		return fmt.Errorf("pki: parse issued %s CRL: %w", class, err)
	}
	if authority == nil {
		return fmt.Errorf("pki: issued %s CRL authority is missing", class)
	}
	if err := list.CheckSignatureFrom(authority); err != nil {
		return fmt.Errorf("pki: issued %s CRL signature is invalid: %w", class, err)
	}
	if list.Number == nil || !list.Number.IsInt64() || list.Number.Int64() != sequence ||
		!list.ThisUpdate.Equal(issuedAt) || len(list.RevokedCertificateEntries) != entryCount {
		return fmt.Errorf("pki: issued %s CRL content is mismatched", class)
	}
	return nil
}

func parseExactRevocationList(der []byte) (*x509.RevocationList, error) {
	owned := slices.Clone(der)
	list, err := x509.ParseRevocationList(owned)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(list.Raw, owned) {
		return nil, errors.New("revocation-list DER contains trailing data")
	}
	return list, nil
}
