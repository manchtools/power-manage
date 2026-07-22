package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
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
	eventStore  *store.Store
	authorities *Authorities
	publisher   CRLPublisher
	now         func() time.Time
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
	if interfaceNil(publisher) {
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
	current, err := i.eventStore.LatestCRL(ctx, class)
	if err != nil {
		return store.SignedCRL{}, err
	}
	if current.Sequence > 0 {
		return current, nil
	}
	return i.issue(ctx, class, store.CRLSource{})
}

func (i *CRLIssuer) issue(
	ctx context.Context,
	class store.CertificateClass,
	source store.CRLSource,
) (store.SignedCRL, error) {
	for attempt := range crlStateCASAttempts {
		if err := ctx.Err(); err != nil {
			return store.SignedCRL{}, err
		}
		current, err := i.eventStore.LatestCRL(ctx, class)
		if err != nil {
			return store.SignedCRL{}, err
		}
		if source == (store.CRLSource{}) && current.Sequence > 0 {
			return current, nil
		}
		if source.StreamVersion > 0 {
			receiptSequence, found, err := i.eventStore.CRLWorkReceipt(ctx, class, source)
			if err != nil {
				return store.SignedCRL{}, err
			}
			if found {
				if current.Sequence < receiptSequence {
					return store.SignedCRL{}, errors.New("pki: CRL state precedes its durable work receipt")
				}
				if current.Sequence > receiptSequence {
					return current, nil
				}
				if current.Source != source {
					return store.SignedCRL{}, errors.New("pki: CRL state does not match its durable work receipt")
				}
				if err := i.publisher.Publish(ctx, current); err != nil {
					return store.SignedCRL{}, fmt.Errorf("pki: republish %s CRL: %w", class, err)
				}
				return current, nil
			}
		}
		revocations, err := i.eventStore.CertificateRevocations(ctx, class)
		if err != nil {
			return store.SignedCRL{}, err
		}
		issuedAt := i.now().UTC().Truncate(time.Second)
		if issuedAt.IsZero() {
			return store.SignedCRL{}, errors.New("pki: CRL clock returned zero time")
		}
		if current.IssuedAt.After(issuedAt) {
			issuedAt = current.IssuedAt
		}
		sequence := current.Sequence + 1
		entries, err := revocationListEntries(revocations)
		if err != nil {
			return store.SignedCRL{}, err
		}
		template := &x509.RevocationList{
			RevokedCertificateEntries: entries,
			Number:                    big.NewInt(sequence),
			ThisUpdate:                issuedAt,
			NextUpdate:                issuedAt.Add(DefaultCRLMaxAge),
		}
		der, authority, err := i.sign(class, template)
		if err != nil {
			return store.SignedCRL{}, err
		}
		if err := validateIssuedCRL(der, authority, class, sequence, issuedAt, len(entries)); err != nil {
			return store.SignedCRL{}, err
		}
		stored, err := i.eventStore.CompareAndSwapCRL(ctx, class, current.Sequence, der, issuedAt, source)
		if err != nil {
			return store.SignedCRL{}, err
		}
		if !stored {
			if err := waitForCRLCASRetry(ctx, attempt); err != nil {
				return store.SignedCRL{}, err
			}
			continue
		}
		state := store.SignedCRL{
			Class: class, Sequence: sequence, DER: slices.Clone(der), IssuedAt: issuedAt, Source: source,
		}
		if err := i.publisher.Publish(ctx, state); err != nil {
			return store.SignedCRL{}, fmt.Errorf("pki: publish %s CRL: %w", class, err)
		}
		return state, nil
	}
	return store.SignedCRL{}, errors.New("pki: CRL state remained contended")
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

func (i *CRLIssuer) sign(
	class store.CertificateClass,
	template *x509.RevocationList,
) ([]byte, *x509.Certificate, error) {
	switch class {
	case store.CertificateClassAgent:
		der, err := i.authorities.SignAgentRevocationList(template)
		return der, i.authorities.agentCA.certificate, err
	case store.CertificateClassGateway:
		der, err := i.authorities.SignGatewayRevocationList(template)
		return der, i.authorities.gatewayCA.certificate, err
	default:
		return nil, nil, errors.New("pki: invalid CRL certificate class")
	}
}

func (i *CRLIssuer) validateWiring() error {
	if i == nil || i.eventStore == nil || i.authorities == nil || interfaceNil(i.publisher) || i.now == nil {
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
