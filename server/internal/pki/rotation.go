package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/store"
)

// RotationPhase is one node in the exact CA continuity graph.
type RotationPhase string

const (
	RotationPhaseStable  RotationPhase = "stable"
	RotationPhaseTrust   RotationPhase = "trust"
	RotationPhaseMigrate RotationPhase = "migrate"
	RotationPhaseRetire  RotationPhase = "retire"
)

const (
	AgentLeafTrustConfirmed       = "AgentLeafTrustConfirmed"
	AgentConsumerTrustConfirmed   = "AgentConsumerTrustConfirmed"
	GatewayLeafTrustConfirmed     = "GatewayLeafTrustConfirmed"
	GatewayConsumerTrustConfirmed = "GatewayConsumerTrustConfirmed"
)

const (
	agentRotationFenceKey   int64 = 0x60060001
	gatewayRotationFenceKey int64 = 0x60060002
)

// ErrTrustStateRejected deliberately hides reporter existence and state.
var ErrTrustStateRejected = errors.New("trust state confirmation rejected")

// AuthoritySnapshot is an immutable, complete view of one CA class.
type AuthoritySnapshot struct {
	Class                        store.CertificateClass
	Phase                        RotationPhase
	Generation                   uint64
	Revision                     uint64
	DesiredRootDER               [][]byte
	IssuingRootDER               []byte
	SuccessorRootDER             []byte
	PredecessorRootDER           []byte
	TransitionCertificateDER     []byte
	RequiredCRLIssuerFingerprint []byte
	RequiredCRLSequence          uint64
	PublishedCRLSequence         uint64
}

// TrustBundlePublication is the immutable distribution unit for one phase.
type TrustBundlePublication struct {
	Class                    store.CertificateClass
	Generation               uint64
	Revision                 uint64
	RootCertificateDER       [][]byte
	TransitionCertificateDER []byte
	CRLIssuerFingerprints    [][sha256.Size]byte
}

// TrustBundleDistributor publishes committed trust intent to consumers.
type TrustBundleDistributor interface {
	PublishTrustBundle(context.Context, TrustBundlePublication) error
}

// RotationManagerConfig wires durable state, signing custody, and distribution.
type RotationManagerConfig struct {
	EventStore       *store.Store
	Authorities      *Authorities
	Distributor      TrustBundleDistributor
	SuccessorSigners map[store.CertificateClass]crypto.Signer
}

// RotationManager coordinates independent agent and gateway CA generations.
type RotationManager struct {
	eventStore       *store.Store
	authorities      *Authorities
	distributor      TrustBundleDistributor
	signerMu         sync.RWMutex
	successorSigners map[store.CertificateClass]crypto.Signer
	now              func() time.Time
}

// TrustStateConfirmation binds an exact reporter certificate to one claim.
type TrustStateConfirmation struct {
	ReporterCertificateDER []byte
	Claim                  sign.TrustStateClaim
	Signature              []byte
}

// ControlTrustStateConfirmation is control's intrinsic gateway-root receipt.
type ControlTrustStateConfirmation struct {
	ClaimedClass         store.CertificateClass
	Generation           uint64
	Revision             uint64
	RootFingerprints     [][]byte
	CRLIssuerFingerprint []byte
	CRLSequence          uint64
}

// NewRotationManager reconstructs durable state and binds every stored root to
// the configured signer before making it usable.
func NewRotationManager(config RotationManagerConfig) (*RotationManager, error) {
	if config.EventStore == nil || config.Authorities == nil || interfaceNil(config.Distributor) {
		return nil, errors.New("pki: CA rotation dependencies are not wired")
	}
	manager := &RotationManager{
		eventStore: config.EventStore, authorities: config.Authorities, distributor: config.Distributor,
		successorSigners: make(map[store.CertificateClass]crypto.Signer), now: time.Now,
	}
	for class, signer := range config.SuccessorSigners {
		if class != store.CertificateClassAgent && class != store.CertificateClassGateway {
			return nil, errors.New("pki: invalid configured successor certificate class")
		}
		if err := sign.ValidateSigningKey(signer); err != nil {
			return nil, fmt.Errorf("pki: validate configured successor signer: %w", err)
		}
		manager.successorSigners[class] = signer
	}
	for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
		state, err := config.EventStore.CARotationState(context.Background(), class)
		if store.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := manager.restoreAuthorities(state); err != nil {
			return nil, err
		}
	}
	if authority, ok := manager.authorities.currentAuthority(store.CertificateClassAgent); ok {
		if err := manager.ensureInitialCRL(context.Background(), store.CertificateClassAgent, authority); err != nil {
			return nil, fmt.Errorf("pki: initialize agent CRL: %w", err)
		}
	}
	return manager, nil
}

// Snapshot reloads the durable phase so independent managers cannot serve stale state.
func (m *RotationManager) Snapshot(ctx context.Context, class store.CertificateClass) (AuthoritySnapshot, error) {
	if err := m.validateCall(ctx, class); err != nil {
		return AuthoritySnapshot{}, err
	}
	state, err := m.eventStore.CARotationState(ctx, class)
	if store.IsNotFound(err) {
		authority, ok := m.authorities.currentAuthority(class)
		if !ok {
			return AuthoritySnapshot{}, errors.New("pki: current CA authority is not wired")
		}
		return m.snapshotFromState(ctx, store.CARotationState{
			CertificateClass: class, Phase: string(RotationPhaseStable), Generation: 1, Revision: 1,
			CurrentRootDER: authority.certificate.Raw,
		})
	}
	if err != nil {
		return AuthoritySnapshot{}, err
	}
	if err := m.restoreAuthorities(state); err != nil {
		return AuthoritySnapshot{}, err
	}
	return m.snapshotFromState(ctx, state)
}

func (m *RotationManager) snapshotsAtLifecycleEvent(
	ctx context.Context,
	streamType string,
	streamID string,
	streamVersion int64,
) (AuthoritySnapshot, AuthoritySnapshot, error) {
	if m == nil || m.eventStore == nil || ctx == nil {
		return AuthoritySnapshot{}, AuthoritySnapshot{}, errors.New("pki: historical CA rotation lookup is not wired")
	}
	states, err := m.eventStore.CARotationStatesAtEvent(ctx, streamType, streamID, streamVersion)
	if err != nil {
		return AuthoritySnapshot{}, AuthoritySnapshot{}, err
	}
	snapshots := make(map[store.CertificateClass]AuthoritySnapshot, 2)
	for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
		state, ok := states[class]
		if ok {
			snapshots[class], err = m.snapshotFromState(ctx, state)
		} else {
			snapshots[class], err = m.Snapshot(ctx, class)
		}
		if err != nil {
			return AuthoritySnapshot{}, AuthoritySnapshot{}, err
		}
	}
	return snapshots[store.CertificateClassAgent], snapshots[store.CertificateClassGateway], nil
}

// BeginTrust adds a validated successor while retaining current issuance.
func (m *RotationManager) BeginTrust(
	ctx context.Context,
	class store.CertificateClass,
	successorRootDER []byte,
	transitionCertificateDER []byte,
	successorSigner crypto.Signer,
) error {
	if err := m.validateCall(ctx, class); err != nil {
		return err
	}
	var next AuthoritySnapshot
	err := m.withExclusiveRotationFence(ctx, class, func() error {
		current, err := m.Snapshot(ctx, class)
		if err != nil {
			return err
		}
		if current.Phase != RotationPhaseStable {
			return errors.New("pki: BeginTrust requires stable phase")
		}
		if err := validateRotationSuccessor(current.IssuingRootDER, successorRootDER, transitionCertificateDER, successorSigner, m.now()); err != nil {
			return err
		}
		requiredFingerprint, requiredSequence, err := m.requiredCRLBaseline(ctx, class, successorRootDER)
		if err != nil {
			return err
		}
		if class == store.CertificateClassAgent && requiredSequence == 0 {
			requiredSequence = 1
		}
		state := store.CARotationState{
			CertificateClass: class, Phase: string(RotationPhaseTrust), Generation: current.Generation + 1, Revision: 1,
			CurrentRootDER: slices.Clone(current.IssuingRootDER), SuccessorRootDER: slices.Clone(successorRootDER),
			TransitionCertificateDER:     slices.Clone(transitionCertificateDER),
			RequiredCRLIssuerFingerprint: requiredFingerprint, RequiredCRLSequence: requiredSequence,
		}
		next, err = m.snapshotFromState(ctx, state)
		if err != nil {
			return err
		}
		if next.PublishedCRLSequence < uint64(requiredSequence) {
			next.PublishedCRLSequence = uint64(requiredSequence)
		}
		event, err := store.CARotationStateEvent("begin-trust", state)
		if err != nil {
			return err
		}
		AppendEvent := m.eventStore.AppendEventBeforeCommit
		return AppendEvent(ctx, event, func(callbackCtx context.Context) error {
			if err := m.publishSnapshot(callbackCtx, next, false); err != nil {
				return err
			}
			if class != store.CertificateClassAgent {
				return nil
			}
			authority, err := newCertificateAuthority("successor", successorRootDER, successorSigner)
			if err != nil {
				return err
			}
			return m.ensureInitialCRL(callbackCtx, class, authority)
		})
	})
	if err != nil {
		return err
	}
	if err := m.authorities.installAuthority(class, successorRootDER, successorSigner); err != nil {
		return fmt.Errorf("pki: install committed successor signer: %w", err)
	}
	m.setSuccessorSigner(class, successorSigner)
	return m.publishSnapshot(ctx, next, true)
}

// Abort withdraws a trusted successor before migration and starts its prune gate.
func (m *RotationManager) Abort(ctx context.Context, class store.CertificateClass) error {
	var next AuthoritySnapshot
	var discarded []byte
	err := m.withExclusiveRotationFence(ctx, class, func() error {
		current, err := m.Snapshot(ctx, class)
		if err != nil {
			return err
		}
		if current.Phase != RotationPhaseTrust || len(current.SuccessorRootDER) == 0 {
			return errors.New("pki: Abort requires active trust phase")
		}
		discarded = slices.Clone(current.SuccessorRootDER)
		requiredFingerprint, requiredSequence, err := m.requiredCRLBaseline(ctx, class, current.IssuingRootDER)
		if err != nil {
			return err
		}
		state := store.CARotationState{
			CertificateClass: class, Phase: string(RotationPhaseTrust), Generation: current.Generation, Revision: current.Revision + 1,
			CurrentRootDER: slices.Clone(current.IssuingRootDER), DiscardedRootDER: discarded,
			RequiredCRLIssuerFingerprint: requiredFingerprint, RequiredCRLSequence: requiredSequence,
		}
		next, err = m.snapshotFromState(ctx, state)
		if err != nil {
			return err
		}
		event, err := store.CARotationStateEvent("abort", state)
		if err != nil {
			return err
		}
		AppendEvent := m.eventStore.AppendEventBeforeCommit
		return AppendEvent(ctx, event, func(callbackCtx context.Context) error {
			return m.publishSnapshot(callbackCtx, next, false)
		})
	})
	if err != nil {
		return err
	}
	return m.publishSnapshot(ctx, next, true)
}

// Migrate selects successor issuance after every active consumer confirms trust.
func (m *RotationManager) Migrate(ctx context.Context, class store.CertificateClass) error {
	var next AuthoritySnapshot
	err := m.withExclusiveRotationFence(ctx, class, func() error {
		current, err := m.Snapshot(ctx, class)
		if err != nil {
			return err
		}
		if current.Phase != RotationPhaseTrust || len(current.SuccessorRootDER) == 0 {
			return errors.New("pki: Migrate requires active trust phase")
		}
		if err := m.requireConsumerConfirmations(ctx, current); err != nil {
			return err
		}
		state := store.CARotationState{
			CertificateClass: class, Phase: string(RotationPhaseMigrate), Generation: current.Generation, Revision: current.Revision,
			CurrentRootDER: slices.Clone(current.IssuingRootDER), SuccessorRootDER: slices.Clone(current.SuccessorRootDER),
			TransitionCertificateDER:     slices.Clone(current.TransitionCertificateDER),
			RequiredCRLIssuerFingerprint: slices.Clone(current.RequiredCRLIssuerFingerprint),
			RequiredCRLSequence:          int64(current.RequiredCRLSequence),
		}
		next, err = m.snapshotFromState(ctx, state)
		if err != nil {
			return err
		}
		event, err := store.CARotationStateEvent("migrate", state)
		if err != nil {
			return err
		}
		AppendEvent := m.eventStore.AppendEventBeforeCommit
		return AppendEvent(ctx, event, func(callbackCtx context.Context) error {
			return m.publishSnapshot(callbackCtx, next, false)
		})
	})
	if err != nil {
		return err
	}
	if err := m.authorities.selectAuthority(class, sha256.Sum256(next.IssuingRootDER)); err != nil {
		return fmt.Errorf("pki: select committed successor signer: %w", err)
	}
	return m.publishSnapshot(ctx, next, true)
}

// Retire removes predecessor trust after every non-revoked leaf migrates.
func (m *RotationManager) Retire(ctx context.Context, class store.CertificateClass) error {
	var next AuthoritySnapshot
	err := m.withExclusiveRotationFence(ctx, class, func() error {
		current, err := m.Snapshot(ctx, class)
		if err != nil {
			return err
		}
		if current.Phase != RotationPhaseMigrate {
			return errors.New("pki: Retire requires migrate phase")
		}
		if err := m.requireLeafMigration(ctx, current); err != nil {
			return err
		}
		requiredFingerprint, requiredSequence, err := m.requiredCRLBaseline(ctx, class, current.SuccessorRootDER)
		if err != nil {
			return err
		}
		state := store.CARotationState{
			CertificateClass: class, Phase: string(RotationPhaseRetire), Generation: current.Generation, Revision: current.Revision + 1,
			CurrentRootDER: slices.Clone(current.DesiredRootDER[0]), SuccessorRootDER: slices.Clone(current.SuccessorRootDER),
			RequiredCRLIssuerFingerprint: requiredFingerprint, RequiredCRLSequence: requiredSequence,
		}
		next, err = m.snapshotFromState(ctx, state)
		if err != nil {
			return err
		}
		event, err := store.CARotationStateEvent("retire", state)
		if err != nil {
			return err
		}
		AppendEvent := m.eventStore.AppendEventBeforeCommit
		return AppendEvent(ctx, event, func(callbackCtx context.Context) error {
			return m.publishSnapshot(callbackCtx, next, false)
		})
	})
	if err != nil {
		return err
	}
	if err := m.authorities.selectAuthority(class, sha256.Sum256(next.IssuingRootDER)); err != nil {
		return fmt.Errorf("pki: select retired successor signer: %w", err)
	}
	return m.publishSnapshot(ctx, next, true)
}

// Normalize completes an abort or retirement after every consumer prunes trust.
func (m *RotationManager) Normalize(ctx context.Context, class store.CertificateClass) error {
	var next AuthoritySnapshot
	var removeFingerprint [sha256.Size]byte
	err := m.withExclusiveRotationFence(ctx, class, func() error {
		current, err := m.Snapshot(ctx, class)
		if err != nil {
			return err
		}
		state, err := m.eventStore.CARotationState(ctx, class)
		if err != nil {
			return err
		}
		if current.Phase != RotationPhaseRetire &&
			!(current.Phase == RotationPhaseTrust && len(current.SuccessorRootDER) == 0 && len(state.DiscardedRootDER) != 0) {
			return errors.New("pki: Normalize requires pending abort or retire phase")
		}
		if err := m.requireConsumerConfirmations(ctx, current); err != nil {
			return err
		}
		root := current.IssuingRootDER
		currentFromSuccessor := current.Phase == RotationPhaseRetire
		if current.Phase == RotationPhaseRetire {
			removeFingerprint = sha256.Sum256(current.PredecessorRootDER)
		} else {
			removeFingerprint = sha256.Sum256(state.DiscardedRootDER)
		}
		normalized := store.CARotationState{
			CertificateClass: class, Phase: string(RotationPhaseStable), Generation: current.Generation,
			Revision: current.Revision, CurrentRootDER: slices.Clone(root), CurrentFromSuccessor: currentFromSuccessor,
		}
		next, err = m.snapshotFromState(ctx, normalized)
		if err != nil {
			return err
		}
		event, err := store.CARotationStateEvent("normalize", normalized)
		if err != nil {
			return err
		}
		AppendEvent := m.eventStore.AppendEventBeforeCommit
		return AppendEvent(ctx, event, func(callbackCtx context.Context) error {
			return m.publishSnapshot(callbackCtx, next, false)
		})
	})
	if err != nil {
		return err
	}
	m.authorities.removeAuthority(class, removeFingerprint)
	return m.publishSnapshot(ctx, next, true)
}

func (m *RotationManager) snapshotFromState(ctx context.Context, state store.CARotationState) (AuthoritySnapshot, error) {
	snapshot := AuthoritySnapshot{
		Class: state.CertificateClass, Phase: RotationPhase(state.Phase), Generation: state.Generation, Revision: state.Revision,
		TransitionCertificateDER:     slices.Clone(state.TransitionCertificateDER),
		RequiredCRLIssuerFingerprint: slices.Clone(state.RequiredCRLIssuerFingerprint),
		RequiredCRLSequence:          uint64(state.RequiredCRLSequence),
	}
	switch snapshot.Phase {
	case RotationPhaseStable:
		snapshot.DesiredRootDER = [][]byte{slices.Clone(state.CurrentRootDER)}
		snapshot.IssuingRootDER = slices.Clone(state.CurrentRootDER)
	case RotationPhaseTrust:
		snapshot.DesiredRootDER = [][]byte{slices.Clone(state.CurrentRootDER)}
		snapshot.IssuingRootDER = slices.Clone(state.CurrentRootDER)
		if len(state.SuccessorRootDER) != 0 {
			snapshot.DesiredRootDER = append(snapshot.DesiredRootDER, slices.Clone(state.SuccessorRootDER))
			snapshot.SuccessorRootDER = slices.Clone(state.SuccessorRootDER)
		}
	case RotationPhaseMigrate:
		snapshot.DesiredRootDER = [][]byte{slices.Clone(state.CurrentRootDER), slices.Clone(state.SuccessorRootDER)}
		snapshot.IssuingRootDER = slices.Clone(state.SuccessorRootDER)
		snapshot.SuccessorRootDER = slices.Clone(state.SuccessorRootDER)
	case RotationPhaseRetire:
		snapshot.DesiredRootDER = [][]byte{slices.Clone(state.SuccessorRootDER)}
		snapshot.IssuingRootDER = slices.Clone(state.SuccessorRootDER)
		snapshot.SuccessorRootDER = slices.Clone(state.SuccessorRootDER)
		snapshot.PredecessorRootDER = slices.Clone(state.CurrentRootDER)
	default:
		return AuthoritySnapshot{}, errors.New("pki: invalid durable CA rotation phase")
	}
	if snapshot.Class == store.CertificateClassAgent && len(snapshot.RequiredCRLIssuerFingerprint) == 0 {
		fingerprint := sha256.Sum256(snapshot.IssuingRootDER)
		snapshot.RequiredCRLIssuerFingerprint = slices.Clone(fingerprint[:])
		snapshot.RequiredCRLSequence = 1
	}
	if len(snapshot.RequiredCRLIssuerFingerprint) == sha256.Size {
		var fingerprint [sha256.Size]byte
		copy(fingerprint[:], snapshot.RequiredCRLIssuerFingerprint)
		crl, err := m.eventStore.LatestCRL(ctx, state.CertificateClass, fingerprint)
		if err != nil {
			return AuthoritySnapshot{}, err
		}
		snapshot.PublishedCRLSequence = uint64(crl.Sequence)
	}
	return snapshot, nil
}

func (m *RotationManager) requiredCRLBaseline(ctx context.Context, class store.CertificateClass, rootDER []byte) ([]byte, int64, error) {
	if class != store.CertificateClassAgent {
		return nil, 0, nil
	}
	fingerprint := sha256.Sum256(rootDER)
	state, err := m.eventStore.LatestCRL(ctx, class, fingerprint)
	if err != nil {
		return nil, 0, err
	}
	return slices.Clone(fingerprint[:]), state.Sequence, nil
}

func (m *RotationManager) ensureInitialCRL(
	ctx context.Context,
	class store.CertificateClass,
	authority certificateAuthority,
) error {
	fingerprint := sha256.Sum256(authority.certificate.Raw)
	current, err := m.eventStore.LatestCRL(ctx, class, fingerprint)
	if err != nil || current.Sequence > 0 {
		return err
	}
	issuedAt := m.now().UTC().Truncate(time.Second)
	der, err := authority.signRevocationList(string(class), &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: issuedAt, NextUpdate: issuedAt.Add(DefaultCRLMaxAge),
	})
	if err != nil {
		return err
	}
	stored, err := m.eventStore.InitializeCRL(ctx, class, fingerprint, der, issuedAt)
	if err != nil {
		return err
	}
	if stored {
		return nil
	}
	current, err = m.eventStore.LatestCRL(ctx, class, fingerprint)
	if err != nil || current.Sequence == 0 {
		return errors.New("pki: initial CRL remained unavailable")
	}
	return nil
}

// ConfirmTrustState validates and durably records one exact signed receipt.
func (m *RotationManager) ConfirmTrustState(ctx context.Context, confirmation TrustStateConfirmation) error {
	reporterClass, claimedClass, err := trustConfirmationClasses(confirmation)
	if err != nil {
		return ErrTrustStateRejected
	}
	err = m.withTrustStateFences(ctx, reporterClass, claimedClass, func() error {
		leaf, consumer, validatedReporterClass, validatedClaimedClass, err := m.validateTrustStateConfirmation(ctx, confirmation)
		if err != nil || validatedReporterClass != reporterClass || validatedClaimedClass != claimedClass {
			return ErrTrustStateRejected
		}
		return m.eventStore.RecordValidatedTrustConfirmation(ctx, leaf, consumer)
	})
	if err != nil {
		return err
	}
	return nil
}

func trustConfirmationClasses(confirmation TrustStateConfirmation) (
	store.CertificateClass,
	store.CertificateClass,
	error,
) {
	certificate, err := parseExactCertificate(confirmation.ReporterCertificateDER)
	if err != nil {
		return "", "", err
	}
	identityClass, _, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return "", "", err
	}
	reporterClass := store.CertificateClass(identityClass)
	claimedClass := store.CertificateClass(confirmation.Claim.ClaimedClass)
	if (reporterClass != store.CertificateClassAgent && reporterClass != store.CertificateClassGateway) ||
		(claimedClass != store.CertificateClassAgent && claimedClass != store.CertificateClassGateway) {
		return "", "", ErrTrustStateRejected
	}
	return reporterClass, claimedClass, nil
}

// ConfirmControlTrustState records control's intrinsic gateway-root receipt.
func (m *RotationManager) ConfirmControlTrustState(ctx context.Context, confirmation ControlTrustStateConfirmation) error {
	if confirmation.ClaimedClass != store.CertificateClassGateway {
		return ErrTrustStateRejected
	}
	snapshot, err := m.Snapshot(ctx, confirmation.ClaimedClass)
	if err != nil || confirmation.Generation != snapshot.Generation || confirmation.Revision != snapshot.Revision ||
		!equalRootFingerprintBytes(confirmation.RootFingerprints, snapshot.DesiredRootDER) ||
		len(confirmation.CRLIssuerFingerprint) != 0 || confirmation.CRLSequence != 0 {
		return ErrTrustStateRejected
	}
	stored := store.ControlTrustConfirmation{
		ClaimedClass: confirmation.ClaimedClass, Generation: confirmation.Generation, Revision: confirmation.Revision,
		RootFingerprints: rootFingerprintArrays(snapshot.DesiredRootDER),
	}
	return m.withTrustStateFences(ctx, store.CertificateClassGateway, store.CertificateClassGateway, func() error {
		return m.eventStore.RecordControlTrustConfirmation(ctx, stored)
	})
}

func (m *RotationManager) validateTrustStateConfirmation(
	ctx context.Context,
	confirmation TrustStateConfirmation,
) (*store.LeafTrustConfirmation, *store.ConsumerTrustConfirmation, store.CertificateClass, store.CertificateClass, error) {
	certificate, err := parseExactCertificate(confirmation.ReporterCertificateDER)
	if err != nil || len(confirmation.Signature) == 0 {
		return nil, nil, "", "", ErrTrustStateRejected
	}
	identityClass, reporterID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return nil, nil, "", "", ErrTrustStateRejected
	}
	reporterClass := store.CertificateClass(identityClass)
	claimedClass := store.CertificateClass(confirmation.Claim.ClaimedClass)
	if (reporterClass != store.CertificateClassAgent && reporterClass != store.CertificateClassGateway) ||
		(claimedClass != store.CertificateClassAgent && claimedClass != store.CertificateClassGateway) ||
		confirmation.Claim.ReporterClass != string(reporterClass) {
		return nil, nil, "", "", ErrTrustStateRejected
	}
	storedDER, active, err := m.currentReporterCertificate(ctx, reporterClass, reporterID)
	if err != nil || !active || !bytes.Equal(storedDER, confirmation.ReporterCertificateDER) {
		return nil, nil, "", "", ErrTrustStateRejected
	}
	fingerprint := sha256.Sum256(confirmation.ReporterCertificateDER)
	if !bytes.Equal(confirmation.Claim.ReporterCertificateFingerprint, fingerprint[:]) ||
		sign.VerifyTrustState(certificate.PublicKey, confirmation.Claim, confirmation.Signature) != nil {
		return nil, nil, "", "", ErrTrustStateRejected
	}
	snapshot, err := m.Snapshot(ctx, claimedClass)
	if err != nil || confirmation.Claim.Generation != snapshot.Generation || confirmation.Claim.Revision != snapshot.Revision ||
		!equalRootFingerprintBytes(confirmation.Claim.RootFingerprints, snapshot.DesiredRootDER) {
		return nil, nil, "", "", ErrTrustStateRejected
	}
	if reporterClass == claimedClass {
		if len(confirmation.Claim.CRLIssuerFingerprint) != 0 || confirmation.Claim.CRLSequence != 0 {
			return nil, nil, "", "", ErrTrustStateRejected
		}
		issuer, ok := verifiedLeafIssuer(certificate, snapshot.DesiredRootDER)
		if !ok {
			return nil, nil, "", "", ErrTrustStateRejected
		}
		return &store.LeafTrustConfirmation{
			CertificateClass: reporterClass, ReporterID: reporterID,
			ReporterCertificateDER: slices.Clone(confirmation.ReporterCertificateDER),
			Generation:             snapshot.Generation, IssuerFingerprint: issuer,
		}, nil, reporterClass, claimedClass, nil
	}
	if (reporterClass == store.CertificateClassAgent && claimedClass != store.CertificateClassGateway) ||
		(reporterClass == store.CertificateClassGateway && claimedClass != store.CertificateClassAgent) {
		return nil, nil, "", "", ErrTrustStateRejected
	}
	if reporterClass == store.CertificateClassGateway {
		if !bytes.Equal(confirmation.Claim.CRLIssuerFingerprint, snapshot.RequiredCRLIssuerFingerprint) ||
			confirmation.Claim.CRLSequence < snapshot.RequiredCRLSequence ||
			confirmation.Claim.CRLSequence > snapshot.PublishedCRLSequence {
			return nil, nil, "", "", ErrTrustStateRejected
		}
	} else if len(confirmation.Claim.CRLIssuerFingerprint) != 0 || confirmation.Claim.CRLSequence != 0 {
		return nil, nil, "", "", ErrTrustStateRejected
	}
	consumer := &store.ConsumerTrustConfirmation{
		ReporterClass: reporterClass, ClaimedClass: claimedClass, ReporterID: reporterID,
		ReporterCertificateDER: slices.Clone(confirmation.ReporterCertificateDER),
		Generation:             snapshot.Generation, Revision: snapshot.Revision,
		RootFingerprints: rootFingerprintArrays(snapshot.DesiredRootDER),
		CRLSequence:      int64(confirmation.Claim.CRLSequence),
	}
	if len(snapshot.RequiredCRLIssuerFingerprint) == sha256.Size {
		copy(consumer.CRLIssuerFingerprint[:], snapshot.RequiredCRLIssuerFingerprint)
	}
	return nil, consumer, reporterClass, claimedClass, nil
}

func (m *RotationManager) currentReporterCertificate(
	ctx context.Context,
	class store.CertificateClass,
	reporterID string,
) ([]byte, bool, error) {
	if class == store.CertificateClassAgent {
		device, err := m.eventStore.Device(ctx, reporterID)
		return device.CertificateDER, err == nil && device.LifecycleState != store.DeviceLifecycleRevoked, err
	}
	gateway, err := m.eventStore.Gateway(ctx, reporterID)
	return gateway.CertificateDER, err == nil && gateway.LifecycleState != store.GatewayLifecycleRevoked, err
}

func verifiedLeafIssuer(certificate *x509.Certificate, roots [][]byte) ([sha256.Size]byte, bool) {
	for _, rootDER := range roots {
		root, err := parseExactCertificate(rootDER)
		if err == nil && certificate.CheckSignatureFrom(root) == nil {
			return sha256.Sum256(rootDER), true
		}
	}
	return [sha256.Size]byte{}, false
}

func equalRootFingerprintBytes(got [][]byte, roots [][]byte) bool {
	if len(got) != len(roots) {
		return false
	}
	for index := range roots {
		fingerprint := sha256.Sum256(roots[index])
		if !bytes.Equal(got[index], fingerprint[:]) {
			return false
		}
	}
	return true
}

func rootFingerprintArrays(roots [][]byte) [][sha256.Size]byte {
	result := make([][sha256.Size]byte, len(roots))
	for index := range roots {
		result[index] = sha256.Sum256(roots[index])
	}
	return result
}

func (m *RotationManager) requireConsumerConfirmations(ctx context.Context, snapshot AuthoritySnapshot) error {
	consumers, err := m.eventStore.ActiveTrustConsumers(ctx, snapshot.Class)
	if err != nil {
		return err
	}
	for _, consumer := range consumers {
		confirmation := store.ConsumerTrustConfirmation{
			ReporterClass: consumer.ReporterClass, ClaimedClass: snapshot.Class,
			ReporterID: consumer.ReporterID, ReporterCertificateDER: consumer.ReporterCertificateDER,
			Generation: snapshot.Generation, Revision: snapshot.Revision,
			RootFingerprints: rootFingerprintArrays(snapshot.DesiredRootDER),
		}
		if consumer.ReporterClass == store.CertificateClassGateway && snapshot.Class == store.CertificateClassAgent {
			copy(confirmation.CRLIssuerFingerprint[:], snapshot.RequiredCRLIssuerFingerprint)
			confirmation.CRLSequence = int64(snapshot.RequiredCRLSequence)
		}
		found, err := m.eventStore.HasConsumerTrustState(ctx, confirmation, int64(snapshot.PublishedCRLSequence))
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("pki: trust confirmation required from %s", consumer.ReporterID)
		}
	}
	if snapshot.Class == store.CertificateClassGateway {
		control := store.ControlTrustConfirmation{
			ClaimedClass: snapshot.Class, Generation: snapshot.Generation, Revision: snapshot.Revision,
			RootFingerprints: rootFingerprintArrays(snapshot.DesiredRootDER),
		}
		found, err := m.eventStore.HasControlTrustConfirmation(ctx, control)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("pki: trust confirmation required from control")
		}
	}
	return nil
}

func (m *RotationManager) requireLeafMigration(ctx context.Context, snapshot AuthoritySnapshot) error {
	if len(snapshot.DesiredRootDER) != 2 || len(snapshot.SuccessorRootDER) == 0 {
		return errors.New("pki: migrate snapshot lacks exact root pair")
	}
	query := store.CAMigrationReportQuery{
		CertificateClass: snapshot.Class, Generation: snapshot.Generation,
		CurrentIssuerFingerprint:   sha256.Sum256(snapshot.DesiredRootDER[0]),
		SuccessorIssuerFingerprint: sha256.Sum256(snapshot.SuccessorRootDER),
		CurrentRootDER:             snapshot.DesiredRootDER[0], SuccessorRootDER: snapshot.SuccessorRootDER,
		Limit: store.MaxCAMigrationReportPageSize,
	}
	for {
		page, err := m.eventStore.CAMigrationReport(ctx, query)
		if err != nil {
			return err
		}
		for _, entry := range page.Entries {
			if entry.Status != store.CAMigrationStatusSuccessorConfirmed && entry.Status != store.CAMigrationStatusRevoked {
				return fmt.Errorf("pki: leaf migration required from %s", entry.ReporterID)
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		query.Cursor = page.NextCursor
	}
}

func (m *RotationManager) publishSnapshot(ctx context.Context, snapshot AuthoritySnapshot, alreadyPublished bool) error {
	if alreadyPublished {
		return nil
	}
	publication := TrustBundlePublication{
		Class: snapshot.Class, Generation: snapshot.Generation, Revision: snapshot.Revision,
		RootCertificateDER:       cloneDERList(snapshot.DesiredRootDER),
		TransitionCertificateDER: slices.Clone(snapshot.TransitionCertificateDER),
	}
	for _, root := range activeCRLRoots(snapshot) {
		publication.CRLIssuerFingerprints = append(publication.CRLIssuerFingerprints, sha256.Sum256(root))
	}
	return m.distributor.PublishTrustBundle(ctx, publication)
}

func activeCRLRoots(snapshot AuthoritySnapshot) [][]byte {
	if snapshot.Phase == RotationPhaseRetire || snapshot.Phase == RotationPhaseStable {
		return [][]byte{snapshot.IssuingRootDER}
	}
	return cloneDERList(snapshot.DesiredRootDER)
}

func cloneDERList(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = slices.Clone(values[index])
	}
	return result
}

func trustBundleFromSnapshot(snapshot AuthoritySnapshot) *powermanagev1.CATrustBundle {
	return &powermanagev1.CATrustBundle{
		Generation: snapshot.Generation, Revision: snapshot.Revision,
		RootCertificateDer:       cloneDERList(snapshot.DesiredRootDER),
		TransitionCertificateDer: slices.Clone(snapshot.TransitionCertificateDER),
		CrlIssuerFingerprint:     slices.Clone(snapshot.RequiredCRLIssuerFingerprint),
		CrlSequence:              snapshot.PublishedCRLSequence,
	}
}

// withIssuanceFences selects one immutable pair of authority snapshots and
// invokes action exactly once; callers may safely perform non-idempotent token
// consumption and event creation inside the fenced action.
func (s *EnrollmentService) withIssuanceFences(
	ctx context.Context,
	action func(AuthoritySnapshot, AuthoritySnapshot) error,
) error {
	if s == nil || action == nil {
		return errors.New("pki: issuance fence is not wired")
	}
	if s.rotationManager != nil {
		return s.rotationManager.withIssuanceFences(ctx, action)
	}
	agent, agentOK := s.authorities.currentAuthority(store.CertificateClassAgent)
	gateway, gatewayOK := s.authorities.currentAuthority(store.CertificateClassGateway)
	if !agentOK || !gatewayOK {
		return errors.New("pki: issuance authorities are not wired")
	}
	return action(
		AuthoritySnapshot{Class: store.CertificateClassAgent, Phase: RotationPhaseStable, Generation: 1, Revision: 1, DesiredRootDER: [][]byte{slices.Clone(agent.certificate.Raw)}, IssuingRootDER: slices.Clone(agent.certificate.Raw)},
		AuthoritySnapshot{Class: store.CertificateClassGateway, Phase: RotationPhaseStable, Generation: 1, Revision: 1, DesiredRootDER: [][]byte{slices.Clone(gateway.certificate.Raw)}, IssuingRootDER: slices.Clone(gateway.certificate.Raw)},
	)
}

func (m *RotationManager) validateCall(ctx context.Context, class store.CertificateClass) error {
	if m == nil || m.eventStore == nil || m.authorities == nil || interfaceNil(m.distributor) || m.now == nil {
		return errors.New("pki: CA rotation manager is not wired")
	}
	if ctx == nil {
		return errors.New("pki: nil CA rotation context")
	}
	if class != store.CertificateClassAgent && class != store.CertificateClassGateway {
		return errors.New("pki: invalid CA rotation certificate class")
	}
	return ctx.Err()
}

func (m *RotationManager) restoreAuthorities(state store.CARotationState) error {
	class := state.CertificateClass
	if state.Phase == string(RotationPhaseStable) && state.CurrentFromSuccessor {
		signer := m.successorSigner(class)
		if signer == nil {
			return fmt.Errorf("pki: no signer configured for durable %s current root", class)
		}
		if err := m.authorities.installAuthority(class, state.CurrentRootDER, signer); err != nil {
			return fmt.Errorf("pki: durable current signer binding: %w", err)
		}
	} else if _, ok := m.authorities.authorityForIssuer(class, sha256.Sum256(state.CurrentRootDER)); !ok {
		return fmt.Errorf("pki: configured %s current authority does not match durable state", class)
	}
	if len(state.SuccessorRootDER) != 0 {
		signer := m.successorSigner(class)
		if signer == nil {
			return fmt.Errorf("pki: no successor signer configured for durable %s rotation", class)
		}
		if err := m.authorities.installAuthority(class, state.SuccessorRootDER, signer); err != nil {
			return fmt.Errorf("pki: durable successor signer binding: %w", err)
		}
	}
	if len(state.DiscardedRootDER) != 0 {
		signer := m.successorSigner(class)
		if signer == nil {
			return fmt.Errorf("pki: no discarded successor signer configured for durable %s rotation", class)
		}
		if err := m.authorities.installAuthority(class, state.DiscardedRootDER, signer); err != nil {
			return fmt.Errorf("pki: durable discarded successor signer binding: %w", err)
		}
	}
	selected := sha256.Sum256(state.CurrentRootDER)
	if state.Phase == string(RotationPhaseMigrate) || state.Phase == string(RotationPhaseRetire) {
		selected = sha256.Sum256(state.SuccessorRootDER)
	}
	if err := m.authorities.selectAuthority(class, selected); err != nil {
		return fmt.Errorf("pki: restore durable signer selection: %w", err)
	}
	return nil
}

func (m *RotationManager) successorSigner(class store.CertificateClass) crypto.Signer {
	m.signerMu.RLock()
	defer m.signerMu.RUnlock()
	return m.successorSigners[class]
}

func (m *RotationManager) setSuccessorSigner(class store.CertificateClass, signer crypto.Signer) {
	m.signerMu.Lock()
	defer m.signerMu.Unlock()
	m.successorSigners[class] = signer
}

func validateRotationSuccessor(currentDER, successorDER, transitionDER []byte, signer crypto.Signer, now time.Time) error {
	current, err := parseExactCertificate(currentDER)
	if err != nil {
		return fmt.Errorf("pki: parse current rotation root: %w", err)
	}
	successor, err := parseExactCertificate(successorDER)
	if err != nil {
		return fmt.Errorf("pki: parse successor rotation root: %w", err)
	}
	if bytes.Equal(current.Raw, successor.Raw) || successor.CheckSignatureFrom(successor) != nil ||
		!successor.IsCA || !successor.BasicConstraintsValid || successor.KeyUsage&x509.KeyUsageCertSign == 0 ||
		successor.KeyUsage&x509.KeyUsageCRLSign == 0 || len(successor.SubjectKeyId) == 0 ||
		bytes.Equal(current.SubjectKeyId, successor.SubjectKeyId) ||
		now.Before(successor.NotBefore) || now.After(successor.NotAfter) {
		return errors.New("pki: invalid successor rotation root")
	}
	if _, err := newCertificateAuthority("successor", successorDER, signer); err != nil {
		return fmt.Errorf("pki: successor signer binding: %w", err)
	}
	transition, err := parseExactCertificate(transitionDER)
	if err != nil {
		return fmt.Errorf("pki: parse rotation transition proof: %w", err)
	}
	successorKey, keyErr := x509.MarshalPKIXPublicKey(successor.PublicKey)
	transitionKey, transitionKeyErr := x509.MarshalPKIXPublicKey(transition.PublicKey)
	if keyErr != nil || transitionKeyErr != nil || !bytes.Equal(successorKey, transitionKey) ||
		!bytes.Equal(transition.RawSubject, successor.RawSubject) || !bytes.Equal(transition.SubjectKeyId, successor.SubjectKeyId) ||
		!bytes.Equal(transition.RawIssuer, current.RawSubject) || !bytes.Equal(transition.AuthorityKeyId, current.SubjectKeyId) ||
		transition.IsCA != successor.IsCA || transition.BasicConstraintsValid != successor.BasicConstraintsValid ||
		transition.MaxPathLen != successor.MaxPathLen || transition.MaxPathLenZero != successor.MaxPathLenZero ||
		transition.KeyUsage != successor.KeyUsage || len(transition.UnhandledCriticalExtensions) != 0 ||
		now.Before(transition.NotBefore) || now.After(transition.NotAfter) || transition.CheckSignatureFrom(current) != nil {
		return errors.New("pki: invalid rotation transition proof")
	}
	return nil
}

func rotationFenceKey(class store.CertificateClass) (int64, error) {
	switch class {
	case store.CertificateClassAgent:
		return agentRotationFenceKey, nil
	case store.CertificateClassGateway:
		return gatewayRotationFenceKey, nil
	default:
		return 0, errors.New("pki: invalid CA rotation fence class")
	}
}

func (m *RotationManager) withExclusiveRotationFence(ctx context.Context, class store.CertificateClass, action func() error) error {
	key, err := rotationFenceKey(class)
	if err != nil {
		return err
	}
	return m.eventStore.WithAdvisoryLocks(ctx, []int64{key}, false, action)
}

// withIssuanceFences acquires both shared session locks and invokes action
// exactly once. Version conflicts are returned to the caller; this boundary
// never retries token consumption, identity generation, or event appends.
func (m *RotationManager) withIssuanceFences(ctx context.Context, action func(AuthoritySnapshot, AuthoritySnapshot) error) error {
	if action == nil {
		return errors.New("pki: nil issuance action")
	}
	return m.eventStore.WithAdvisoryLocks(ctx, []int64{agentRotationFenceKey, gatewayRotationFenceKey}, true, func() error {
		agent, err := m.Snapshot(ctx, store.CertificateClassAgent)
		if err != nil {
			return err
		}
		gateway, err := m.Snapshot(ctx, store.CertificateClassGateway)
		if err != nil {
			return err
		}
		return action(agent, gateway)
	})
}

func (m *RotationManager) withTrustStateFences(
	ctx context.Context,
	reporterClass store.CertificateClass,
	claimedClass store.CertificateClass,
	action func() error,
) error {
	reporterKey, err := rotationFenceKey(reporterClass)
	if err != nil {
		return err
	}
	claimedKey, err := rotationFenceKey(claimedClass)
	if err != nil {
		return err
	}
	return m.eventStore.WithAdvisoryLocks(ctx, []int64{reporterKey, claimedKey}, true, action)
}

func (m *RotationManager) withCRLIssuerFence(ctx context.Context, class store.CertificateClass, action func() error) error {
	key, err := rotationFenceKey(class)
	if err != nil {
		return err
	}
	return m.eventStore.WithAdvisoryLocks(ctx, []int64{key}, true, action)
}
