package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	caRotationStreamType                   = "ca-rotation"
	caTrustConfirmationStreamType          = "ca-trust-confirmation"
	agentLeafTrustConfirmedEventType       = "AgentLeafTrustConfirmed"
	agentConsumerTrustConfirmedEventType   = "AgentConsumerTrustConfirmed"
	gatewayLeafTrustConfirmedEventType     = "GatewayLeafTrustConfirmed"
	gatewayConsumerTrustConfirmedEventType = "GatewayConsumerTrustConfirmed"
	controlTrustStateRecordedEventType     = "ControlTrustStateRecorded"
	caRotationPayloadVersion               = 1
	caRotationTrustBegunEventType          = "CARotationTrustBegun"
	caRotationAbortedEventType             = "CARotationAborted"
	caRotationMigrationBegunEventType      = "CARotationMigrationBegun"
	caRotationRetiredEventType             = "CARotationRetired"
	caRotationNormalizedEventType          = "CARotationNormalized"
	MaxCAMigrationReportPageSize           = 500
)

// CARotationRebuildTarget is the CLI recovery target for CA rotation state.
const CARotationRebuildTarget = "ca-rotation"

// LeafTrustConfirmation is the durable proof that one exact leaf certificate
// has installed the requested trust generation.
type LeafTrustConfirmation struct {
	CertificateClass       CertificateClass
	ReporterID             string
	ReporterCertificateDER []byte
	Generation             uint64
	IssuerFingerprint      [sha256.Size]byte
}

// ConsumerTrustConfirmation is the durable proof that one exact consumer
// certificate has installed another certificate class's trust state.
type ConsumerTrustConfirmation struct {
	ReporterClass          CertificateClass
	ClaimedClass           CertificateClass
	ReporterID             string
	ReporterCertificateDER []byte
	Generation             uint64
	Revision               uint64
	RootFingerprints       [][sha256.Size]byte
	CRLIssuerFingerprint   [sha256.Size]byte
	CRLSequence            int64
}

// ControlTrustConfirmation is control's intrinsic durable gateway-root receipt.
type ControlTrustConfirmation struct {
	ClaimedClass         CertificateClass
	Generation           uint64
	Revision             uint64
	RootFingerprints     [][sha256.Size]byte
	CRLIssuerFingerprint [sha256.Size]byte
	CRLSequence          int64
}

// TrustConsumer is one non-revoked, DER-authoritative opposite-class consumer.
type TrustConsumer struct {
	ReporterID             string
	ReporterClass          CertificateClass
	ReporterCertificateDER []byte
}

// CARotationState is the event-derived durable state of one CA class.
type CARotationState struct {
	CertificateClass             CertificateClass `json:"certificate_class"`
	Phase                        string           `json:"phase"`
	Generation                   uint64           `json:"generation"`
	Revision                     uint64           `json:"revision"`
	CurrentRootDER               []byte           `json:"current_root_der"`
	CurrentFromSuccessor         bool             `json:"current_from_successor"`
	SuccessorRootDER             []byte           `json:"successor_root_der"`
	DiscardedRootDER             []byte           `json:"discarded_root_der"`
	TransitionCertificateDER     []byte           `json:"transition_certificate_der"`
	RequiredCRLIssuerFingerprint []byte           `json:"required_crl_issuer_fingerprint"`
	RequiredCRLSequence          int64            `json:"required_crl_sequence"`
	ProjectionVersion            int64            `json:"-"`
}

type leafTrustConfirmationPayload struct {
	CertificateClass       CertificateClass `json:"certificate_class"`
	ReporterID             string           `json:"reporter_id"`
	ReporterCertificateDER []byte           `json:"reporter_certificate_der"`
	Generation             uint64           `json:"generation"`
	IssuerFingerprint      []byte           `json:"issuer_fingerprint"`
}

type consumerTrustConfirmationPayload struct {
	ReporterClass          CertificateClass `json:"reporter_class"`
	ClaimedClass           CertificateClass `json:"claimed_class"`
	ReporterID             string           `json:"reporter_id"`
	ReporterCertificateDER []byte           `json:"reporter_certificate_der"`
	Generation             uint64           `json:"generation"`
	Revision               uint64           `json:"revision"`
	RootFingerprints       [][]byte         `json:"root_fingerprints"`
	CRLIssuerFingerprint   []byte           `json:"crl_issuer_fingerprint"`
	CRLSequence            int64            `json:"crl_sequence"`
}

type controlTrustConfirmationPayload struct {
	ClaimedClass         CertificateClass `json:"claimed_class"`
	Generation           uint64           `json:"generation"`
	Revision             uint64           `json:"revision"`
	RootFingerprints     [][]byte         `json:"root_fingerprints"`
	CRLIssuerFingerprint []byte           `json:"crl_issuer_fingerprint"`
	CRLSequence          int64            `json:"crl_sequence"`
}

// CARotationStateEvent returns one full-state event for a named transition.
func CARotationStateEvent(operation string, state CARotationState) (Event, error) {
	if err := validateCARotationState(state); err != nil {
		return Event{}, err
	}
	eventType := map[string]string{
		"begin-trust": caRotationTrustBegunEventType,
		"abort":       caRotationAbortedEventType,
		"migrate":     caRotationMigrationBegunEventType,
		"retire":      caRotationRetiredEventType,
		"normalize":   caRotationNormalizedEventType,
	}[operation]
	if eventType == "" {
		return Event{}, errors.New("store: invalid CA rotation operation")
	}
	state.ProjectionVersion = 0
	encoded, err := json.Marshal(state)
	if err != nil {
		return Event{}, fmt.Errorf("store: encode CA rotation state: %w", err)
	}
	return Event{
		StreamType: caRotationStreamType, StreamID: string(state.CertificateClass),
		EventType: eventType, PayloadVersion: caRotationPayloadVersion, Payload: encoded,
	}, nil
}

// CARotationState returns the latest durable state for one CA class.
func (s *Store) CARotationState(ctx context.Context, class CertificateClass) (CARotationState, error) {
	if s == nil || s.pool == nil {
		return CARotationState{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return CARotationState{}, errors.New("store: nil CA rotation state context")
	}
	if !validCertificateClass(class) {
		return CARotationState{}, errors.New("store: invalid CA rotation certificate class")
	}
	row, err := generated.New(s.pool).GetCARotationState(ctx, string(class))
	if err != nil {
		return CARotationState{}, fmt.Errorf("store: read CA rotation state: %w", err)
	}
	var state CARotationState
	if err := json.Unmarshal(row.StateJson, &state); err != nil {
		return CARotationState{}, fmt.Errorf("store: decode CA rotation state: %w", err)
	}
	if err := validateCARotationState(state); err != nil {
		return CARotationState{}, fmt.Errorf("store: invalid CA rotation projection: %w", err)
	}
	if state.CertificateClass != class || row.ProjectionVersion <= 0 {
		return CARotationState{}, errors.New("store: CA rotation projection identity or version is invalid")
	}
	state.ProjectionVersion = row.ProjectionVersion
	return cloneCARotationState(state), nil
}

// CARotationStatesAtEvent reconstructs each class's latest durable phase at
// one lifecycle event's global commit position.
func (s *Store) CARotationStatesAtEvent(
	ctx context.Context,
	streamType string,
	streamID string,
	streamVersion int64,
) (map[CertificateClass]CARotationState, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil || (streamType != deviceStreamType && streamType != gatewayStreamType) ||
		validate.ULIDPathID(streamID) != nil || streamVersion <= 0 {
		return nil, errors.New("store: invalid historical CA rotation event")
	}
	queries := generated.New(s.pool)
	position, err := queries.GetLifecycleEventGlobalPosition(ctx, generated.GetLifecycleEventGlobalPositionParams{
		StreamType: streamType, StreamID: strings.ToUpper(streamID), StreamVersion: streamVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("store: read lifecycle event position: %w", err)
	}
	result := make(map[CertificateClass]CARotationState, 2)
	for _, class := range []CertificateClass{CertificateClassAgent, CertificateClassGateway} {
		row, err := queries.GetLatestCARotationEventAtPosition(ctx, generated.GetLatestCARotationEventAtPositionParams{
			StreamID: string(class), GlobalPosition: position,
		})
		if IsNotFound(err) {
			encoded, nextErr := queries.GetFirstCARotationEventAfterPosition(ctx, generated.GetFirstCARotationEventAfterPositionParams{
				StreamID: string(class), GlobalPosition: position,
			})
			if IsNotFound(nextErr) {
				continue
			}
			if nextErr != nil {
				return nil, fmt.Errorf("store: read first CA rotation state after lifecycle event: %w", nextErr)
			}
			var first CARotationState
			if err := json.Unmarshal(encoded, &first); err != nil || first.CertificateClass != class || len(first.CurrentRootDER) == 0 {
				return nil, errors.New("store: invalid first historical CA rotation state")
			}
			result[class] = CARotationState{
				CertificateClass: class, Phase: "stable", Generation: 1, Revision: 1,
				CurrentRootDER: slices.Clone(first.CurrentRootDER),
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("store: read historical CA rotation state: %w", err)
		}
		var state CARotationState
		if err := json.Unmarshal(row.Payload, &state); err != nil {
			return nil, fmt.Errorf("store: decode historical CA rotation state: %w", err)
		}
		if err := validateCARotationState(state); err != nil || state.CertificateClass != class {
			return nil, errors.New("store: invalid historical CA rotation state")
		}
		state.ProjectionVersion = row.StreamVersion
		result[class] = cloneCARotationState(state)
	}
	return result, nil
}

func validateCARotationState(state CARotationState) error {
	if !validCertificateClass(state.CertificateClass) {
		return errors.New("store: invalid CA rotation certificate class")
	}
	if state.Generation == 0 || state.Revision == 0 || len(state.CurrentRootDER) == 0 {
		return errors.New("store: incomplete CA rotation state")
	}
	if len(state.CurrentRootDER) > maxCertificateDERBytes || len(state.SuccessorRootDER) > maxCertificateDERBytes ||
		len(state.DiscardedRootDER) > maxCertificateDERBytes || len(state.TransitionCertificateDER) > maxCertificateDERBytes {
		return errors.New("store: oversized CA rotation certificate material")
	}
	if (len(state.RequiredCRLIssuerFingerprint) != 0 && len(state.RequiredCRLIssuerFingerprint) != sha256.Size) ||
		state.RequiredCRLSequence < 0 {
		return errors.New("store: invalid CA rotation CRL baseline")
	}
	switch state.Phase {
	case "stable":
		if len(state.SuccessorRootDER) != 0 || len(state.DiscardedRootDER) != 0 || len(state.TransitionCertificateDER) != 0 {
			return errors.New("store: stable CA rotation state contains overlap material")
		}
	case "trust":
		if len(state.SuccessorRootDER) == 0 && len(state.DiscardedRootDER) == 0 {
			return errors.New("store: trust CA rotation state lacks successor or discarded root")
		}
	case "migrate":
		if len(state.SuccessorRootDER) == 0 || len(state.TransitionCertificateDER) == 0 {
			return errors.New("store: migrate CA rotation state lacks successor material")
		}
	case "retire":
		if len(state.SuccessorRootDER) == 0 {
			return errors.New("store: retire CA rotation state lacks successor material")
		}
	default:
		return errors.New("store: invalid CA rotation phase")
	}
	return nil
}

func cloneCARotationState(state CARotationState) CARotationState {
	state.CurrentRootDER = slices.Clone(state.CurrentRootDER)
	state.SuccessorRootDER = slices.Clone(state.SuccessorRootDER)
	state.DiscardedRootDER = slices.Clone(state.DiscardedRootDER)
	state.TransitionCertificateDER = slices.Clone(state.TransitionCertificateDER)
	state.RequiredCRLIssuerFingerprint = slices.Clone(state.RequiredCRLIssuerFingerprint)
	return state
}

// CAMigrationStatus is one cryptographically derived leaf migration state.
type CAMigrationStatus string

const (
	CAMigrationStatusCurrentIssued          CAMigrationStatus = "current-issued"
	CAMigrationStatusSuccessorIssued        CAMigrationStatus = "successor-issued"
	CAMigrationStatusSuccessorConfirmed     CAMigrationStatus = "successor-confirmed"
	CAMigrationStatusRevoked                CAMigrationStatus = "revoked"
	CAMigrationStatusInvalidIssuerSignature CAMigrationStatus = "invalid-issuer-signature"
)

// CAMigrationReportQuery selects one stable page of class-specific leaves.
type CAMigrationReportQuery struct {
	CertificateClass           CertificateClass
	Generation                 uint64
	CurrentIssuerFingerprint   [sha256.Size]byte
	SuccessorIssuerFingerprint [sha256.Size]byte
	CurrentRootDER             []byte
	SuccessorRootDER           []byte
	Cursor                     string
	Limit                      int
}

// CAMigrationReportEntry classifies one stored leaf certificate.
type CAMigrationReportEntry struct {
	ReporterID             string
	ReporterCertificateDER []byte
	Status                 CAMigrationStatus
}

// CAMigrationReportPage is one stable keyset-paginated report page.
type CAMigrationReportPage struct {
	Entries    []CAMigrationReportEntry
	NextCursor string
}

// RecordLeafTrustConfirmation appends one validated, idempotent confirmation.
func (s *Store) RecordLeafTrustConfirmation(ctx context.Context, confirmation LeafTrustConfirmation) error {
	if s == nil || s.pool == nil {
		return errors.New("store: nil store")
	}
	payload, eventType, err := validatedLeafTrustConfirmation(confirmation)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("store: encode leaf trust confirmation: %w", err)
	}
	found, err := s.confirmationEventExists(ctx, eventType, confirmation.ReporterID, encoded)
	if err != nil || found {
		return err
	}
	return s.AppendEvent(ctx, Event{
		StreamType: caTrustConfirmationStreamType, StreamID: confirmation.ReporterID,
		EventType: eventType, PayloadVersion: caRotationPayloadVersion, Payload: encoded,
	})
}

// RecordConsumerTrustConfirmation appends one validated, idempotent confirmation.
func (s *Store) RecordConsumerTrustConfirmation(ctx context.Context, confirmation ConsumerTrustConfirmation) error {
	if s == nil || s.pool == nil {
		return errors.New("store: nil store")
	}
	payload, eventType, err := validatedConsumerTrustConfirmation(confirmation)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("store: encode consumer trust confirmation: %w", err)
	}
	found, err := s.confirmationEventExists(ctx, eventType, confirmation.ReporterID, encoded)
	if err != nil || found {
		return err
	}
	return s.AppendEvent(ctx, Event{
		StreamType: caTrustConfirmationStreamType, StreamID: confirmation.ReporterID,
		EventType: eventType, PayloadVersion: caRotationPayloadVersion, Payload: encoded,
	})
}

// RecordValidatedTrustConfirmation persists exactly one prevalidated receipt.
func (s *Store) RecordValidatedTrustConfirmation(
	ctx context.Context,
	leaf *LeafTrustConfirmation,
	consumer *ConsumerTrustConfirmation,
) error {
	if (leaf == nil) == (consumer == nil) {
		return errors.New("store: trust confirmation must contain exactly one receipt kind")
	}
	if leaf != nil {
		return s.RecordLeafTrustConfirmation(ctx, *leaf)
	}
	return s.RecordConsumerTrustConfirmation(ctx, *consumer)
}

// RecordControlTrustConfirmation appends control's idempotent gateway-root receipt.
func (s *Store) RecordControlTrustConfirmation(ctx context.Context, confirmation ControlTrustConfirmation) error {
	if s == nil || s.pool == nil {
		return errors.New("store: nil store")
	}
	if confirmation.ClaimedClass != CertificateClassGateway || confirmation.Generation == 0 ||
		confirmation.Revision == 0 || len(confirmation.RootFingerprints) == 0 ||
		confirmation.CRLIssuerFingerprint != ([sha256.Size]byte{}) || confirmation.CRLSequence != 0 {
		return errors.New("store: invalid control trust confirmation")
	}
	payload := controlTrustConfirmationPayload{
		ClaimedClass: confirmation.ClaimedClass, Generation: confirmation.Generation, Revision: confirmation.Revision,
		RootFingerprints: cloneFingerprintBytes(confirmation.RootFingerprints),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("store: encode control trust confirmation: %w", err)
	}
	const controlReporterID = "00000000000000000000000000"
	found, err := s.confirmationEventExists(ctx, controlTrustStateRecordedEventType, controlReporterID, encoded)
	if err != nil || found {
		return err
	}
	return s.AppendEvent(ctx, Event{
		StreamType: caTrustConfirmationStreamType, StreamID: controlReporterID,
		EventType: controlTrustStateRecordedEventType, PayloadVersion: caRotationPayloadVersion, Payload: encoded,
	})
}

// ActiveTrustConsumers returns every non-revoked opposite-class consumer.
func (s *Store) ActiveTrustConsumers(ctx context.Context, claimedClass CertificateClass) ([]TrustConsumer, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil || !validCertificateClass(claimedClass) {
		return nil, errors.New("store: invalid active trust-consumer request")
	}
	rows, err := generated.New(s.pool).ListActiveTrustConsumers(ctx, string(claimedClass))
	if err != nil {
		return nil, fmt.Errorf("store: list active trust consumers: %w", err)
	}
	result := make([]TrustConsumer, 0, len(rows))
	for _, row := range rows {
		reporterClass := CertificateClass(row.ReporterClass)
		if !validCertificateClass(reporterClass) {
			return nil, errors.New("store: invalid active trust-consumer class")
		}
		result = append(result, TrustConsumer{
			ReporterClass: reporterClass, ReporterID: row.ReporterID,
			ReporterCertificateDER: slices.Clone(row.CertificateDer),
		})
	}
	return result, nil
}

// HasConsumerTrustConfirmation reports an exact durable consumer receipt.
func (s *Store) HasConsumerTrustConfirmation(ctx context.Context, confirmation ConsumerTrustConfirmation) (bool, error) {
	payload, eventType, err := validatedConsumerTrustConfirmation(confirmation)
	if err != nil {
		return false, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("store: encode consumer trust confirmation lookup: %w", err)
	}
	return s.confirmationEventExists(ctx, eventType, confirmation.ReporterID, encoded)
}

// HasConsumerTrustState reports a receipt whose CRL sequence lies in the
// inclusive durable publication interval.
func (s *Store) HasConsumerTrustState(
	ctx context.Context,
	confirmation ConsumerTrustConfirmation,
	maximumCRLSequence int64,
) (bool, error) {
	payload, eventType, err := validatedConsumerTrustConfirmation(confirmation)
	if err != nil {
		return false, err
	}
	if maximumCRLSequence < confirmation.CRLSequence {
		return false, errors.New("store: invalid consumer confirmation CRL interval")
	}
	rows, err := generated.New(s.pool).ListTrustConfirmationPayloads(ctx, generated.ListTrustConfirmationPayloadsParams{
		StreamID: payload.ReporterID, EventType: eventType,
	})
	if err != nil {
		return false, fmt.Errorf("store: query consumer trust confirmations: %w", err)
	}
	for _, encoded := range rows {
		var candidate consumerTrustConfirmationPayload
		if err := json.Unmarshal(encoded, &candidate); err != nil {
			return false, fmt.Errorf("store: decode consumer trust confirmation: %w", err)
		}
		if candidate.ReporterClass == payload.ReporterClass && candidate.ClaimedClass == payload.ClaimedClass &&
			candidate.ReporterID == payload.ReporterID && candidate.Generation == payload.Generation &&
			candidate.Revision == payload.Revision && bytes.Equal(candidate.ReporterCertificateDER, payload.ReporterCertificateDER) &&
			equalByteSlices(candidate.RootFingerprints, payload.RootFingerprints) &&
			bytes.Equal(candidate.CRLIssuerFingerprint, payload.CRLIssuerFingerprint) &&
			candidate.CRLSequence >= confirmation.CRLSequence && candidate.CRLSequence <= maximumCRLSequence {
			return true, nil
		}
	}
	return false, nil
}

func equalByteSlices(first, second [][]byte) bool {
	return len(first) == len(second) && slices.EqualFunc(first, second, bytes.Equal)
}

// HasControlTrustConfirmation reports control's exact durable gateway-root receipt.
func (s *Store) HasControlTrustConfirmation(ctx context.Context, confirmation ControlTrustConfirmation) (bool, error) {
	if confirmation.ClaimedClass != CertificateClassGateway || confirmation.Generation == 0 ||
		confirmation.Revision == 0 || len(confirmation.RootFingerprints) == 0 ||
		confirmation.CRLIssuerFingerprint != ([sha256.Size]byte{}) || confirmation.CRLSequence != 0 {
		return false, errors.New("store: invalid control trust confirmation lookup")
	}
	payload := controlTrustConfirmationPayload{
		ClaimedClass: confirmation.ClaimedClass, Generation: confirmation.Generation, Revision: confirmation.Revision,
		RootFingerprints: cloneFingerprintBytes(confirmation.RootFingerprints),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("store: encode control trust confirmation lookup: %w", err)
	}
	return s.confirmationEventExists(ctx, controlTrustStateRecordedEventType, "00000000000000000000000000", encoded)
}

func cloneFingerprintBytes(values [][sha256.Size]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = slices.Clone(values[index][:])
	}
	return result
}

func (s *Store) confirmationEventExists(ctx context.Context, eventType, reporterID string, payload []byte) (bool, error) {
	if ctx == nil {
		return false, errors.New("store: nil trust-confirmation context")
	}
	found, err := generated.New(s.pool).TrustConfirmationEventExists(ctx, generated.TrustConfirmationEventExistsParams{
		StreamID: strings.ToUpper(reporterID), EventType: eventType, Payload: payload,
	})
	if err != nil {
		return false, fmt.Errorf("store: inspect trust confirmation: %w", err)
	}
	return found, nil
}

func validatedLeafTrustConfirmation(value LeafTrustConfirmation) (leafTrustConfirmationPayload, string, error) {
	if !validCertificateClass(value.CertificateClass) {
		return leafTrustConfirmationPayload{}, "", errors.New("store: invalid leaf confirmation certificate class")
	}
	reporterID, certificate, err := validateConfirmationReporter(value.CertificateClass, value.ReporterID, value.ReporterCertificateDER)
	if err != nil {
		return leafTrustConfirmationPayload{}, "", err
	}
	if value.Generation == 0 || value.IssuerFingerprint == ([sha256.Size]byte{}) {
		return leafTrustConfirmationPayload{}, "", errors.New("store: invalid leaf confirmation generation or issuer fingerprint")
	}
	if certificate.CheckSignatureFrom(certificate) == nil {
		return leafTrustConfirmationPayload{}, "", errors.New("store: leaf confirmation certificate is a CA")
	}
	eventType := agentLeafTrustConfirmedEventType
	if value.CertificateClass == CertificateClassGateway {
		eventType = gatewayLeafTrustConfirmedEventType
	}
	return leafTrustConfirmationPayload{
		CertificateClass: value.CertificateClass, ReporterID: reporterID,
		ReporterCertificateDER: slices.Clone(value.ReporterCertificateDER), Generation: value.Generation,
		IssuerFingerprint: slices.Clone(value.IssuerFingerprint[:]),
	}, eventType, nil
}

func validatedConsumerTrustConfirmation(value ConsumerTrustConfirmation) (consumerTrustConfirmationPayload, string, error) {
	if !validCertificateClass(value.ReporterClass) || !validCertificateClass(value.ClaimedClass) {
		return consumerTrustConfirmationPayload{}, "", errors.New("store: invalid consumer confirmation certificate class")
	}
	reporterID, _, err := validateConfirmationReporter(value.ReporterClass, value.ReporterID, value.ReporterCertificateDER)
	if err != nil {
		return consumerTrustConfirmationPayload{}, "", err
	}
	if value.Generation == 0 || value.Revision == 0 || len(value.RootFingerprints) == 0 {
		return consumerTrustConfirmationPayload{}, "", errors.New("store: invalid consumer confirmation trust revision")
	}
	roots := make([][]byte, len(value.RootFingerprints))
	for index, fingerprint := range value.RootFingerprints {
		if fingerprint == ([sha256.Size]byte{}) {
			return consumerTrustConfirmationPayload{}, "", errors.New("store: invalid consumer confirmation root fingerprint")
		}
		roots[index] = slices.Clone(fingerprint[:])
	}
	eventType := agentConsumerTrustConfirmedEventType
	if value.ReporterClass == CertificateClassGateway {
		eventType = gatewayConsumerTrustConfirmedEventType
	}
	return consumerTrustConfirmationPayload{
		ReporterClass: value.ReporterClass, ClaimedClass: value.ClaimedClass, ReporterID: reporterID,
		ReporterCertificateDER: slices.Clone(value.ReporterCertificateDER), Generation: value.Generation,
		Revision: value.Revision, RootFingerprints: roots,
		CRLIssuerFingerprint: slices.Clone(value.CRLIssuerFingerprint[:]), CRLSequence: value.CRLSequence,
	}, eventType, nil
}

func validateConfirmationReporter(class CertificateClass, reporterID string, certificateDER []byte) (string, *x509.Certificate, error) {
	if err := validate.ULIDPathID(reporterID); err != nil {
		return "", nil, fmt.Errorf("store: invalid confirmation reporter ID: %w", err)
	}
	reporterID = strings.ToUpper(reporterID)
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !bytes.Equal(certificate.Raw, certificateDER) {
		return "", nil, errors.New("store: invalid confirmation reporter certificate DER")
	}
	wantClass := identity.AgentClass
	if class == CertificateClassGateway {
		wantClass = identity.GatewayClass
	}
	gotClass, gotID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || gotClass != wantClass || gotID != reporterID {
		return "", nil, errors.New("store: confirmation reporter certificate identity is mismatched")
	}
	return reporterID, certificate, nil
}

// CAMigrationReport classifies leaves from their stored DER and verified issuer signature.
func (s *Store) CAMigrationReport(ctx context.Context, query CAMigrationReportQuery) (CAMigrationReportPage, error) {
	if s == nil || s.pool == nil {
		return CAMigrationReportPage{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return CAMigrationReportPage{}, errors.New("store: nil CA migration report context")
	}
	current, successor, err := validateCAMigrationReportQuery(query)
	if err != nil {
		return CAMigrationReportPage{}, err
	}
	rows, err := generated.New(s.pool).ListCAMigrationReportEntries(ctx, generated.ListCAMigrationReportEntriesParams{
		PageSize: int32(query.Limit + 1), CertificateClass: string(query.CertificateClass), Cursor: strings.ToUpper(query.Cursor),
	})
	if err != nil {
		return CAMigrationReportPage{}, fmt.Errorf("store: query CA migration report: %w", err)
	}
	entries := make([]CAMigrationReportEntry, 0, query.Limit+1)
	for _, row := range rows {
		status, err := s.classifyCAMigrationEntry(
			ctx, query, row.ReporterID, row.CertificateDer, row.LifecycleState, current, successor,
		)
		if err != nil {
			return CAMigrationReportPage{}, err
		}
		entries = append(entries, CAMigrationReportEntry{
			ReporterID: row.ReporterID, ReporterCertificateDER: slices.Clone(row.CertificateDer), Status: status,
		})
	}
	page := CAMigrationReportPage{Entries: entries}
	if len(entries) > query.Limit {
		page.Entries = entries[:query.Limit]
		page.NextCursor = page.Entries[len(page.Entries)-1].ReporterID
	}
	return page, nil
}

func validateCAMigrationReportQuery(query CAMigrationReportQuery) (*x509.Certificate, *x509.Certificate, error) {
	if !validCertificateClass(query.CertificateClass) {
		return nil, nil, errors.New("store: invalid CA migration report certificate class")
	}
	if query.Generation == 0 {
		return nil, nil, errors.New("store: invalid CA migration report generation")
	}
	if query.Limit <= 0 || query.Limit > MaxCAMigrationReportPageSize {
		return nil, nil, errors.New("store: invalid CA migration report limit")
	}
	if query.Cursor != "" {
		if err := validate.ULIDPathID(query.Cursor); err != nil {
			return nil, nil, fmt.Errorf("store: invalid CA migration report cursor: %w", err)
		}
	}
	if query.CurrentIssuerFingerprint == query.SuccessorIssuerFingerprint {
		return nil, nil, errors.New("store: CA migration report fingerprints must differ")
	}
	current, err := validateReportRoot("current", query.CurrentRootDER, query.CurrentIssuerFingerprint)
	if err != nil {
		return nil, nil, err
	}
	successor, err := validateReportRoot("successor", query.SuccessorRootDER, query.SuccessorIssuerFingerprint)
	if err != nil {
		return nil, nil, err
	}
	return current, successor, nil
}

func validateReportRoot(name string, der []byte, fingerprint [sha256.Size]byte) (*x509.Certificate, error) {
	root, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(root.Raw, der) || !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, fmt.Errorf("store: invalid %s root certificate", name)
	}
	if sha256.Sum256(der) != fingerprint {
		return nil, fmt.Errorf("store: %s fingerprint does not match root", name)
	}
	return root, nil
}

func (s *Store) classifyCAMigrationEntry(
	ctx context.Context,
	query CAMigrationReportQuery,
	reporterID string,
	certificateDER []byte,
	lifecycle string,
	current *x509.Certificate,
	successor *x509.Certificate,
) (CAMigrationStatus, error) {
	if lifecycle == string(DeviceLifecycleRevoked) || lifecycle == string(GatewayLifecycleRevoked) {
		return CAMigrationStatusRevoked, nil
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !bytes.Equal(certificate.Raw, certificateDER) {
		return CAMigrationStatusInvalidIssuerSignature, nil
	}
	if certificate.CheckSignatureFrom(successor) == nil {
		confirmed, err := s.hasLeafTrustConfirmation(ctx, query.CertificateClass, reporterID, certificateDER, query.Generation, query.SuccessorIssuerFingerprint)
		if err != nil {
			return "", err
		}
		if confirmed {
			return CAMigrationStatusSuccessorConfirmed, nil
		}
		return CAMigrationStatusSuccessorIssued, nil
	}
	if certificate.CheckSignatureFrom(current) == nil {
		return CAMigrationStatusCurrentIssued, nil
	}
	return CAMigrationStatusInvalidIssuerSignature, nil
}

func (s *Store) hasLeafTrustConfirmation(
	ctx context.Context,
	class CertificateClass,
	reporterID string,
	certificateDER []byte,
	generation uint64,
	issuer [sha256.Size]byte,
) (bool, error) {
	eventType := agentLeafTrustConfirmedEventType
	if class == CertificateClassGateway {
		eventType = gatewayLeafTrustConfirmedEventType
	}
	rows, err := generated.New(s.pool).ListTrustConfirmationPayloads(ctx, generated.ListTrustConfirmationPayloadsParams{
		StreamID: reporterID, EventType: eventType,
	})
	if err != nil {
		return false, fmt.Errorf("store: query leaf trust confirmations: %w", err)
	}
	for _, encoded := range rows {
		var payload leafTrustConfirmationPayload
		if err := json.Unmarshal(encoded, &payload); err != nil {
			return false, fmt.Errorf("store: decode leaf trust confirmation: %w", err)
		}
		if payload.CertificateClass == class && payload.ReporterID == reporterID && payload.Generation == generation &&
			bytes.Equal(payload.ReporterCertificateDER, certificateDER) && bytes.Equal(payload.IssuerFingerprint, issuer[:]) {
			return true, nil
		}
	}
	return false, nil
}

func caRotationEventDefinitions() map[string]eventDefinition {
	definitions := map[string]eventDefinition{
		agentLeafTrustConfirmedEventType:       confirmationEventDefinition(leafTrustConfirmationPayload{}),
		gatewayLeafTrustConfirmedEventType:     confirmationEventDefinition(leafTrustConfirmationPayload{}),
		agentConsumerTrustConfirmedEventType:   confirmationEventDefinition(consumerTrustConfirmationPayload{}),
		gatewayConsumerTrustConfirmedEventType: confirmationEventDefinition(consumerTrustConfirmationPayload{}),
		controlTrustStateRecordedEventType: {
			PayloadVersion: caRotationPayloadVersion, PayloadType: controlTrustConfirmationPayload{},
			GoldenPayload: goldenControlTrustConfirmationPayload, Projector: projectTrustConfirmation,
		},
	}
	for _, eventType := range []string{
		caRotationTrustBegunEventType, caRotationAbortedEventType, caRotationMigrationBegunEventType,
		caRotationRetiredEventType, caRotationNormalizedEventType,
	} {
		definitions[eventType] = eventDefinition{
			PayloadVersion: caRotationPayloadVersion, PayloadType: CARotationState{},
			GoldenPayload: goldenCARotationStatePayload, Projector: projectCARotationState,
		}
	}
	return definitions
}

func confirmationEventDefinition(payloadType any) eventDefinition {
	return eventDefinition{
		PayloadVersion: caRotationPayloadVersion, PayloadType: payloadType,
		GoldenPayload: func() ([]byte, error) { return goldenConfirmationPayload(payloadType) },
		Projector:     projectTrustConfirmation,
	}
}

func goldenConfirmationPayload(payloadType any) ([]byte, error) {
	switch payloadType.(type) {
	case leafTrustConfirmationPayload:
		return json.Marshal(leafTrustConfirmationPayload{
			CertificateClass: CertificateClassAgent, ReporterID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			ReporterCertificateDER: []byte{1, 2, 3}, Generation: 2, IssuerFingerprint: bytes.Repeat([]byte{1}, sha256.Size),
		})
	case consumerTrustConfirmationPayload:
		return json.Marshal(consumerTrustConfirmationPayload{
			ReporterClass: CertificateClassGateway, ClaimedClass: CertificateClassAgent,
			ReporterID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ReporterCertificateDER: []byte{1, 2, 3},
			Generation: 2, Revision: 1, RootFingerprints: [][]byte{bytes.Repeat([]byte{1}, sha256.Size)},
			CRLIssuerFingerprint: bytes.Repeat([]byte{2}, sha256.Size), CRLSequence: 1,
		})
	default:
		return nil, errors.New("store: unknown confirmation golden payload type")
	}
}

func caRotationGoldenCorpus() map[string]goldenEvent {
	leaf, _ := goldenConfirmationPayload(leafTrustConfirmationPayload{})
	consumer, _ := goldenConfirmationPayload(consumerTrustConfirmationPayload{})
	control, _ := goldenControlTrustConfirmationPayload()
	state, _ := goldenCARotationStatePayload()
	corpus := map[string]goldenEvent{
		agentLeafTrustConfirmedEventType:       {PayloadVersion: 1, Payload: leaf},
		gatewayLeafTrustConfirmedEventType:     {PayloadVersion: 1, Payload: leaf},
		agentConsumerTrustConfirmedEventType:   {PayloadVersion: 1, Payload: consumer},
		gatewayConsumerTrustConfirmedEventType: {PayloadVersion: 1, Payload: consumer},
		controlTrustStateRecordedEventType:     {PayloadVersion: 1, Payload: control},
	}
	for _, eventType := range []string{
		caRotationTrustBegunEventType, caRotationAbortedEventType, caRotationMigrationBegunEventType,
		caRotationRetiredEventType, caRotationNormalizedEventType,
	} {
		corpus[eventType] = goldenEvent{PayloadVersion: 1, Payload: state}
	}
	return corpus
}

func goldenControlTrustConfirmationPayload() ([]byte, error) {
	return json.Marshal(controlTrustConfirmationPayload{
		ClaimedClass: CertificateClassGateway, Generation: 2, Revision: 1,
		RootFingerprints: [][]byte{bytes.Repeat([]byte{1}, sha256.Size)},
	})
}

func goldenCARotationStatePayload() ([]byte, error) {
	return json.Marshal(CARotationState{
		CertificateClass: CertificateClassAgent, Phase: "stable", Generation: 1, Revision: 1,
		CurrentRootDER: []byte{1, 2, 3},
	})
}

func projectCARotationState(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	state, err := decodeEventPayload[CARotationState](event, caRotationPayloadVersion)
	if err != nil {
		return err
	}
	if err := validateCARotationState(state); err != nil {
		return err
	}
	if string(state.CertificateClass) != event.StreamID {
		return errors.New("store: CA rotation event stream identity is mismatched")
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("store: encode projected CA rotation state: %w", err)
	}
	affected, err := generated.New(tx).UpsertCARotationState(ctx, generated.UpsertCARotationStateParams{
		CertificateClass: string(state.CertificateClass), ProjectionVersion: event.StreamVersion,
		StateJson: encoded, UpdatedAt: event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project CA rotation state: %w", err)
	}
	if affected != 1 {
		return errors.New("store: CA rotation projection version conflict")
	}
	return nil
}

func projectTrustConfirmation(_ context.Context, _ ProjectionTx, event PersistedEvent) error {
	switch event.EventType {
	case agentLeafTrustConfirmedEventType, gatewayLeafTrustConfirmedEventType:
		_, err := decodeEventPayload[leafTrustConfirmationPayload](event, caRotationPayloadVersion)
		return err
	case agentConsumerTrustConfirmedEventType, gatewayConsumerTrustConfirmedEventType:
		_, err := decodeEventPayload[consumerTrustConfirmationPayload](event, caRotationPayloadVersion)
		return err
	case controlTrustStateRecordedEventType:
		_, err := decodeEventPayload[controlTrustConfirmationPayload](event, caRotationPayloadVersion)
		return err
	default:
		return fmt.Errorf("store: unknown trust confirmation event type %q", event.EventType)
	}
}

func resetCARotationState(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetCARotationState(ctx); err != nil {
		return fmt.Errorf("store: reset CA rotation state: %w", err)
	}
	return nil
}
