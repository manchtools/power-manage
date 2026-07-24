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
	"github.com/manchtools/power-manage/contract/seal"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	deviceStreamType                   = "device"
	agentEnrolledEventType             = "AgentEnrolled"
	agentCertificateRenewedEventType   = "AgentCertificateRenewed"
	agentCertificateRevokedEventType   = "AgentCertificateRevoked"
	agentForceRenewalRequiredEventType = "AgentCertificateForceRenewalRequired"
	agentOwnerUpdatedEventType         = "AgentOwnerUpdated"
	agentDeletedEventType              = "AgentDeleted"
	devicePayloadVersion               = 1
	maxCertificateDERBytes             = 65536
	reasonCodeUnspecified              = 0
	reasonCodeSuperseded               = 4
)

// DeviceRebuildTarget is the CLI-only device projection recovery target.
const DeviceRebuildTarget = "devices"

// PublishAgentCRLWorkKind is durable CRL-publication work derived from a
// certificate revocation projection.
const PublishAgentCRLWorkKind = "publish-agent-crl"

// DeviceLifecycleState is the authoritative renewal eligibility projected
// from one device's lifecycle events.
type DeviceLifecycleState string

const (
	DeviceLifecycleActive       DeviceLifecycleState = "active"
	DeviceLifecycleForceRenewal DeviceLifecycleState = "force_renewal"
	DeviceLifecycleRevoked      DeviceLifecycleState = "revoked"
)

// Device is the DER-authoritative enrolled agent state. Public key material is
// always re-derived from CertificateDER by its consumers.
type Device struct {
	DeviceID               string
	CertificateDER         []byte
	CertificateFingerprint [sha256.Size]byte
	SealingPublicKey       []byte
	PreviousCertificateDER []byte
	RegistrationTokenID    string
	Owner                  string
	LifecycleState         DeviceLifecycleState
	ProjectionVersion      int64
}

type agentEnrolledPayload struct {
	CertificateDER      []byte `json:"certificate_der"`
	SealingPublicKey    []byte `json:"sealing_public_key"`
	RegistrationTokenID string `json:"registration_token_id"`
	Owner               string `json:"owner"`
}

type agentCertificateRenewedPayload struct {
	CertificateDER           []byte `json:"certificate_der"`
	SealingPublicKey         []byte `json:"sealing_public_key"`
	SupersededCertificateDER []byte `json:"superseded_certificate_der"`
}

type agentCertificateLifecyclePayload struct {
	CertificateDER []byte `json:"certificate_der"`
}

type agentOwnerUpdatedPayload struct {
	Owner string `json:"owner"`
}

// AgentEnrolledEvent binds issued certificate DER and an X25519 sealing key to
// one control-authored device identity.
func AgentEnrolledEvent(
	deviceID string,
	certificateDER []byte,
	sealingPublicKey []byte,
	registrationTokenID string,
	owner string,
) (Event, error) {
	deviceID, payload, err := validateAgentEnrollment(
		deviceID,
		agentEnrolledPayload{
			CertificateDER:      certificateDER,
			SealingPublicKey:    sealingPublicKey,
			RegistrationTokenID: registrationTokenID,
			Owner:               owner,
		},
	)
	if err != nil {
		return Event{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("store: encode agent enrollment: %w", err)
	}
	return Event{
		StreamType:     deviceStreamType,
		StreamID:       deviceID,
		EventType:      agentEnrolledEventType,
		PayloadVersion: devicePayloadVersion,
		Payload:        encoded,
	}, nil
}

// AgentCertificateRenewedEvent atomically replaces an agent certificate and
// sealing key while retaining the exact superseded DER as durable revocation
// input for CRL materialization.
func AgentCertificateRenewedEvent(
	deviceID string,
	certificateDER []byte,
	sealingPublicKey []byte,
	supersededCertificateDER []byte,
) (Event, error) {
	deviceID, payload, err := validateAgentCertificateRenewal(deviceID, agentCertificateRenewedPayload{
		CertificateDER:           certificateDER,
		SealingPublicKey:         sealingPublicKey,
		SupersededCertificateDER: supersededCertificateDER,
	})
	if err != nil {
		return Event{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("store: encode agent certificate renewal: %w", err)
	}
	return Event{
		StreamType:     deviceStreamType,
		StreamID:       deviceID,
		EventType:      agentCertificateRenewedEventType,
		PayloadVersion: devicePayloadVersion,
		Payload:        encoded,
	}, nil
}

// AgentCertificateRevokedEvent terminates the exact currently stored agent
// certificate. The projector rejects stale or substituted predecessors.
func AgentCertificateRevokedEvent(deviceID string, certificateDER []byte) (Event, error) {
	return agentCertificateLifecycleEvent(deviceID, certificateDER, agentCertificateRevokedEventType)
}

// AgentCertificateForceRenewalRequiredEvent revokes the exact current
// certificate but leaves one proof-of-possession renewal path available.
func AgentCertificateForceRenewalRequiredEvent(deviceID string, certificateDER []byte) (Event, error) {
	return agentCertificateLifecycleEvent(deviceID, certificateDER, agentForceRenewalRequiredEventType)
}

// AgentOwnerUpdatedEvent replaces management-owned device metadata.
func AgentOwnerUpdatedEvent(deviceID, owner string) (Event, error) {
	deviceID, err := canonicalDeviceID(deviceID)
	if err != nil {
		return Event{}, err
	}
	if err := validateDeviceOwner(owner); err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(agentOwnerUpdatedPayload{Owner: owner})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode device owner update: %w", err)
	}
	return deviceEvent(deviceID, agentOwnerUpdatedEventType, payload), nil
}

// AgentDeletedEvent removes a device after recording its exact certificate as
// revocation input.
func AgentDeletedEvent(deviceID string, certificateDER []byte) (Event, error) {
	return agentCertificateLifecycleEvent(deviceID, certificateDER, agentDeletedEventType)
}

func agentCertificateLifecycleEvent(deviceID string, certificateDER []byte, eventType string) (Event, error) {
	deviceID, certificateDER, _, err := validateAgentCertificate(deviceID, certificateDER)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(agentCertificateLifecyclePayload{CertificateDER: certificateDER})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode agent certificate lifecycle event: %w", err)
	}
	return Event{
		StreamType:     deviceStreamType,
		StreamID:       deviceID,
		EventType:      eventType,
		PayloadVersion: devicePayloadVersion,
		Payload:        payload,
	}, nil
}

// Device reads one enrolled agent projection and validates every trust-bearing
// field before returning it.
func (s *Store) Device(ctx context.Context, deviceID string) (Device, error) {
	if s == nil || s.pool == nil {
		return Device{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return Device{}, errors.New("store: nil device context")
	}
	deviceID, err := canonicalDeviceID(deviceID)
	if err != nil {
		return Device{}, err
	}
	row, err := generated.New(s.pool).GetDevice(ctx, deviceID)
	if err != nil {
		return Device{}, fmt.Errorf("store: read device: %w", err)
	}
	return deviceFromRow(deviceID, row)
}

// ScopedDevice reads one device through static device-group membership.
func (s *Store) ScopedDevice(
	ctx context.Context,
	deviceID string,
	global bool,
	deviceGroupIDs []string,
) (Device, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return Device{}, errors.New("store: invalid scoped device lookup")
	}
	deviceID, err := canonicalDeviceID(deviceID)
	if err != nil {
		return Device{}, err
	}
	deviceGroupIDs, err = normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return Device{}, err
	}
	row, err := generated.New(s.pool).GetScopedDevice(ctx, generated.GetScopedDeviceParams{
		DeviceID:       deviceID,
		GlobalScope:    global,
		DeviceGroupIds: deviceGroupIDs,
	})
	if err != nil {
		return Device{}, fmt.Errorf("store: read scoped device: %w", err)
	}
	return deviceFromValues(
		deviceID,
		row.DeviceID,
		row.ProjectionVersion,
		row.CertificateDer,
		row.CertificateFingerprint,
		row.SealingPublicKey,
		row.RegistrationTokenID,
		row.Owner,
		row.LifecycleState,
		row.PreviousCertificateDer,
		true,
	)
}

// ListScopedDevices returns one statically group-confined device page.
func (s *Store) ListScopedDevices(
	ctx context.Context,
	global bool,
	deviceGroupIDs []string,
	limit int32,
) ([]Device, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid scoped device list")
	}
	deviceGroupIDs, err := normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return nil, err
	}
	rows, err := generated.New(s.pool).ListScopedDevices(
		ctx,
		generated.ListScopedDevicesParams{
			GlobalScope:    global,
			DeviceGroupIds: deviceGroupIDs,
			PageLimit:      limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list scoped devices: %w", err)
	}
	devices := make([]Device, len(rows))
	for index, row := range rows {
		devices[index], err = deviceFromValues(
			row.DeviceID,
			row.DeviceID,
			row.ProjectionVersion,
			row.CertificateDer,
			row.CertificateFingerprint,
			row.SealingPublicKey,
			row.RegistrationTokenID,
			row.Owner,
			row.LifecycleState,
			row.PreviousCertificateDer,
			true,
		)
		if err != nil {
			return nil, err
		}
	}
	return devices, nil
}

func deviceFromRow(deviceID string, row generated.GetDeviceRow) (Device, error) {
	return deviceFromRowWithFingerprintPolicy(deviceID, row, true)
}

func deviceFromRowWithFingerprintPolicy(deviceID string, row generated.GetDeviceRow, requireDerivedFingerprint bool) (Device, error) {
	return deviceFromValues(
		deviceID,
		row.DeviceID,
		row.ProjectionVersion,
		row.CertificateDer,
		row.CertificateFingerprint,
		row.SealingPublicKey,
		row.RegistrationTokenID,
		row.Owner,
		row.LifecycleState,
		row.PreviousCertificateDer,
		requireDerivedFingerprint,
	)
}

func deviceFromValues(
	deviceID string,
	rowDeviceID string,
	projectionVersion int64,
	certificateDER []byte,
	certificateFingerprint []byte,
	sealingPublicKey []byte,
	registrationTokenID string,
	owner string,
	lifecycleStateValue string,
	previousCertificateDERValue []byte,
	requireDerivedFingerprint bool,
) (Device, error) {
	if projectionVersion <= 0 {
		return Device{}, errors.New("store: device projection has an invalid version")
	}
	canonicalID, payload, err := validateAgentEnrollment(rowDeviceID, agentEnrolledPayload{
		CertificateDER:      certificateDER,
		SealingPublicKey:    sealingPublicKey,
		RegistrationTokenID: registrationTokenID,
		Owner:               owner,
	})
	if err != nil {
		return Device{}, fmt.Errorf("store: invalid device projection: %w", err)
	}
	if canonicalID != deviceID {
		return Device{}, errors.New("store: device projection returned a mismatched ID")
	}
	if len(certificateFingerprint) != sha256.Size {
		return Device{}, errors.New("store: device projection has an invalid certificate fingerprint")
	}
	lifecycleState := DeviceLifecycleState(lifecycleStateValue)
	if !validDeviceLifecycleState(lifecycleState) {
		return Device{}, errors.New("store: device projection has an invalid lifecycle state")
	}
	var storedFingerprint [sha256.Size]byte
	copy(storedFingerprint[:], certificateFingerprint)
	derivedFingerprint := sha256.Sum256(payload.CertificateDER)
	if requireDerivedFingerprint && storedFingerprint != derivedFingerprint {
		return Device{}, errors.New("store: device projection has a mismatched certificate fingerprint")
	}
	var previousCertificateDER []byte
	if len(previousCertificateDERValue) > 0 {
		_, renewal, err := validateAgentCertificateRenewal(canonicalID, agentCertificateRenewedPayload{
			CertificateDER:           payload.CertificateDER,
			SealingPublicKey:         payload.SealingPublicKey,
			SupersededCertificateDER: previousCertificateDERValue,
		})
		if err != nil {
			return Device{}, fmt.Errorf("store: invalid previous certificate projection: %w", err)
		}
		previousCertificateDER = renewal.SupersededCertificateDER
	}
	return Device{
		DeviceID:               canonicalID,
		CertificateDER:         payload.CertificateDER,
		CertificateFingerprint: storedFingerprint,
		SealingPublicKey:       payload.SealingPublicKey,
		PreviousCertificateDER: previousCertificateDER,
		RegistrationTokenID:    payload.RegistrationTokenID,
		Owner:                  payload.Owner,
		LifecycleState:         lifecycleState,
		ProjectionVersion:      projectionVersion,
	}, nil
}

// DeviceManagementEventTypes returns management-owned device mutations.
func DeviceManagementEventTypes() []string {
	return []string{agentOwnerUpdatedEventType, agentDeletedEventType}
}

func deviceEvent(deviceID, eventType string, payload []byte) Event {
	return Event{
		StreamType:     deviceStreamType,
		StreamID:       deviceID,
		EventType:      eventType,
		PayloadVersion: devicePayloadVersion,
		Payload:        payload,
	}
}

func deviceEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		agentEnrolledEventType: {
			PayloadVersion: devicePayloadVersion,
			PayloadType:    agentEnrolledPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(agentEnrolledPayload{
					CertificateDER:      []byte{1, 2, 3},
					SealingPublicKey:    make([]byte, seal.X25519PublicKeySize),
					RegistrationTokenID: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
					Owner:               "owner@example.com",
				})
			},
			Projector: projectAgentEnrollment,
		},
		agentCertificateRenewedEventType: {
			PayloadVersion: devicePayloadVersion,
			PayloadType:    agentCertificateRenewedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(agentCertificateRenewedPayload{
					CertificateDER:           []byte{1, 2, 3},
					SealingPublicKey:         make([]byte, seal.X25519PublicKeySize),
					SupersededCertificateDER: []byte{4, 5, 6},
				})
			},
			Projector: projectAgentCertificateRenewal,
		},
		agentCertificateRevokedEventType: {
			PayloadVersion: devicePayloadVersion,
			PayloadType:    agentCertificateLifecyclePayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(agentCertificateLifecyclePayload{CertificateDER: []byte{1, 2, 3}})
			},
			Projector: projectAgentCertificateRevocation,
		},
		agentForceRenewalRequiredEventType: {
			PayloadVersion: devicePayloadVersion,
			PayloadType:    agentCertificateLifecyclePayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(agentCertificateLifecyclePayload{CertificateDER: []byte{1, 2, 3}})
			},
			Projector: projectAgentForceRenewal,
		},
		agentOwnerUpdatedEventType: {
			PayloadVersion: devicePayloadVersion,
			PayloadType:    agentOwnerUpdatedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(agentOwnerUpdatedPayload{Owner: "new-owner@example.com"})
			},
			Projector: projectAgentOwnerUpdate,
		},
		agentDeletedEventType: {
			PayloadVersion: devicePayloadVersion,
			PayloadType:    agentCertificateLifecyclePayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(agentCertificateLifecyclePayload{CertificateDER: []byte{1, 2, 3}})
			},
			Projector: projectAgentDeletion,
		},
	}
}

func deviceGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		agentEnrolledEventType: {
			PayloadVersion: devicePayloadVersion,
			Payload: []byte(
				`{"certificate_der":"AQID","sealing_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","registration_token_id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","owner":"owner@example.com"}`,
			),
		},
		agentCertificateRenewedEventType: {
			PayloadVersion: devicePayloadVersion,
			Payload: []byte(
				`{"certificate_der":"AQID","sealing_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","superseded_certificate_der":"BAUG"}`,
			),
		},
		agentCertificateRevokedEventType: {
			PayloadVersion: devicePayloadVersion,
			Payload:        []byte(`{"certificate_der":"AQID"}`),
		},
		agentForceRenewalRequiredEventType: {
			PayloadVersion: devicePayloadVersion,
			Payload:        []byte(`{"certificate_der":"AQID"}`),
		},
		agentOwnerUpdatedEventType: {
			PayloadVersion: devicePayloadVersion,
			Payload:        []byte(`{"owner":"new-owner@example.com"}`),
		},
		agentDeletedEventType: {
			PayloadVersion: devicePayloadVersion,
			Payload:        []byte(`{"certificate_der":"AQID"}`),
		},
	}
}

func projectAgentEnrollment(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion != 1 {
		return fmt.Errorf("store: agent enrollment must be stream version 1, got %d", event.StreamVersion)
	}
	payload, err := decodeEventPayload[agentEnrolledPayload](event, devicePayloadVersion)
	if err != nil {
		return err
	}
	deviceID, payload, err := validateAgentEnrollment(event.StreamID, payload)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(payload.CertificateDER)
	affected, err := generated.New(tx).UpsertDeviceEnrollment(ctx, generated.UpsertDeviceEnrollmentParams{
		DeviceID:               deviceID,
		ProjectionVersion:      event.StreamVersion,
		CertificateDer:         payload.CertificateDER,
		CertificateFingerprint: fingerprint[:],
		SealingPublicKey:       payload.SealingPublicKey,
		RegistrationTokenID:    payload.RegistrationTokenID,
		Owner:                  payload.Owner,
		UpdatedAt:              event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project agent enrollment: %w", err)
	}
	if affected == 1 {
		return nil
	}
	if affected != 0 {
		return fmt.Errorf("store: agent enrollment affected %d rows; want one", affected)
	}
	row, err := generated.New(tx).GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("store: inspect agent enrollment projection: %w", err)
	}
	if row.ProjectionVersion == event.StreamVersion &&
		bytes.Equal(row.CertificateDer, payload.CertificateDER) &&
		bytes.Equal(row.CertificateFingerprint, fingerprint[:]) &&
		bytes.Equal(row.SealingPublicKey, payload.SealingPublicKey) &&
		len(row.PreviousCertificateDer) == 0 &&
		row.RegistrationTokenID == payload.RegistrationTokenID &&
		row.Owner == payload.Owner && row.LifecycleState == string(DeviceLifecycleActive) {
		return nil
	}
	return errors.New("store: agent enrollment conflicts with the current device projection")
}

func projectAgentCertificateRenewal(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return fmt.Errorf("store: agent certificate renewal must follow enrollment, got stream version %d", event.StreamVersion)
	}
	payload, err := decodeEventPayload[agentCertificateRenewedPayload](event, devicePayloadVersion)
	if err != nil {
		return err
	}
	deviceID, payload, err := validateAgentCertificateRenewal(event.StreamID, payload)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(payload.CertificateDER)
	affected, err := generated.New(tx).UpdateDeviceRenewal(ctx, generated.UpdateDeviceRenewalParams{
		DeviceID:                  deviceID,
		ProjectionVersion:         event.StreamVersion,
		PreviousProjectionVersion: event.StreamVersion - 1,
		CertificateDer:            payload.CertificateDER,
		CertificateFingerprint:    fingerprint[:],
		SealingPublicKey:          payload.SealingPublicKey,
		SupersededCertificateDer:  payload.SupersededCertificateDER,
		UpdatedAt:                 event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project agent certificate renewal: %w", err)
	}
	if affected == 1 {
		return projectCertificateRevocation(ctx, tx, event, payload.SupersededCertificateDER, reasonCodeSuperseded, CertificateClassAgent, PublishAgentCRLWorkKind)
	}
	if affected != 0 {
		return fmt.Errorf("store: agent certificate renewal affected %d rows; want one", affected)
	}
	row, err := generated.New(tx).GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("store: inspect agent certificate renewal projection: %w", err)
	}
	if row.ProjectionVersion == event.StreamVersion &&
		bytes.Equal(row.CertificateDer, payload.CertificateDER) &&
		bytes.Equal(row.CertificateFingerprint, fingerprint[:]) &&
		bytes.Equal(row.SealingPublicKey, payload.SealingPublicKey) &&
		bytes.Equal(row.PreviousCertificateDer, payload.SupersededCertificateDER) &&
		row.LifecycleState == string(DeviceLifecycleActive) {
		return projectCertificateRevocation(ctx, tx, event, payload.SupersededCertificateDER, reasonCodeSuperseded, CertificateClassAgent, PublishAgentCRLWorkKind)
	}
	return errors.New("store: agent certificate renewal conflicts with the current device projection")
}

func projectAgentCertificateRevocation(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	return projectAgentLifecycleState(ctx, tx, event, DeviceLifecycleRevoked, reasonCodeUnspecified, true)
}

func projectAgentForceRenewal(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	return projectAgentLifecycleState(ctx, tx, event, DeviceLifecycleForceRenewal, reasonCodeSuperseded, false)
}

func projectAgentOwnerUpdate(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: device owner update must follow enrollment")
	}
	payload, err := decodeEventPayload[agentOwnerUpdatedPayload](event, devicePayloadVersion)
	if err != nil {
		return err
	}
	deviceID, err := canonicalDeviceID(event.StreamID)
	if err != nil {
		return err
	}
	if err := validateDeviceOwner(payload.Owner); err != nil {
		return err
	}
	affected, err := generated.New(tx).UpdateDeviceOwner(ctx, generated.UpdateDeviceOwnerParams{
		Owner:                     payload.Owner,
		ProjectionVersion:         event.StreamVersion,
		UpdatedAt:                 event.CreatedAt,
		DeviceID:                  deviceID,
		PreviousProjectionVersion: event.StreamVersion - 1,
	})
	if err != nil {
		return fmt.Errorf("store: project device owner update: %w", err)
	}
	if affected == 1 {
		return nil
	}
	if affected != 0 {
		return fmt.Errorf("store: device owner update affected %d rows; want one", affected)
	}
	row, err := generated.New(tx).GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("store: inspect device owner update: %w", err)
	}
	if row.ProjectionVersion == event.StreamVersion && row.Owner == payload.Owner {
		return nil
	}
	return errors.New("store: device owner update conflicts with the current projection")
}

func projectAgentDeletion(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: device deletion must follow enrollment")
	}
	payload, err := decodeEventPayload[agentCertificateLifecyclePayload](event, devicePayloadVersion)
	if err != nil {
		return err
	}
	deviceID, certificateDER, _, err := validateAgentCertificate(
		event.StreamID,
		payload.CertificateDER,
	)
	if err != nil {
		return err
	}
	row, err := generated.New(tx).GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("store: read device for deletion: %w", err)
	}
	if row.ProjectionVersion != event.StreamVersion-1 ||
		!bytes.Equal(row.CertificateDer, certificateDER) {
		return errors.New("store: device deletion conflicts with the current projection")
	}
	switch DeviceLifecycleState(row.LifecycleState) {
	case DeviceLifecycleActive, DeviceLifecycleForceRenewal:
		if err := projectCertificateRevocation(
			ctx,
			tx,
			event,
			certificateDER,
			reasonCodeUnspecified,
			CertificateClassAgent,
			PublishAgentCRLWorkKind,
		); err != nil {
			return err
		}
	case DeviceLifecycleRevoked:
	default:
		return errors.New("store: device deletion found an invalid lifecycle state")
	}
	affected, err := generated.New(tx).DeleteDeviceProjection(
		ctx,
		generated.DeleteDeviceProjectionParams{
			DeviceID:          deviceID,
			ProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project device deletion: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: device deletion affected %d rows; want one", affected)
	}
	return nil
}

func projectAgentLifecycleState(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
	nextState DeviceLifecycleState,
	reasonCode int,
	allowForceRenewal bool,
) error {
	if event.StreamVersion <= 1 {
		return fmt.Errorf("store: agent certificate lifecycle event must follow enrollment, got stream version %d", event.StreamVersion)
	}
	payload, err := decodeEventPayload[agentCertificateLifecyclePayload](event, devicePayloadVersion)
	if err != nil {
		return err
	}
	deviceID, certificateDER, _, err := validateAgentCertificate(event.StreamID, payload.CertificateDER)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).UpdateDeviceLifecycleState(ctx, generated.UpdateDeviceLifecycleStateParams{
		ProjectionVersion:         event.StreamVersion,
		LifecycleState:            string(nextState),
		UpdatedAt:                 event.CreatedAt,
		DeviceID:                  deviceID,
		PreviousProjectionVersion: event.StreamVersion - 1,
		CertificateDer:            certificateDER,
		PreviousLifecycleState:    string(DeviceLifecycleActive),
		AllowForceRenewal:         allowForceRenewal,
	})
	if err != nil {
		return fmt.Errorf("store: project agent lifecycle state: %w", err)
	}
	if affected != 0 && affected != 1 {
		return fmt.Errorf("store: agent lifecycle state affected %d rows; want one", affected)
	}
	if affected == 0 {
		row, readErr := generated.New(tx).GetDevice(ctx, deviceID)
		if readErr != nil {
			return fmt.Errorf("store: inspect agent lifecycle projection: %w", readErr)
		}
		if row.ProjectionVersion != event.StreamVersion || row.LifecycleState != string(nextState) ||
			!bytes.Equal(row.CertificateDer, certificateDER) {
			return errors.New("store: agent certificate lifecycle event conflicts with the current device projection")
		}
	}
	return projectCertificateRevocation(ctx, tx, event, certificateDER, reasonCode, CertificateClassAgent, PublishAgentCRLWorkKind)
}

func projectCertificateRevocation(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
	certificateDER []byte,
	reasonCode int,
	class CertificateClass,
	workKind string,
) error {
	if !validCertificateClass(class) ||
		(class == CertificateClassAgent && workKind != PublishAgentCRLWorkKind) ||
		(class == CertificateClassGateway && workKind != PublishGatewayCRLWorkKind) {
		return errors.New("store: invalid certificate revocation class or work kind")
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !bytes.Equal(certificate.Raw, certificateDER) || certificate.SerialNumber == nil ||
		certificate.SerialNumber.Sign() <= 0 || len(certificate.AuthorityKeyId) == 0 {
		return errors.New("store: revoked certificate DER is invalid")
	}
	fingerprint := sha256.Sum256(certificateDER)
	queries := generated.New(tx)
	affected, err := queries.InsertCertificateRevocation(ctx, generated.InsertCertificateRevocationParams{
		CertificateClass:       string(class),
		CertificateFingerprint: fingerprint[:],
		CertificateDer:         certificateDER,
		IssuerIdentifier:       slices.Clone(certificate.AuthorityKeyId),
		SerialNumber:           certificate.SerialNumber.Bytes(),
		RevokedAt:              event.CreatedAt,
		ReasonCode:             int16(reasonCode),
		SourceStreamType:       event.StreamType,
		SourceStreamID:         event.StreamID,
		SourceStreamVersion:    event.StreamVersion,
	})
	if err != nil {
		return fmt.Errorf("store: project certificate revocation: %w", err)
	}
	if affected == 0 {
		existing, readErr := queries.GetCertificateRevocation(ctx, generated.GetCertificateRevocationParams{
			CertificateClass:       string(class),
			CertificateFingerprint: fingerprint[:],
		})
		if readErr != nil {
			return fmt.Errorf("store: inspect certificate revocation: %w", readErr)
		}
		if !bytes.Equal(existing.CertificateDer, certificateDER) ||
			!bytes.Equal(existing.IssuerIdentifier, certificate.AuthorityKeyId) ||
			!bytes.Equal(existing.SerialNumber, certificate.SerialNumber.Bytes()) ||
			!compatibleRevocationReason(existing.ReasonCode, int16(reasonCode)) {
			return errors.New("store: certificate revocation conflicts with existing material")
		}
		if existing.SourceStreamType == event.StreamType &&
			existing.SourceStreamID == event.StreamID &&
			existing.SourceStreamVersion == event.StreamVersion {
			if existing.ReasonCode != int16(reasonCode) {
				return errors.New("store: certificate revocation source event has a mismatched reason")
			}
			return nil
		}
	} else if affected != 1 {
		return fmt.Errorf("store: certificate revocation affected %d rows; want one", affected)
	}
	return tx.EnqueueWork(ctx, Work{
		Kind:           workKind,
		PayloadVersion: 1,
		Payload:        []byte(`{}`),
		RunAt:          event.CreatedAt,
		MaxAttempts:    maxWorkAttempts,
	})
}

func compatibleRevocationReason(existing, next int16) bool {
	return existing == next || existing == reasonCodeSuperseded && next == reasonCodeUnspecified
}

func resetDevices(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetAgentCertificateRevocations(ctx); err != nil {
		return fmt.Errorf("store: reset agent certificate revocations: %w", err)
	}
	if err := generated.New(tx).ResetDevices(ctx); err != nil {
		return fmt.Errorf("store: reset devices: %w", err)
	}
	return nil
}

func validDeviceLifecycleState(state DeviceLifecycleState) bool {
	return state == DeviceLifecycleActive || state == DeviceLifecycleForceRenewal || state == DeviceLifecycleRevoked
}

func validateAgentEnrollment(deviceID string, payload agentEnrolledPayload) (string, agentEnrolledPayload, error) {
	deviceID, certificateDER, certificate, err := validateAgentCertificate(deviceID, payload.CertificateDER)
	if err != nil {
		return "", agentEnrolledPayload{}, err
	}
	if err := seal.ValidateX25519PublicKey(payload.SealingPublicKey); err != nil {
		return "", agentEnrolledPayload{}, err
	}
	tokenID, err := canonicalRegistrationTokenID(payload.RegistrationTokenID)
	if err != nil {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: invalid registration token ID: %w", err)
	}
	if err := validateRegistrationTokenMetadata(1, certificate.NotAfter, payload.Owner); err != nil {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: invalid device owner: %w", err)
	}
	return deviceID, agentEnrolledPayload{
		CertificateDER:      certificateDER,
		SealingPublicKey:    slices.Clone(payload.SealingPublicKey),
		RegistrationTokenID: tokenID,
		Owner:               payload.Owner,
	}, nil
}

func validateDeviceOwner(owner string) error {
	if err := validateRegistrationTokenOwner(owner); err != nil {
		return errors.New("store: device owner is invalid")
	}
	return nil
}

func validateAgentCertificateRenewal(
	deviceID string,
	payload agentCertificateRenewedPayload,
) (string, agentCertificateRenewedPayload, error) {
	deviceID, certificateDER, certificate, err := validateAgentCertificate(deviceID, payload.CertificateDER)
	if err != nil {
		return "", agentCertificateRenewedPayload{}, err
	}
	_, supersededDER, superseded, err := validateAgentCertificate(deviceID, payload.SupersededCertificateDER)
	if err != nil {
		return "", agentCertificateRenewedPayload{}, fmt.Errorf("store: invalid superseded certificate: %w", err)
	}
	if bytes.Equal(certificateDER, supersededDER) {
		return "", agentCertificateRenewedPayload{}, errors.New("store: renewed certificate equals the superseded certificate")
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return "", agentCertificateRenewedPayload{}, fmt.Errorf("store: marshal renewed certificate public key: %w", err)
	}
	supersededKey, err := x509.MarshalPKIXPublicKey(superseded.PublicKey)
	if err != nil {
		return "", agentCertificateRenewedPayload{}, fmt.Errorf("store: marshal superseded certificate public key: %w", err)
	}
	if !bytes.Equal(certificateKey, supersededKey) {
		return "", agentCertificateRenewedPayload{}, errors.New("store: renewed certificate public key differs from superseded certificate")
	}
	if err := seal.ValidateX25519PublicKey(payload.SealingPublicKey); err != nil {
		return "", agentCertificateRenewedPayload{}, err
	}
	return deviceID, agentCertificateRenewedPayload{
		CertificateDER:           certificateDER,
		SealingPublicKey:         slices.Clone(payload.SealingPublicKey),
		SupersededCertificateDER: supersededDER,
	}, nil
}

func validateAgentCertificate(deviceID string, der []byte) (string, []byte, *x509.Certificate, error) {
	deviceID, err := canonicalDeviceID(deviceID)
	if err != nil {
		return "", nil, nil, err
	}
	if len(der) == 0 || len(der) > maxCertificateDERBytes {
		return "", nil, nil, fmt.Errorf("store: certificate DER must contain 1..%d bytes", maxCertificateDERBytes)
	}
	certificateDER := slices.Clone(der)
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return "", nil, nil, fmt.Errorf("store: parse certificate DER: %w", err)
	}
	if !bytes.Equal(certificate.Raw, certificateDER) {
		return "", nil, nil, errors.New("store: certificate DER contains trailing data")
	}
	class, certificateID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return "", nil, nil, fmt.Errorf("store: parse certificate identity: %w", err)
	}
	if class != identity.AgentClass {
		return "", nil, nil, fmt.Errorf("store: certificate class %q is not agent", class)
	}
	if certificateID != deviceID {
		return "", nil, nil, errors.New("store: certificate identity is mismatched with device ID")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		!certificate.NotAfter.After(certificate.NotBefore) {
		return "", nil, nil, errors.New("store: certificate DER has an invalid agent profile")
	}
	if err := sign.ValidateSigningKey(certificate.PublicKey); err != nil {
		return "", nil, nil, fmt.Errorf("store: validate certificate public key: %w", err)
	}
	return deviceID, certificateDER, certificate, nil
}

func canonicalDeviceID(deviceID string) (string, error) {
	if err := validate.ULIDPathID(deviceID); err != nil {
		return "", fmt.Errorf("store: invalid device ID: %w", err)
	}
	return strings.ToUpper(deviceID), nil
}
