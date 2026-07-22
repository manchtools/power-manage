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
	deviceStreamType       = "device"
	agentEnrolledEventType = "AgentEnrolled"
	devicePayloadVersion   = 1
	maxCertificateDERBytes = 65536
)

// DeviceRebuildTarget is the CLI-only device projection recovery target.
const DeviceRebuildTarget = "devices"

// Device is the DER-authoritative enrolled agent state. Public key material is
// always re-derived from CertificateDER by its consumers.
type Device struct {
	DeviceID               string
	CertificateDER         []byte
	CertificateFingerprint [sha256.Size]byte
	SealingPublicKey       []byte
	RegistrationTokenID    string
	Owner                  string
	ProjectionVersion      int64
}

type agentEnrolledPayload struct {
	CertificateDER      []byte `json:"certificate_der"`
	SealingPublicKey    []byte `json:"sealing_public_key"`
	RegistrationTokenID string `json:"registration_token_id"`
	Owner               string `json:"owner"`
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
	if row.ProjectionVersion <= 0 {
		return Device{}, errors.New("store: device projection has an invalid version")
	}
	canonicalID, payload, err := validateAgentEnrollment(row.DeviceID, agentEnrolledPayload{
		CertificateDER:      row.CertificateDer,
		SealingPublicKey:    row.SealingPublicKey,
		RegistrationTokenID: row.RegistrationTokenID,
		Owner:               row.Owner,
	})
	if err != nil {
		return Device{}, fmt.Errorf("store: invalid device projection: %w", err)
	}
	if canonicalID != deviceID {
		return Device{}, errors.New("store: device projection returned a mismatched ID")
	}
	fingerprint := sha256.Sum256(payload.CertificateDER)
	if !bytes.Equal(row.CertificateFingerprint, fingerprint[:]) {
		return Device{}, errors.New("store: device projection has a mismatched certificate fingerprint")
	}
	return Device{
		DeviceID:               canonicalID,
		CertificateDER:         payload.CertificateDER,
		CertificateFingerprint: fingerprint,
		SealingPublicKey:       payload.SealingPublicKey,
		RegistrationTokenID:    payload.RegistrationTokenID,
		Owner:                  payload.Owner,
		ProjectionVersion:      row.ProjectionVersion,
	}, nil
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
		row.RegistrationTokenID == payload.RegistrationTokenID &&
		row.Owner == payload.Owner {
		return nil
	}
	return errors.New("store: agent enrollment conflicts with the current device projection")
}

func resetDevices(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetDevices(ctx); err != nil {
		return fmt.Errorf("store: reset devices: %w", err)
	}
	return nil
}

func validateAgentEnrollment(deviceID string, payload agentEnrolledPayload) (string, agentEnrolledPayload, error) {
	deviceID, err := canonicalDeviceID(deviceID)
	if err != nil {
		return "", agentEnrolledPayload{}, err
	}
	if len(payload.CertificateDER) == 0 || len(payload.CertificateDER) > maxCertificateDERBytes {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: certificate DER must contain 1..%d bytes", maxCertificateDERBytes)
	}
	certificateDER := slices.Clone(payload.CertificateDER)
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: parse certificate DER: %w", err)
	}
	if !bytes.Equal(certificate.Raw, certificateDER) {
		return "", agentEnrolledPayload{}, errors.New("store: certificate DER contains trailing data")
	}
	class, certificateID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: parse certificate identity: %w", err)
	}
	if class != identity.AgentClass {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: certificate class %q is not agent", class)
	}
	if certificateID != deviceID {
		return "", agentEnrolledPayload{}, errors.New("store: certificate identity is mismatched with device ID")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		!certificate.NotAfter.After(certificate.NotBefore) {
		return "", agentEnrolledPayload{}, errors.New("store: certificate DER has an invalid agent profile")
	}
	if err := sign.ValidateSigningKey(certificate.PublicKey); err != nil {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: validate certificate public key: %w", err)
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

func canonicalDeviceID(deviceID string) (string, error) {
	if err := validate.ULIDPathID(deviceID); err != nil {
		return "", fmt.Errorf("store: invalid device ID: %w", err)
	}
	return strings.ToUpper(deviceID), nil
}
