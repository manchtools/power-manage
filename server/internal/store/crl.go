package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// CertificateClass separates revocation state by issuing CA.
type CertificateClass string

const (
	CertificateClassAgent   CertificateClass = "agent"
	CertificateClassGateway CertificateClass = "gateway"
)

// CertificateRevocation is the event-derived input to one signed CRL.
type CertificateRevocation struct {
	Class               CertificateClass
	CertificateDER      []byte
	Fingerprint         [sha256.Size]byte
	IssuerIdentifier    []byte
	SerialNumber        []byte
	RevokedAt           time.Time
	ReasonCode          int
	SourceStreamType    string
	SourceStreamID      string
	SourceStreamVersion int64
}

// SignedCRL is the latest durable publication for one certificate class.
type SignedCRL struct {
	Class             CertificateClass
	IssuerFingerprint [sha256.Size]byte
	Sequence          int64
	DER               []byte
	IssuedAt          time.Time
	Source            CRLSource
}

// CRLSource is the event tuple whose work produced a signed CRL. The zero
// value identifies an initial empty publication.
type CRLSource struct {
	StreamType    string
	StreamID      string
	StreamVersion int64
}

// CertificateRevocations returns validated, defensively copied CRL inputs.
func (s *Store) CertificateRevocations(ctx context.Context, class CertificateClass) ([]CertificateRevocation, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil {
		return nil, errors.New("store: nil certificate-revocations context")
	}
	if !validCertificateClass(class) {
		return nil, errors.New("store: invalid certificate class")
	}
	rows, err := generated.New(s.pool).ListCertificateRevocations(ctx, string(class))
	if err != nil {
		return nil, fmt.Errorf("store: list certificate revocations: %w", err)
	}
	result := make([]CertificateRevocation, 0, len(rows))
	for _, row := range rows {
		revocation, err := certificateRevocation(row)
		if err != nil {
			return nil, err
		}
		result = append(result, revocation)
	}
	return result, nil
}

func certificateRevocation(row generated.CertificateRevocation) (CertificateRevocation, error) {
	class := CertificateClass(row.CertificateClass)
	if !validCertificateClass(class) || len(row.CertificateFingerprint) != sha256.Size ||
		row.RevokedAt.IsZero() || row.SourceStreamVersion <= 0 ||
		row.SourceStreamType == "" || row.SourceStreamID == "" || !validReasonCode(int(row.ReasonCode)) {
		return CertificateRevocation{}, errors.New("store: invalid certificate revocation projection")
	}
	certificate, err := x509.ParseCertificate(row.CertificateDer)
	if err != nil || !bytes.Equal(certificate.Raw, row.CertificateDer) || certificate.SerialNumber == nil ||
		certificate.SerialNumber.Sign() <= 0 || !bytes.Equal(certificate.SerialNumber.Bytes(), row.SerialNumber) ||
		len(certificate.AuthorityKeyId) == 0 || !bytes.Equal(certificate.AuthorityKeyId, row.IssuerIdentifier) {
		return CertificateRevocation{}, errors.New("store: certificate revocation contains invalid certificate material")
	}
	identityClass, _, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || (class == CertificateClassAgent && identityClass != identity.AgentClass) ||
		(class == CertificateClassGateway && identityClass != identity.GatewayClass) {
		return CertificateRevocation{}, errors.New("store: certificate revocation class does not match certificate identity")
	}
	fingerprint := sha256.Sum256(row.CertificateDer)
	if !bytes.Equal(fingerprint[:], row.CertificateFingerprint) {
		return CertificateRevocation{}, errors.New("store: certificate revocation fingerprint is mismatched")
	}
	return CertificateRevocation{
		Class:               class,
		CertificateDER:      slices.Clone(row.CertificateDer),
		Fingerprint:         fingerprint,
		IssuerIdentifier:    slices.Clone(row.IssuerIdentifier),
		SerialNumber:        slices.Clone(row.SerialNumber),
		RevokedAt:           row.RevokedAt,
		ReasonCode:          int(row.ReasonCode),
		SourceStreamType:    row.SourceStreamType,
		SourceStreamID:      row.SourceStreamID,
		SourceStreamVersion: row.SourceStreamVersion,
	}, nil
}

// LatestCRL returns the durable signed publication, or sequence zero before
// the first CRL has been issued.
func (s *Store) LatestCRL(ctx context.Context, class CertificateClass, issuer ...[sha256.Size]byte) (SignedCRL, error) {
	if s == nil || s.pool == nil {
		return SignedCRL{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return SignedCRL{}, errors.New("store: nil CRL-state context")
	}
	if !validCertificateClass(class) {
		return SignedCRL{}, errors.New("store: invalid certificate class")
	}
	if len(issuer) > 1 {
		return SignedCRL{}, errors.New("store: invalid CRL issuer fingerprint")
	}
	var issuerFingerprint [sha256.Size]byte
	if len(issuer) == 1 {
		issuerFingerprint = issuer[0]
	}
	row, err := generated.New(s.pool).GetCRLState(ctx, generated.GetCRLStateParams{
		CertificateClass: string(class), IssuerFingerprint: issuerFingerprint[:],
	})
	if IsNotFound(err) {
		return SignedCRL{Class: class, IssuerFingerprint: issuerFingerprint}, nil
	}
	if err != nil {
		return SignedCRL{}, fmt.Errorf("store: read CRL state: %w", err)
	}
	if len(row.IssuerFingerprint) != sha256.Size || !bytes.Equal(row.IssuerFingerprint, issuerFingerprint[:]) {
		return SignedCRL{}, errors.New("store: CRL state issuer fingerprint is invalid")
	}
	state := SignedCRL{Class: class, IssuerFingerprint: issuerFingerprint, Sequence: row.Sequence}
	if row.Sequence == 0 {
		if len(row.CrlDer) != 0 || row.IssuedAt.Valid {
			return SignedCRL{}, errors.New("store: empty CRL state contains publication material")
		}
		return state, nil
	}
	if row.Sequence < 0 || len(row.CrlDer) == 0 || !row.IssuedAt.Valid || row.IssuedAt.Time.IsZero() {
		return SignedCRL{}, errors.New("store: invalid CRL state projection")
	}
	if err := validateCRLMaterial(row.CrlDer, row.Sequence, row.IssuedAt.Time); err != nil {
		return SignedCRL{}, fmt.Errorf("store: invalid CRL state projection: %w", err)
	}
	state.DER = slices.Clone(row.CrlDer)
	state.IssuedAt = row.IssuedAt.Time
	if row.SourceStreamType.Valid || row.SourceStreamID.Valid || row.SourceStreamVersion.Valid {
		state.Source = CRLSource{
			StreamType:    row.SourceStreamType.String,
			StreamID:      row.SourceStreamID.String,
			StreamVersion: row.SourceStreamVersion.Int64,
		}
		if !validCRLSource(state.Source) {
			return SignedCRL{}, errors.New("store: invalid CRL source event")
		}
	}
	return state, nil
}

// CurrentCRLs returns every durable issuer-scoped CRL for one class.
func (s *Store) CurrentCRLs(ctx context.Context, class CertificateClass) ([]SignedCRL, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil {
		return nil, errors.New("store: nil current-CRLs context")
	}
	if !validCertificateClass(class) {
		return nil, errors.New("store: invalid certificate class")
	}
	rows, err := generated.New(s.pool).ListCurrentCRLIssuers(ctx, string(class))
	if err != nil {
		return nil, fmt.Errorf("store: list current CRL issuers: %w", err)
	}
	result := make([]SignedCRL, 0, len(rows))
	for _, raw := range rows {
		if len(raw) != sha256.Size {
			return nil, errors.New("store: current CRL issuer fingerprint is invalid")
		}
		var fingerprint [sha256.Size]byte
		copy(fingerprint[:], raw)
		state, err := s.LatestCRL(ctx, class, fingerprint)
		if err != nil {
			return nil, err
		}
		result = append(result, state)
	}
	return result, nil
}

// CRLWorkReceipt returns the publication sequence produced by one durable
// source event. Missing receipts are reported without an error.
func (s *Store) CRLWorkReceipt(
	ctx context.Context,
	class CertificateClass,
	args ...any,
) (int64, bool, error) {
	if s == nil || s.pool == nil {
		return 0, false, errors.New("store: nil store")
	}
	if ctx == nil {
		return 0, false, errors.New("store: nil CRL-work-receipt context")
	}
	issuerFingerprint, source, ok := parseCRLReceiptArgs(args)
	if !validCertificateClass(class) || !ok || !validCRLSource(source) {
		return 0, false, errors.New("store: invalid CRL-work-receipt input")
	}
	sequence, err := generated.New(s.pool).GetCRLWorkReceipt(ctx, generated.GetCRLWorkReceiptParams{
		CertificateClass:    string(class),
		IssuerFingerprint:   issuerFingerprint[:],
		SourceStreamType:    source.StreamType,
		SourceStreamID:      source.StreamID,
		SourceStreamVersion: source.StreamVersion,
	})
	if IsNotFound(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store: read CRL work receipt: %w", err)
	}
	if sequence <= 0 {
		return 0, false, errors.New("store: invalid CRL work receipt")
	}
	return sequence, true, nil
}

// RecordCoveredCRLWorkReceipt records that an already-committed CRL covers a
// revocation event coalesced with the work item that produced the list.
func (s *Store) RecordCoveredCRLWorkReceipt(
	ctx context.Context,
	class CertificateClass,
	issuer [sha256.Size]byte,
	source CRLSource,
	publicationSequence int64,
) error {
	if s == nil || s.pool == nil {
		return errors.New("store: nil store")
	}
	if ctx == nil || !validCertificateClass(class) || !validCRLSource(source) || publicationSequence <= 0 {
		return errors.New("store: invalid covered CRL-work-receipt input")
	}
	_, err := generated.New(s.pool).RecordCoveredCRLWorkReceipt(ctx, generated.RecordCoveredCRLWorkReceiptParams{
		CertificateClass: string(class), IssuerFingerprint: issuer[:],
		SourceStreamType: source.StreamType, SourceStreamID: source.StreamID,
		SourceStreamVersion: source.StreamVersion, PublicationSequence: publicationSequence,
	})
	if err != nil {
		return fmt.Errorf("store: record covered CRL work receipt: %w", err)
	}
	_, found, err := s.CRLWorkReceipt(ctx, class, issuer, source)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("store: covered CRL work receipt was not recorded")
	}
	return nil
}

// CompareAndSwapCRL stores exactly the next signed sequence.
func (s *Store) CompareAndSwapCRL(
	ctx context.Context,
	class CertificateClass,
	args ...any,
) (bool, error) {
	if s == nil || s.pool == nil {
		return false, errors.New("store: nil store")
	}
	if ctx == nil {
		return false, errors.New("store: nil CRL compare-and-swap context")
	}
	issuerScoped := len(args) == 5
	issuerFingerprint, expectedSequence, der, issuedAt, source, ok := parseCRLCompareAndSwapArgs(args)
	if !validCertificateClass(class) || !ok || expectedSequence < 0 || len(der) == 0 || issuedAt.IsZero() ||
		(source.isZero() && expectedSequence != 0 && !issuerScoped) || (!source.isZero() && !validCRLSource(source)) {
		return false, errors.New("store: invalid CRL compare-and-swap input")
	}
	if err := validateCRLMaterial(der, expectedSequence+1, issuedAt); err != nil {
		return false, fmt.Errorf("store: invalid CRL compare-and-swap input: %w", err)
	}
	queries := generated.New(s.pool)
	var (
		affected int64
		err      error
	)
	if source.isZero() {
		affected, err = queries.CompareAndSwapCRLState(ctx, generated.CompareAndSwapCRLStateParams{
			IssuerFingerprint: issuerFingerprint[:],
			NextSequence:      expectedSequence + 1,
			CrlDer:            slices.Clone(der),
			IssuedAt:          pgtype.Timestamptz{Time: issuedAt, Valid: true},
			CertificateClass:  string(class),
			ExpectedSequence:  expectedSequence,
		})
	} else {
		affected, err = queries.CompareAndSwapCRLStateForWork(ctx, generated.CompareAndSwapCRLStateForWorkParams{
			IssuerFingerprint:   issuerFingerprint[:],
			NextSequence:        expectedSequence + 1,
			CrlDer:              slices.Clone(der),
			IssuedAt:            pgtype.Timestamptz{Time: issuedAt, Valid: true},
			SourceStreamType:    source.StreamType,
			SourceStreamID:      source.StreamID,
			SourceStreamVersion: source.StreamVersion,
			CertificateClass:    string(class),
			ExpectedSequence:    expectedSequence,
		})
	}
	if err != nil {
		return false, fmt.Errorf("store: compare and swap CRL state: %w", err)
	}
	if affected != 0 && affected != 1 {
		return false, fmt.Errorf("store: compare and swap CRL state affected %d rows", affected)
	}
	return affected == 1, nil
}

// InitializeCRL creates the first issuer-scoped publication if absent.
func (s *Store) InitializeCRL(
	ctx context.Context,
	class CertificateClass,
	issuer [sha256.Size]byte,
	der []byte,
	issuedAt time.Time,
) (bool, error) {
	return s.CompareAndSwapCRL(ctx, class, issuer, int64(0), der, issuedAt, CRLSource{})
}

func validateCRLMaterial(der []byte, sequence int64, issuedAt time.Time) error {
	list, err := x509.ParseRevocationList(der)
	if err != nil || !bytes.Equal(list.Raw, der) {
		return errors.New("revocation-list DER is invalid")
	}
	if list.Number == nil || !list.Number.IsInt64() || list.Number.Int64() != sequence {
		return errors.New("revocation-list number does not match sequence")
	}
	if !list.ThisUpdate.Equal(issuedAt) || !list.NextUpdate.After(list.ThisUpdate) {
		return errors.New("revocation-list validity does not match issued-at")
	}
	return nil
}

func parseCRLReceiptArgs(args []any) ([sha256.Size]byte, CRLSource, bool) {
	var issuer [sha256.Size]byte
	if len(args) == 1 {
		source, ok := args[0].(CRLSource)
		return issuer, source, ok
	}
	if len(args) == 2 {
		fingerprint, fingerprintOK := args[0].([sha256.Size]byte)
		source, sourceOK := args[1].(CRLSource)
		return fingerprint, source, fingerprintOK && sourceOK
	}
	return issuer, CRLSource{}, false
}

func parseCRLCompareAndSwapArgs(args []any) ([sha256.Size]byte, int64, []byte, time.Time, CRLSource, bool) {
	var issuer [sha256.Size]byte
	if len(args) == 5 {
		fingerprint, ok := args[0].([sha256.Size]byte)
		if !ok {
			return issuer, 0, nil, time.Time{}, CRLSource{}, false
		}
		issuer = fingerprint
		args = args[1:]
	}
	if len(args) != 4 {
		return issuer, 0, nil, time.Time{}, CRLSource{}, false
	}
	expected, ok := integerSequence(args[0])
	der, derOK := args[1].([]byte)
	issuedAt, timeOK := args[2].(time.Time)
	source, sourceOK := args[3].(CRLSource)
	return issuer, expected, der, issuedAt, source, ok && derOK && timeOK && sourceOK
}

func integerSequence(value any) (int64, bool) {
	switch sequence := value.(type) {
	case int:
		return int64(sequence), true
	case int64:
		return sequence, true
	case uint64:
		if sequence <= math.MaxInt64 {
			return int64(sequence), true
		}
		return 0, false
	default:
		return 0, false
	}
}

func (source CRLSource) isZero() bool {
	return source.StreamType == "" && source.StreamID == "" && source.StreamVersion == 0
}

func validCRLSource(source CRLSource) bool {
	return source.StreamType != "" && source.StreamID != "" && source.StreamVersion > 0
}

func validCertificateClass(class CertificateClass) bool {
	return class == CertificateClassAgent || class == CertificateClassGateway
}

func validReasonCode(code int) bool {
	switch code {
	case 0, 1, 2, 3, 4, 5, 6, 8, 9, 10:
		return true
	default:
		return false
	}
}
