package enroll

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/manchtools/power-manage/sdk/fsafe"
)

const DefaultCredentialPath = "/var/lib/power-manage/identity.pem"

type createCredentialFile func(string, []byte, os.FileMode) error

// FileCredentialStore creates one atomic, root-only PEM credential bundle.
type FileCredentialStore struct {
	path   string
	create createCredentialFile
	now    func() time.Time
}

// NewFileCredentialStore builds the production no-overwrite credential sink.
func NewFileCredentialStore(path string) (*FileCredentialStore, error) {
	return newFileCredentialStore(path, fsafe.WriteFileNew)
}

func newFileCredentialStore(path string, create createCredentialFile) (*FileCredentialStore, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("enroll: credential path must be absolute")
	}
	if create == nil {
		return nil, errors.New("enroll: nil credential file creator")
	}
	return &FileCredentialStore{path: filepath.Clean(path), create: create, now: time.Now}, nil
}

// Create validates and atomically publishes the first credential bundle.
func (s *FileCredentialStore) Create(ctx context.Context, bundle CredentialBundle) error {
	if s == nil || s.path == "" || s.create == nil || s.now == nil {
		return errors.New("enroll: credential store is not wired")
	}
	if ctx == nil {
		return errors.New("enroll: nil credential-store context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCredentialBundle(bundle, s.now()); err != nil {
		return fmt.Errorf("enroll: validate credential bundle: %w", err)
	}
	encoded, err := encodeCredentialBundle(bundle)
	if err != nil {
		return err
	}
	if err := s.create(s.path, encoded, 0o600); err != nil {
		return fmt.Errorf("enroll: create credential bundle: %w", err)
	}
	return nil
}

func encodeCredentialBundle(bundle CredentialBundle) ([]byte, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(bundle.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("enroll: marshal mTLS private key: %w", err)
	}
	sealingPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(bundle.SealingPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("enroll: marshal sealing private key: %w", err)
	}
	blocks := []*pem.Block{
		{Type: "POWER MANAGE AGENT CERTIFICATE", Bytes: bundle.CertificateDER},
		{Type: "POWER MANAGE AGENT PRIVATE KEY", Bytes: privateKeyDER},
		{Type: "POWER MANAGE AGENT CA CERTIFICATE", Bytes: bundle.CertificateAuthorityDER},
		{Type: "POWER MANAGE SEALING PRIVATE KEY", Bytes: sealingPrivateKeyDER},
	}
	var encoded []byte
	for _, block := range blocks {
		encoded = append(encoded, pem.EncodeToMemory(block)...)
	}
	return encoded, nil
}
