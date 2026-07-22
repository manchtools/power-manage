package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/manchtools/power-manage/contract/sign"
)

const (
	// DefaultAddress is the dedicated server-auth-only PkiService listener.
	DefaultAddress            = ":8083"
	maxEnrollmentRequestBytes = 192 << 10
	serverShutdownTimeout     = 5 * time.Second
)

// Server owns the dedicated PkiService HTTPS boundary.
type Server struct {
	http *http.Server
}

// NewServer builds a TLS 1.3, server-auth-only PkiService server.
func NewServer(service *EnrollmentService, certificate tls.Certificate) (*Server, error) {
	if err := service.validateWiring(); err != nil {
		return nil, fmt.Errorf("pki: reject enrollment service: %w", err)
	}
	certificate, err := validateEnrollmentServerCertificate(certificate, time.Now())
	if err != nil {
		return nil, err
	}
	path, handler := NewEnrollmentHTTPHandler(service)
	mux := http.NewServeMux()
	mux.Handle(path, http.MaxBytesHandler(handler, maxEnrollmentRequestBytes))
	return &Server{http: &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.NoClientCert,
		},
	}}, nil
}

// ListenAndServe binds address (or DefaultAddress when empty) and serves the
// PkiService boundary until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context, address string) error {
	if s == nil || s.http == nil || s.http.TLSConfig == nil {
		return errors.New("pki: server is not wired")
	}
	if ctx == nil {
		return errors.New("pki: nil server context")
	}
	if strings.TrimSpace(address) == "" {
		address = DefaultAddress
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("pki: listen on %s: %w", address, err)
	}
	return s.Serve(ctx, listener)
}

// Serve runs the PkiService over TLS on an already-bound listener.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || s.http == nil || s.http.TLSConfig == nil {
		return errors.New("pki: server is not wired")
	}
	if ctx == nil {
		return errors.New("pki: nil server context")
	}
	if listener == nil {
		return errors.New("pki: nil server listener")
	}
	serveDone := make(chan struct{})
	shutdownResult := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), serverShutdownTimeout)
			defer cancel()
			shutdownResult <- s.http.Shutdown(shutdownContext)
		case <-serveDone:
			shutdownResult <- nil
		}
	}()
	serveErr := s.http.ServeTLS(listener, "", "")
	close(serveDone)
	shutdownErr := <-shutdownResult
	if ctx.Err() != nil {
		return errors.Join(ctx.Err(), shutdownErr)
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return shutdownErr
	}
	return errors.Join(fmt.Errorf("pki: serve TLS: %w", serveErr), shutdownErr)
}

func validateEnrollmentServerCertificate(certificate tls.Certificate, now time.Time) (tls.Certificate, error) {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return tls.Certificate{}, errors.New("pki: TLS certificate or private key is missing")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: parse TLS server certificate: %w", err)
	}
	if !bytes.Equal(leaf.Raw, certificate.Certificate[0]) {
		return tls.Certificate{}, errors.New("pki: TLS server certificate contains trailing data")
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return tls.Certificate{}, errors.New("pki: TLS server certificate is not currently valid")
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return tls.Certificate{}, errors.New("pki: TLS server certificate has an invalid server profile")
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, errors.New("pki: TLS server private key is not a signer")
	}
	if err := sign.ValidateSigningKey(signer); err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: validate TLS server private key: %w", err)
	}
	if err := sign.ValidateSigningKey(leaf.PublicKey); err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: validate TLS server public key: %w", err)
	}
	leafPublicDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: marshal TLS server public key: %w", err)
	}
	signerPublicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: marshal TLS server signer public key: %w", err)
	}
	if !bytes.Equal(leafPublicDER, signerPublicDER) {
		return tls.Certificate{}, errors.New("pki: TLS server private key does not match certificate")
	}
	copy := certificate
	copy.Certificate = make([][]byte, len(certificate.Certificate))
	for i, der := range certificate.Certificate {
		copy.Certificate[i] = slices.Clone(der)
	}
	copy.Leaf = leaf
	return copy, nil
}
