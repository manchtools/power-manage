package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServer_ServesTLS13WithoutClientCertificate(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	serverCertificate, roots := newEnrollmentServerCertificate(t)
	server, err := NewServer(fixture.service, serverCertificate)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if DefaultAddress != ":8083" {
		t.Fatalf("DefaultAddress = %q; want :8083", DefaultAddress)
	}
	if server.http.TLSConfig.MinVersion != tls.VersionTLS13 || server.http.TLSConfig.ClientAuth != tls.NoClientCert || server.http.TLSConfig.ClientCAs != nil {
		t.Fatalf("Pki TLS config = min:%x clientAuth:%v clientCAs:%v; want TLS1.3 server-auth only", server.http.TLSConfig.MinVersion, server.http.TLSConfig.ClientAuth, server.http.TLSConfig.ClientCAs)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for Pki server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: "localhost",
	}}}
	response, err := client.Get("https://localhost:" + fmt.Sprint(port) + "/not-found")
	if err != nil {
		cancel()
		t.Fatalf("TLS1.3 request without client certificate: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		cancel()
		t.Fatalf("unknown Pki path status = %d; want 404", response.StatusCode)
	}

	tls12Client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: "localhost",
	}}}
	_, err = tls12Client.Get("https://localhost:" + fmt.Sprint(port) + "/not-found")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "protocol version") {
		cancel()
		t.Fatalf("TLS1.2 handshake error = %v; want protocol-version rejection", err)
	}

	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve cancellation error = %v; want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Pki server did not stop after cancellation")
	}
}

func TestNewServer_RejectsUnwiredTLSOrHandler(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	certificate, _ := newEnrollmentServerCertificate(t)
	tests := []struct {
		name        string
		service     *EnrollmentService
		certificate tls.Certificate
		want        string
	}{
		{name: "nil service", certificate: certificate, want: "service"},
		{name: "unwired service", service: &EnrollmentService{}, certificate: certificate, want: "service"},
		{name: "missing certificate", service: fixture.service, want: "certificate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewServer(test.service, test.certificate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewServer error = %v; want category %q", err, test.want)
			}
		})
	}
}

func newEnrollmentServerCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate TLS CA key: %v", err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(20),
		Subject:               pkix.Name{CommonName: "Pki listener test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create TLS CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse TLS CA: %v", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate TLS server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(21),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, serverKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create TLS server certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal TLS server key: %v", err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}),
	)
	if err != nil {
		t.Fatalf("load TLS server certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certificate, roots
}
