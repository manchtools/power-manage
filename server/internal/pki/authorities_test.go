package pki_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/pki"
)

const testDeviceID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// TestNewAuthorities_AcceptsThreeDistinctApprovedAuthorities pins PKI-1's
// three-key custody set and every approved shared signing-key profile.
func TestNewAuthorities_AcceptsThreeDistinctApprovedAuthorities(t *testing.T) {
	tests := []struct {
		name    string
		agent   func(*testing.T) crypto.Signer
		gateway func(*testing.T) crypto.Signer
		command func(*testing.T) crypto.Signer
	}{
		{name: "ECDSA curves", agent: p256Signer, gateway: p384Signer, command: p521Signer},
		{name: "RSA 2048 and ECDSA", agent: rsa2048Signer, gateway: p256Signer, command: p384Signer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			agent := newCA(t, test.agent(t), defaultCAOptions())
			gateway := newCA(t, test.gateway(t), defaultCAOptions())
			command := test.command(t)
			authorities, err := pki.NewAuthorities(agent.der, agent.signer, gateway.der, gateway.signer, command)
			if err != nil {
				t.Fatalf("NewAuthorities rejected approved distinct keys: %v", err)
			}
			if authorities == nil {
				t.Fatal("NewAuthorities returned nil authorities")
			}
		})
	}
}

// TestNewAuthorities_RejectsInvalidCA pins exact-DER parsing plus the CA,
// CertSign, CRLSign, and SubjectKeyId preconditions required by x509 CRL minting.
func TestNewAuthorities_RejectsInvalidCA(t *testing.T) {
	agentSigner := p256Signer(t)
	agent := newCA(t, agentSigner, defaultCAOptions())
	gateway := newCA(t, p384Signer(t), defaultCAOptions())
	command := p521Signer(t)
	tests := []struct {
		name    string
		der     func(*testing.T, crypto.Signer) []byte
		wantErr func(string) string
	}{
		{name: "empty DER", der: func(*testing.T, crypto.Signer) []byte { return nil }, wantErr: parseCAError},
		{name: "malformed DER", der: func(*testing.T, crypto.Signer) []byte { return []byte("not DER") }, wantErr: parseCAError},
		{name: "trailing DER", der: func(t *testing.T, signer crypto.Signer) []byte {
			ca := newCA(t, signer, defaultCAOptions())
			return append(append([]byte(nil), ca.der...), 0)
		}, wantErr: fixedError("trailing data")},
		{name: "not a CA", der: func(t *testing.T, signer crypto.Signer) []byte {
			opts := defaultCAOptions()
			opts.isCA = false
			return newCA(t, signer, opts).der
		}, wantErr: fixedError("not a CA")},
		{name: "missing certificate signing usage", der: func(t *testing.T, signer crypto.Signer) []byte {
			opts := defaultCAOptions()
			opts.keyUsage &^= x509.KeyUsageCertSign
			return newCA(t, signer, opts).der
		}, wantErr: fixedError("certificate-signing key usage")},
		{name: "missing CRL signing usage", der: func(t *testing.T, signer crypto.Signer) []byte {
			opts := defaultCAOptions()
			opts.keyUsage &^= x509.KeyUsageCRLSign
			return newCA(t, signer, opts).der
		}, wantErr: fixedError("CRL-signing key usage")},
		{name: "missing subject key ID", der: func(t *testing.T, signer crypto.Signer) []byte {
			opts := defaultCAOptions()
			opts.subjectKeyID = false
			return newCA(t, signer, opts).der
		}, wantErr: fixedError("subject key ID")},
	}
	roles := []struct {
		name   string
		signer crypto.Signer
		build  func([]byte) error
	}{
		{name: "agent", signer: agentSigner, build: func(der []byte) error {
			_, err := pki.NewAuthorities(der, agentSigner, gateway.der, gateway.signer, command)
			return err
		}},
		{name: "gateway", signer: gateway.signer, build: func(der []byte) error {
			_, err := pki.NewAuthorities(agent.der, agent.signer, der, gateway.signer, command)
			return err
		}},
	}
	for _, role := range roles {
		for _, test := range tests {
			t.Run(role.name+"/"+test.name, func(t *testing.T) {
				err := role.build(test.der(t, role.signer))
				assertErrorContains(t, err, test.wantErr(role.name))
			})
		}
	}
}

func parseCAError(role string) string { return "parse " + role + " CA certificate" }

func fixedError(message string) func(string) string {
	return func(string) string { return message }
}

// TestNewAuthorities_RejectsMismatchedOrReusedKeys pins signer/certificate
// binding and pairwise separation of agent CA, gateway CA, and command keys.
func TestNewAuthorities_RejectsMismatchedOrReusedKeys(t *testing.T) {
	tests := []struct {
		name    string
		build   func(*testing.T) (testCA, testCA, crypto.Signer)
		wantErr string
	}{
		{name: "agent signer mismatch", build: func(t *testing.T) (testCA, testCA, crypto.Signer) {
			agent := newCA(t, p256Signer(t), defaultCAOptions())
			agent.signer = p384Signer(t)
			return agent, newCA(t, p521Signer(t), defaultCAOptions()), rsa2048Signer(t)
		}, wantErr: "agent CA signer does not match certificate"},
		{name: "gateway signer mismatch", build: func(t *testing.T) (testCA, testCA, crypto.Signer) {
			gateway := newCA(t, p384Signer(t), defaultCAOptions())
			gateway.signer = p521Signer(t)
			return newCA(t, p256Signer(t), defaultCAOptions()), gateway, rsa2048Signer(t)
		}, wantErr: "gateway CA signer does not match certificate"},
		{name: "CA key reused", build: func(t *testing.T) (testCA, testCA, crypto.Signer) {
			shared := p256Signer(t)
			return newCA(t, shared, defaultCAOptions()), newCA(t, shared, defaultCAOptions()), p384Signer(t)
		}, wantErr: "agent and gateway CA keys are reused"},
		{name: "command key reuses agent CA", build: func(t *testing.T) (testCA, testCA, crypto.Signer) {
			agent := newCA(t, p256Signer(t), defaultCAOptions())
			return agent, newCA(t, p384Signer(t), defaultCAOptions()), agent.signer
		}, wantErr: "command key reuses agent CA key"},
		{name: "command key reuses gateway CA", build: func(t *testing.T) (testCA, testCA, crypto.Signer) {
			gateway := newCA(t, p384Signer(t), defaultCAOptions())
			return newCA(t, p256Signer(t), defaultCAOptions()), gateway, gateway.signer
		}, wantErr: "command key reuses gateway CA key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			agent, gateway, command := test.build(t)
			_, err := pki.NewAuthorities(agent.der, agent.signer, gateway.der, gateway.signer, command)
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

// TestNewAuthorities_RejectsUnsupportedSigningProfiles proves all three
// boot-time key inputs route through the shared fail-closed profile gate.
func TestNewAuthorities_RejectsUnsupportedSigningProfiles(t *testing.T) {
	agent := newCA(t, p256Signer(t), defaultCAOptions())
	gateway := newCA(t, p384Signer(t), defaultCAOptions())
	validCommand := p521Signer(t)
	agentECDSA := agent.signer.(*ecdsa.PrivateKey)
	agentECDSAScalar, err := agentECDSA.Bytes()
	if err != nil {
		t.Fatalf("encode valid agent CA scalar: %v", err)
	}
	agentMismatchedScalar := new(big.Int).Add(new(big.Int).SetBytes(agentECDSAScalar), big.NewInt(1))
	agentMismatchedScalar.Mod(agentMismatchedScalar, agentECDSA.Curve.Params().N)
	if agentMismatchedScalar.Sign() == 0 {
		agentMismatchedScalar.SetInt64(1)
	}
	agentMismatchedD := ecdsaPrivateKeyWithScalar(t, agentECDSA.PublicKey, agentMismatchedScalar.Bytes())
	commandECDSA := validCommand.(*ecdsa.PrivateKey)
	commandNilD := ecdsaPrivateKeyWithScalar(t, commandECDSA.PublicKey, nil)
	rsaGatewaySigner := rsa2048Signer(t).(*rsa.PrivateKey)
	rsaGateway := newCA(t, rsaGatewaySigner, defaultCAOptions())
	rsaGatewayMissingPrimes := *rsaGatewaySigner
	rsaGatewayMissingPrimes.Primes = nil
	rsaCommandSigner := rsa2048Signer(t).(*rsa.PrivateKey)
	rsaCommandZeroD := *rsaCommandSigner
	rsaCommandZeroD.D = new(big.Int)
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 fixture: %v", err)
	}
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024 fixture: %v", err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224 fixture: %v", err)
	}
	malformed := ecdsaPrivateKeyWithScalar(t, ecdsa.PublicKey{Curve: elliptic.P256()}, []byte{1})
	var typedNil *ecdsa.PrivateKey
	weakGateway := newCA(t, weakRSA, defaultCAOptions())
	tests := []struct {
		name       string
		agent      crypto.Signer
		gateway    crypto.Signer
		command    crypto.Signer
		gatewayDER []byte
		wantErr    string
	}{
		{name: "nil agent CA signer", gateway: gateway.signer, command: validCommand, wantErr: "nil"},
		{name: "typed-nil gateway CA signer", agent: agent.signer, gateway: typedNil, command: validCommand, wantErr: "nil"},
		{name: "Ed25519 command signer", agent: agent.signer, gateway: gateway.signer, command: ed25519Key, wantErr: "ed25519"},
		{name: "P-224 agent CA signer", agent: p224, gateway: gateway.signer, command: validCommand, wantErr: "unsupported ECDSA curve"},
		{name: "RSA-1024 gateway CA signer", agent: agent.signer, gateway: weakRSA, gatewayDER: weakGateway.der, command: validCommand, wantErr: "2048"},
		{name: "malformed command signer", agent: agent.signer, gateway: gateway.signer, command: malformed, wantErr: "malformed"},
		{name: "agent CA signer has mismatched ECDSA private scalar", agent: agentMismatchedD, gateway: gateway.signer, command: validCommand, wantErr: "invalid ECDSA private key"},
		{name: "gateway CA signer has invalid RSA private components", agent: agent.signer, gateway: &rsaGatewayMissingPrimes, gatewayDER: rsaGateway.der, command: validCommand, wantErr: "invalid RSA private key"},
		{name: "command signer has nil ECDSA private scalar", agent: agent.signer, gateway: gateway.signer, command: commandNilD, wantErr: "invalid ECDSA private key"},
		{name: "command signer has zero RSA private exponent", agent: agent.signer, gateway: gateway.signer, command: &rsaCommandZeroD, wantErr: "invalid RSA private key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gatewayDER := test.gatewayDER
			if gatewayDER == nil {
				gatewayDER = gateway.der
			}
			_, err := pki.NewAuthorities(agent.der, test.agent, gatewayDER, test.gateway, test.command)
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

// TestAuthorities_SignCommandUsesCommandAuthority proves command signatures
// come from the dedicated command key, never either CA signer.
func TestAuthorities_SignCommandUsesCommandAuthority(t *testing.T) {
	agent := newCA(t, p256Signer(t), defaultCAOptions())
	gateway := newCA(t, p384Signer(t), defaultCAOptions())
	command := p521Signer(t)
	authorities, err := pki.NewAuthorities(agent.der, agent.signer, gateway.der, gateway.signer, command)
	if err != nil {
		t.Fatalf("NewAuthorities: %v", err)
	}
	cmd := testCommand()
	if err := authorities.SignCommand(cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	if _, err := sign.VerifyCommand(command.Public(), cmd, testCommandOptions()); err != nil {
		t.Fatalf("command authority signature did not verify: %v", err)
	}
	for name, wrongKey := range map[string]crypto.PublicKey{
		"agent CA":   agent.signer.Public(),
		"gateway CA": gateway.signer.Public(),
	} {
		if _, err := sign.VerifyCommand(wrongKey, cmd, testCommandOptions()); err == nil {
			t.Errorf("command signature verified with %s key", name)
		}
	}
}

// TestAuthorities_SignRevocationListsWithClassCA pins class-separated CRL
// issuance: each list verifies only under its owning CA certificate.
func TestAuthorities_SignRevocationListsWithClassCA(t *testing.T) {
	agent := newCA(t, p256Signer(t), defaultCAOptions())
	gateway := newCA(t, p384Signer(t), defaultCAOptions())
	authorities, err := pki.NewAuthorities(agent.der, agent.signer, gateway.der, gateway.signer, p521Signer(t))
	if err != nil {
		t.Fatalf("NewAuthorities: %v", err)
	}

	agentDER, err := authorities.SignAgentRevocationList(testRevocationList(1))
	if err != nil {
		t.Fatalf("SignAgentRevocationList: %v", err)
	}
	gatewayDER, err := authorities.SignGatewayRevocationList(testRevocationList(2))
	if err != nil {
		t.Fatalf("SignGatewayRevocationList: %v", err)
	}
	agentList := parseRevocationList(t, agentDER)
	gatewayList := parseRevocationList(t, gatewayDER)
	if err := agentList.CheckSignatureFrom(agent.cert); err != nil {
		t.Fatalf("agent CRL does not verify under agent CA: %v", err)
	}
	if err := gatewayList.CheckSignatureFrom(gateway.cert); err != nil {
		t.Fatalf("gateway CRL does not verify under gateway CA: %v", err)
	}
	if err := agentList.CheckSignatureFrom(gateway.cert); err == nil {
		t.Error("agent CRL verified under gateway CA")
	}
	if err := gatewayList.CheckSignatureFrom(agent.cert); err == nil {
		t.Error("gateway CRL verified under agent CA")
	}
}

// TestAuthorities_SignRevocationListsRejectReservedExtensions prevents raw
// ExtraExtensions from overriding the class CA's authority key identifier or
// the typed monotonic CRL number in the serialized list.
func TestAuthorities_SignRevocationListsRejectReservedExtensions(t *testing.T) {
	agent := newCA(t, p256Signer(t), defaultCAOptions())
	gateway := newCA(t, p384Signer(t), defaultCAOptions())
	authorities, err := pki.NewAuthorities(agent.der, agent.signer, gateway.der, gateway.signer, p521Signer(t))
	if err != nil {
		t.Fatalf("NewAuthorities: %v", err)
	}
	maliciousNumber := big.NewInt(999)
	maliciousNumberDER, err := asn1.Marshal(maliciousNumber)
	if err != nil {
		t.Fatalf("marshal malicious CRL number: %v", err)
	}
	maliciousKeyID := []byte{0x42}
	tests := []struct {
		name      string
		extension pkix.Extension
	}{
		{name: "authorityKeyIdentifier", extension: pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35},
			Value: []byte{0x30, 0x03, 0x80, 0x01, 0x42},
		}},
		{name: "cRLNumber", extension: pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 20},
			Value: maliciousNumberDER,
		}},
	}
	roles := []struct {
		name   string
		issuer testCA
		sign   func(*x509.RevocationList) ([]byte, error)
	}{
		{name: "agent", issuer: agent, sign: authorities.SignAgentRevocationList},
		{name: "gateway", issuer: gateway, sign: authorities.SignGatewayRevocationList},
	}
	for _, role := range roles {
		for _, test := range tests {
			t.Run(role.name+"/"+test.name, func(t *testing.T) {
				template := testRevocationList(7)
				template.ExtraExtensions = []pkix.Extension{test.extension}
				der, err := role.sign(template)
				if err != nil {
					if der != nil {
						t.Errorf("reserved extension rejection returned %d DER bytes", len(der))
					}
					assertErrorContains(t, err, "reserved CRL extension")
					return
				}

				parsed := parseRevocationList(t, der)
				duplicateCount := 0
				for _, extension := range parsed.Extensions {
					if extension.Id.Equal(test.extension.Id) {
						duplicateCount++
					}
				}
				switch test.name {
				case "authorityKeyIdentifier":
					t.Fatalf("accepted reserved authorityKeyIdentifier ExtraExtension: serialized %d copies and parser selected key ID %x instead of issuer key ID %x (override=%t)", duplicateCount, parsed.AuthorityKeyId, role.issuer.cert.SubjectKeyId, reflect.DeepEqual(parsed.AuthorityKeyId, maliciousKeyID))
				case "cRLNumber":
					overridden := parsed.Number != nil && parsed.Number.Cmp(maliciousNumber) == 0
					t.Fatalf("accepted reserved cRLNumber ExtraExtension: serialized %d copies and parser selected number %v instead of typed number 7 (override=%t)", duplicateCount, parsed.Number, overridden)
				}
			})
		}
	}
}

// TestAuthorities_KeepPrivateKeysOpaque prevents custody from growing a
// private-key accessor while later issuance APIs are still out of scope.
func TestAuthorities_KeepPrivateKeysOpaque(t *testing.T) {
	agent := newCA(t, p256Signer(t), defaultCAOptions())
	gateway := newCA(t, p384Signer(t), defaultCAOptions())
	authorities, err := pki.NewAuthorities(agent.der, agent.signer, gateway.der, gateway.signer, p521Signer(t))
	if err != nil {
		t.Fatalf("NewAuthorities: %v", err)
	}
	signerType := reflect.TypeFor[crypto.Signer]()
	typeOfAuthorities := reflect.TypeOf(authorities)
	for i := 0; i < typeOfAuthorities.NumMethod(); i++ {
		method := typeOfAuthorities.Method(i)
		for out := 0; out < method.Type.NumOut(); out++ {
			if method.Type.Out(out).Implements(signerType) {
				t.Errorf("Authorities.%s exposes a private signer", method.Name)
			}
		}
	}
}

// TestDERResultVerifier_ParsesStoredCertificateEveryCall is AC-14: changing
// exact stored DER changes the verifying key on the next call; no projection
// key or cached first certificate can remain authoritative.
func TestDERResultVerifier_ParsesStoredCertificateEveryCall(t *testing.T) {
	firstKey := p256Signer(t)
	secondKey := p384Signer(t)
	firstDER := newLeafCertificate(t, firstKey.Public(), p521Signer(t))
	secondDER := newLeafCertificate(t, secondKey.Public(), p521Signer(t))
	envelope := testResult()
	if err := sign.SignResult(firstKey, envelope); err != nil {
		t.Fatalf("SignResult(first key): %v", err)
	}
	verifier := pki.DERResultVerifier{}
	payload, err := verifier.VerifyResult(firstDER, envelope, sign.ResultVerifyOptions{DeviceID: testDeviceID})
	if err != nil || string(payload) != "result payload" {
		t.Fatalf("VerifyResult(first DER) = (%q, %v)", payload, err)
	}
	payload, err = verifier.VerifyResult(secondDER, envelope, sign.ResultVerifyOptions{DeviceID: testDeviceID})
	if err == nil || payload != nil {
		t.Fatalf("VerifyResult(second DER, first signature) = (%q, %v); want signature rejection", payload, err)
	}
	assertErrorContains(t, err, "signature")

	envelope = testResult()
	if err := sign.SignResult(secondKey, envelope); err != nil {
		t.Fatalf("SignResult(second key): %v", err)
	}
	payload, err = verifier.VerifyResult(secondDER, envelope, sign.ResultVerifyOptions{DeviceID: testDeviceID})
	if err != nil || string(payload) != "result payload" {
		t.Fatalf("VerifyResult(second DER) = (%q, %v)", payload, err)
	}
}

// TestDERResultVerifier_FailsClosed pins malformed/non-exact DER, unsupported
// certificate keys, and bad signatures to specific rejection categories.
func TestDERResultVerifier_FailsClosed(t *testing.T) {
	validKey := p256Signer(t)
	validDER := newLeafCertificate(t, validKey.Public(), p521Signer(t))
	validEnvelope := testResult()
	if err := sign.SignResult(validKey, validEnvelope); err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 fixture: %v", err)
	}
	ed25519DER := newLeafCertificate(t, ed25519Key.Public(), p521Signer(t))
	tests := []struct {
		name     string
		der      []byte
		envelope func() *powermanagev1.DeviceSigned
		wantErr  string
	}{
		{name: "empty DER", wantErr: "parse stored certificate DER"},
		{name: "malformed DER", der: []byte("not DER"), wantErr: "parse stored certificate DER"},
		{name: "trailing DER", der: append(append([]byte(nil), validDER...), 0), wantErr: "trailing data"},
		{name: "unsupported Ed25519 certificate key", der: ed25519DER, envelope: testResult, wantErr: "ed25519"},
		{name: "bad signature", der: validDER, envelope: func() *powermanagev1.DeviceSigned {
			envelope := testResult()
			envelope.Signature = []byte{1}
			return envelope
		}, wantErr: "signature"},
	}
	verifier := pki.DERResultVerifier{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := validEnvelope
			if test.envelope != nil {
				envelope = test.envelope()
			}
			payload, err := verifier.VerifyResult(test.der, envelope, sign.ResultVerifyOptions{DeviceID: testDeviceID})
			if payload != nil {
				t.Errorf("VerifyResult returned payload %q on rejection", payload)
			}
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

type testCA struct {
	der    []byte
	cert   *x509.Certificate
	signer crypto.Signer
}

type caOptions struct {
	isCA         bool
	keyUsage     x509.KeyUsage
	subjectKeyID bool
}

func defaultCAOptions() caOptions {
	return caOptions{isCA: true, keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, subjectKeyID: true}
}

func newCA(t *testing.T, signer crypto.Signer, opts caOptions) testCA {
	t.Helper()
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal CA public key: %v", err)
	}
	keyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  opts.isCA,
		BasicConstraintsValid: true,
		KeyUsage:              opts.keyUsage,
	}
	if opts.subjectKeyID {
		template.SubjectKeyId = append([]byte(nil), keyID[:20]...)
	} else {
		// CreateCertificate otherwise synthesizes a SubjectKeyId for a CA.
		// An explicit empty extension produces the invalid-but-parseable boot
		// fixture required to prove the CRL signer precondition.
		template.ExtraExtensions = []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14},
			Value: []byte{0x04, 0x00},
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate fixture: %v", err)
	}
	return testCA{der: der, cert: cert, signer: signer}
}

func newLeafCertificate(t *testing.T, publicKey crypto.PublicKey, issuerSigner crypto.Signer) []byte {
	t.Helper()
	issuer := newCA(t, issuerSigner, defaultCAOptions())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: testDeviceID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, publicKey, issuer.signer)
	if err != nil {
		t.Fatalf("create device certificate: %v", err)
	}
	return der
}

func testCommand() *powermanagev1.SignedCommand {
	return &powermanagev1.SignedCommand{
		Payload:        []byte("command payload"),
		CommandType:    "action",
		TargetDeviceId: testDeviceID,
		IssuedAt:       timestamppb.New(time.Unix(1700000000, 0)),
		ExpiresAt:      timestamppb.New(time.Unix(1700000030, 0)),
	}
}

func testCommandOptions() sign.VerifyOptions {
	return sign.VerifyOptions{DeviceID: testDeviceID, Now: time.Unix(1700000005, 0), Instant: true}
}

func testResult() *powermanagev1.DeviceSigned {
	return &powermanagev1.DeviceSigned{
		Payload:    []byte("result payload"),
		ResultType: "execution",
		DeviceId:   testDeviceID,
		IssuedAt:   timestamppb.New(time.Unix(1700000000, 0)),
	}
}

func testRevocationList(number int64) *x509.RevocationList {
	return &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}
}

func parseRevocationList(t *testing.T, der []byte) *x509.RevocationList {
	t.Helper()
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse signed CRL: %v", err)
	}
	return list
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error; want rejection containing %q", want)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
		t.Fatalf("error = %q; want substring %q", err, want)
	}
}

func ecdsaPrivateKeyWithScalar(t *testing.T, public ecdsa.PublicKey, scalar []byte) *ecdsa.PrivateKey {
	t.Helper()
	key := &ecdsa.PrivateKey{PublicKey: public}
	field := reflect.ValueOf(key).Elem().FieldByName("D")
	if !field.IsValid() || !field.CanSet() {
		t.Fatal("ecdsa.PrivateKey scalar field D is unavailable to the adversarial test fixture")
	}
	if scalar == nil {
		field.Set(reflect.Zero(field.Type()))
	} else {
		field.Set(reflect.ValueOf(new(big.Int).SetBytes(scalar)))
	}
	return key
}

func p256Signer(t *testing.T) crypto.Signer { return ecdsaSigner(t, elliptic.P256()) }
func p384Signer(t *testing.T) crypto.Signer { return ecdsaSigner(t, elliptic.P384()) }
func p521Signer(t *testing.T) crypto.Signer { return ecdsaSigner(t, elliptic.P521()) }

func ecdsaSigner(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	return key
}

func rsa2048Signer(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA-2048 key: %v", err)
	}
	return key
}
