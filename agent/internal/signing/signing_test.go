package signing_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/manchtools/power-manage/agent/internal/signing"
	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
)

const testDeviceID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// TestNewProfile_RejectsUnsupportedSigningProfiles pins the M2 boot boundary:
// command custody is public-key-only and both roles use the shared key profile.
func TestNewProfile_RejectsUnsupportedSigningProfiles(t *testing.T) {
	validCommand := p256Signer(t)
	validDevice := p384Signer(t)
	ed25519Public, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
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
	malformedPublic := &ecdsa.PublicKey{Curve: elliptic.P256()}
	malformedPrivate := ecdsaPrivateKeyWithScalar(t, *malformedPublic, []byte{1})
	validECDSADevice := validDevice.(*ecdsa.PrivateKey)
	validECDSADeviceScalar, err := validECDSADevice.Bytes()
	if err != nil {
		t.Fatalf("encode valid ECDSA device scalar: %v", err)
	}
	mismatchedECDSADeviceScalar := new(big.Int).Add(new(big.Int).SetBytes(validECDSADeviceScalar), big.NewInt(1))
	mismatchedECDSADeviceScalar.Mod(mismatchedECDSADeviceScalar, validECDSADevice.Curve.Params().N)
	if mismatchedECDSADeviceScalar.Sign() == 0 {
		mismatchedECDSADeviceScalar.SetInt64(1)
	}
	ecdsaNilD := ecdsaPrivateKeyWithScalar(t, validECDSADevice.PublicKey, nil)
	ecdsaZeroD := ecdsaPrivateKeyWithScalar(t, validECDSADevice.PublicKey, []byte{})
	ecdsaMismatchedD := ecdsaPrivateKeyWithScalar(t, validECDSADevice.PublicKey, mismatchedECDSADeviceScalar.Bytes())
	validRSADevice := rsa2048Signer(t).(*rsa.PrivateKey)
	rsaNilD := *validRSADevice
	rsaNilD.D = nil
	rsaZeroD := *validRSADevice
	rsaZeroD.D = new(big.Int)
	rsaMismatchedD := *validRSADevice
	rsaMismatchedD.D = new(big.Int).Add(validRSADevice.D, big.NewInt(1))
	rsaMissingPrimes := *validRSADevice
	rsaMissingPrimes.Primes = nil
	var typedNilPublic *ecdsa.PublicKey
	var typedNilPrivate *ecdsa.PrivateKey
	tests := []struct {
		name       string
		commandKey crypto.PublicKey
		deviceKey  crypto.Signer
		wantErr    string
	}{
		{name: "nil command verification key", deviceKey: validDevice, wantErr: "nil"},
		{name: "typed-nil command verification key", commandKey: typedNilPublic, deviceKey: validDevice, wantErr: "nil"},
		{name: "command private key violates custody", commandKey: validCommand, deviceKey: validDevice, wantErr: "command verification key must be public"},
		{name: "device key reuses command authority", commandKey: validCommand.Public(), deviceKey: validCommand, wantErr: "must differ"},
		{name: "Ed25519 command key", commandKey: ed25519Public, deviceKey: validDevice, wantErr: "ed25519"},
		{name: "P-224 command key", commandKey: &p224.PublicKey, deviceKey: validDevice, wantErr: "unsupported ECDSA curve"},
		{name: "RSA-1024 command key", commandKey: &weakRSA.PublicKey, deviceKey: validDevice, wantErr: "2048"},
		{name: "malformed command key", commandKey: malformedPublic, deviceKey: validDevice, wantErr: "malformed"},
		{name: "nil device signing key", commandKey: validCommand.Public(), wantErr: "nil"},
		{name: "typed-nil device signing key", commandKey: validCommand.Public(), deviceKey: typedNilPrivate, wantErr: "nil"},
		{name: "Ed25519 device key", commandKey: validCommand.Public(), deviceKey: ed25519Private, wantErr: "ed25519"},
		{name: "P-224 device key", commandKey: validCommand.Public(), deviceKey: p224, wantErr: "unsupported ECDSA curve"},
		{name: "RSA-1024 device key", commandKey: validCommand.Public(), deviceKey: weakRSA, wantErr: "2048"},
		{name: "malformed device key", commandKey: validCommand.Public(), deviceKey: malformedPrivate, wantErr: "malformed"},
		{name: "device ECDSA key has nil D", commandKey: validCommand.Public(), deviceKey: ecdsaNilD, wantErr: "invalid ECDSA private key"},
		{name: "device ECDSA key has zero D", commandKey: validCommand.Public(), deviceKey: ecdsaZeroD, wantErr: "invalid ECDSA private key"},
		{name: "device ECDSA key has mismatched D", commandKey: validCommand.Public(), deviceKey: ecdsaMismatchedD, wantErr: "invalid ECDSA private key"},
		{name: "device RSA key has nil D", commandKey: validCommand.Public(), deviceKey: &rsaNilD, wantErr: "invalid RSA private key"},
		{name: "device RSA key has zero D", commandKey: validCommand.Public(), deviceKey: &rsaZeroD, wantErr: "invalid RSA private key"},
		{name: "device RSA key has mismatched D", commandKey: validCommand.Public(), deviceKey: &rsaMismatchedD, wantErr: "invalid RSA private key"},
		{name: "device RSA key has missing primes", commandKey: validCommand.Public(), deviceKey: &rsaMissingPrimes, wantErr: "invalid RSA private key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := signing.NewProfile(test.commandKey, test.deviceKey)
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

// TestProfile_VerifiesCommandsAndSignsResults proves the two agent
// chokepoints accept all approved profiles and keep the device signer opaque.
func TestProfile_VerifiesCommandsAndSignsResults(t *testing.T) {
	tests := []struct {
		name    string
		command func(*testing.T) crypto.Signer
		device  func(*testing.T) crypto.Signer
	}{
		{name: "ECDSA P-256 command and P-384 device", command: p256Signer, device: p384Signer},
		{name: "ECDSA P-521 command and RSA-2048 device", command: p521Signer, device: rsa2048Signer},
		{name: "RSA-2048 command and ECDSA P-256 device", command: rsa2048Signer, device: p256Signer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commandKey := test.command(t)
			deviceKey := test.device(t)
			profile, err := signing.NewProfile(commandKey.Public(), deviceKey)
			if err != nil {
				t.Fatalf("NewProfile rejected approved keys: %v", err)
			}
			if profile == nil {
				t.Fatal("NewProfile returned nil profile")
			}

			command := testCommand()
			if err := sign.SignCommand(commandKey, command); err != nil {
				t.Fatalf("SignCommand fixture: %v", err)
			}
			payload, err := profile.VerifyCommand(command, commandOptions())
			if err != nil || string(payload) != "command payload" {
				t.Fatalf("VerifyCommand = (%q, %v)", payload, err)
			}

			result := testResult()
			if err := profile.SignResult(result); err != nil {
				t.Fatalf("SignResult: %v", err)
			}
			payload, err = sign.VerifyResult(deviceKey.Public(), result, sign.ResultVerifyOptions{DeviceID: testDeviceID})
			if err != nil || string(payload) != "result payload" {
				t.Fatalf("VerifyResult(profile signature) = (%q, %v)", payload, err)
			}

			signerType := reflect.TypeFor[crypto.Signer]()
			profileType := reflect.TypeOf(profile)
			for i := 0; i < profileType.NumMethod(); i++ {
				method := profileType.Method(i)
				for out := 0; out < method.Type.NumOut(); out++ {
					if method.Type.Out(out).Implements(signerType) {
						t.Errorf("Profile.%s exposes its device private signer", method.Name)
					}
				}
			}
		})
	}
}

// TestProfile_FailsClosedOnInvalidSignatures pins nil payload on command
// verification failure and proves result signatures bind the exact envelope.
func TestProfile_FailsClosedOnInvalidSignatures(t *testing.T) {
	commandKey := p256Signer(t)
	deviceKey := p384Signer(t)
	profile, err := signing.NewProfile(commandKey.Public(), deviceKey)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}

	command := testCommand()
	if err := sign.SignCommand(commandKey, command); err != nil {
		t.Fatalf("SignCommand fixture: %v", err)
	}
	command.Payload[0] ^= 0xff
	payload, err := profile.VerifyCommand(command, commandOptions())
	if payload != nil {
		t.Errorf("VerifyCommand returned payload %q for a tampered signature", payload)
	}
	assertErrorContains(t, err, "signature")

	result := testResult()
	if err := profile.SignResult(result); err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	result.DeviceId = "01BX5ZZKBKACTAV9WEVGEMMVS0"
	payload, err = sign.VerifyResult(deviceKey.Public(), result, sign.ResultVerifyOptions{DeviceID: result.DeviceId})
	if payload != nil {
		t.Errorf("VerifyResult returned payload %q for a re-addressed result", payload)
	}
	assertErrorContains(t, err, "signature")
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

func commandOptions() sign.VerifyOptions {
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
