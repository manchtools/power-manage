package archtest

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestPkiServiceShape pins the public certificate-lifecycle wire surface.
// Requests carry operation-specific authorization inputs, never a
// self-asserted device identity, and responses cannot carry private key
// material.
func TestPkiServiceShape(t *testing.T) {
	files := packageFiles(ContractPackage)
	service, err := findService(files, "PkiService")
	if err != nil {
		t.Fatalf("find PkiService: %v", err)
	}
	methods := service.Methods()
	if methods.Len() != 4 {
		t.Fatalf("PkiService methods = %d; want four lifecycle methods", methods.Len())
	}
	enroll := methods.ByName("EnrollAgent")
	renew := methods.ByName("RenewAgent")
	revoke := methods.ByName("RevokeAgent")
	forceRenew := methods.ByName("ForceRenewAgent")
	for _, method := range []protoreflect.MethodDescriptor{enroll, renew, revoke, forceRenew} {
		if method == nil || method.IsStreamingClient() || method.IsStreamingServer() {
			t.Fatalf("PkiService method = %v; want a unary method", method)
		}
	}

	assertMessageFields(t, enroll.Input(), []string{
		"registration_token",
		"certificate_signing_request_der",
		"sealing_public_key",
	})
	assertMessageFields(t, enroll.Output(), []string{
		"certificate_der",
		"certificate_authority_der",
	})
	assertStringMaxLen(t, enroll.Input().Fields().ByName("registration_token"), 512)
	assertBytesBounds(t, enroll.Input().Fields().ByName("certificate_signing_request_der"), 1, 65536)
	assertBytesLen(t, enroll.Input().Fields().ByName("sealing_public_key"), 32)
	assertCertificateResponseBounds(t, enroll.Output())

	assertMessageFields(t, renew.Input(), []string{
		"certificate_der",
		"certificate_signing_request_der",
		"sealing_public_key",
	})
	assertMessageFields(t, renew.Output(), []string{
		"certificate_der",
		"certificate_authority_der",
	})
	assertBytesBounds(t, renew.Input().Fields().ByName("certificate_der"), 1, 65536)
	assertBytesBounds(t, renew.Input().Fields().ByName("certificate_signing_request_der"), 1, 65536)
	assertBytesLen(t, renew.Input().Fields().ByName("sealing_public_key"), 32)
	assertCertificateResponseBounds(t, renew.Output())

	for _, method := range []protoreflect.MethodDescriptor{revoke, forceRenew} {
		assertMessageFields(t, method.Input(), []string{"certificate_der"})
		assertBytesBounds(t, method.Input().Fields().ByName("certificate_der"), 1, 65536)
		assertMessageFields(t, method.Output(), nil)
	}
}

func assertCertificateResponseBounds(t *testing.T, message protoreflect.MessageDescriptor) {
	t.Helper()
	assertBytesBounds(t, message.Fields().ByName("certificate_der"), 1, 65536)
	assertBytesBounds(t, message.Fields().ByName("certificate_authority_der"), 1, 65536)
}

func assertMessageFields(t *testing.T, message protoreflect.MessageDescriptor, want []string) {
	t.Helper()
	got := make([]string, 0, message.Fields().Len())
	for i := 0; i < message.Fields().Len(); i++ {
		got = append(got, string(message.Fields().Get(i).Name()))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s fields = %v; want %v", message.FullName(), got, want)
	}
}

func requirePkiField(t *testing.T, field protoreflect.FieldDescriptor) protoreflect.FieldDescriptor {
	t.Helper()
	if field == nil {
		t.Fatal("required PkiService field is absent")
	}
	return field
}

func assertStringMaxLen(t *testing.T, field protoreflect.FieldDescriptor, max uint64) {
	t.Helper()
	field = requirePkiField(t, field)
	rules := fieldRules(field).GetString()
	if rules == nil || rules.MaxLen == nil || rules.GetMaxLen() != max || rules.MinLen != nil {
		t.Fatalf("%s string rules = %v; want max_len=%d with no minimum", field.FullName(), rules, max)
	}
}

func assertBytesBounds(t *testing.T, field protoreflect.FieldDescriptor, min, max uint64) {
	t.Helper()
	field = requirePkiField(t, field)
	rules := fieldRules(field).GetBytes()
	if rules == nil || rules.MinLen == nil || rules.MaxLen == nil || rules.GetMinLen() != min || rules.GetMaxLen() != max {
		t.Fatalf("%s bytes rules = %v; want min_len=%d max_len=%d", field.FullName(), rules, min, max)
	}
}

func assertBytesLen(t *testing.T, field protoreflect.FieldDescriptor, length uint64) {
	t.Helper()
	field = requirePkiField(t, field)
	rules := fieldRules(field).GetBytes()
	if rules == nil || rules.Len == nil || rules.GetLen() != length {
		t.Fatalf("%s bytes rules = %v; want len=%d", field.FullName(), rules, length)
	}
}
