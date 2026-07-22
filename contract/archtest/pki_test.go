package archtest

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestPkiServiceEnrollmentShape pins the M4 CSR-only public enrollment wire
// surface. The request has authorization material, never a self-asserted
// device identity, and the response cannot carry private key material.
func TestPkiServiceEnrollmentShape(t *testing.T) {
	files := packageFiles(ContractPackage)
	service, err := findService(files, "PkiService")
	if err != nil {
		t.Fatalf("find PkiService: %v", err)
	}
	methods := service.Methods()
	if methods.Len() != 1 {
		t.Fatalf("PkiService methods = %d; want exactly EnrollAgent", methods.Len())
	}
	method := methods.Get(0)
	if method.Name() != "EnrollAgent" || method.IsStreamingClient() || method.IsStreamingServer() {
		t.Fatalf("PkiService method = %s (client_stream=%v server_stream=%v); want unary EnrollAgent", method.Name(), method.IsStreamingClient(), method.IsStreamingServer())
	}

	assertMessageFields(t, method.Input(), []string{
		"registration_token",
		"certificate_signing_request_der",
		"sealing_public_key",
	})
	assertMessageFields(t, method.Output(), []string{
		"certificate_der",
		"certificate_authority_der",
	})

	assertStringMaxLen(t, method.Input().Fields().ByName("registration_token"), 512)
	assertBytesBounds(t, method.Input().Fields().ByName("certificate_signing_request_der"), 1, 65536)
	assertBytesLen(t, method.Input().Fields().ByName("sealing_public_key"), 32)
	assertBytesBounds(t, method.Output().Fields().ByName("certificate_der"), 1, 65536)
	assertBytesBounds(t, method.Output().Fields().ByName("certificate_authority_der"), 1, 65536)
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
