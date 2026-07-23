package archtest

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestGuard_NoLocalCredentialSurface(t *testing.T) {
	files := Discover(t, "contract proto files", 11, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	messages := Discover(t, "contract messages", 1, func() ([]protoreflect.MessageDescriptor, error) {
		return allMessages(files), nil
	})
	for _, violation := range localCredentialFieldViolations(messages) {
		t.Errorf("%s — local password, TOTP, and WebAuthn credentials are forbidden (GUARD-007-6)", violation)
	}
}

func TestGuard_NoLocalCredentialSurface_Liveness(t *testing.T) {
	file := localCredentialFixture(t)
	messages := Discover(t, "local-credential fixture messages", 1, func() ([]protoreflect.MessageDescriptor, error) {
		return allMessages([]protoreflect.FileDescriptor{file}), nil
	})
	got := localCredentialFieldViolations(messages)
	want := []string{
		"powermanage.authfixture.v1.JSONAliasRequest.display_label",
		"powermanage.authfixture.v1.LocalCredentialRequest.password",
		"powermanage.authfixture.v1.LocalCredentialRequest.totpCode",
		"powermanage.authfixture.v1.LocalCredentialRequest.web_authn_credential",
		"powermanage.authfixture.v1.TypedCredentialRequest.assertion",
		"powermanage.authfixture.v1.TypedCredentialRequest.challenge",
		"powermanage.authfixture.v1.TypedCredentialRequest.response",
	}
	if len(got) != len(want) {
		t.Fatalf("fixture violations = %v, want exactly %v", got, want)
	}
	for i, field := range want {
		if !strings.HasPrefix(got[i], field+":") {
			t.Errorf("violation %d = %q, want it to flag %s", i, got[i], field)
		}
	}
	for _, violation := range got {
		if strings.Contains(violation, "external_credential_id") {
			t.Errorf("guard flagged generic external credential reference %q", violation)
		}
	}
}

func localCredentialFixture(t *testing.T) protoreflect.FileDescriptor {
	t.Helper()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	stringType := descriptorpb.FieldDescriptorProto_TYPE_STRING
	bytesType := descriptorpb.FieldDescriptorProto_TYPE_BYTES
	messageType := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:  proto.String("proto3"),
		Name:    proto.String("powermanage/authfixture/v1/auth.proto"),
		Package: proto.String("powermanage.authfixture.v1"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("JSONAliasRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{{
					Name: proto.String("display_label"), JsonName: proto.String("password"),
					Number: proto.Int32(1), Label: &optional, Type: &stringType,
				}},
			},
			{
				Name: proto.String("LocalCredentialRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("password"), Number: proto.Int32(1), Label: &optional, Type: &stringType},
					{Name: proto.String("totpCode"), Number: proto.Int32(2), Label: &optional, Type: &stringType},
					{Name: proto.String("web_authn_credential"), Number: proto.Int32(3), Label: &optional, Type: &bytesType},
					{Name: proto.String("external_credential_id"), Number: proto.Int32(4), Label: &optional, Type: &stringType},
				},
			},
			{Name: proto.String("PasswordCredential")},
			{Name: proto.String("TotpCredential")},
			{Name: proto.String("WebAuthnCredential")},
			{
				Name: proto.String("TypedCredentialRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name: proto.String("assertion"), Number: proto.Int32(1), Label: &optional, Type: &messageType,
						TypeName: proto.String(".powermanage.authfixture.v1.PasswordCredential"),
					},
					{
						Name: proto.String("challenge"), Number: proto.Int32(2), Label: &optional, Type: &messageType,
						TypeName: proto.String(".powermanage.authfixture.v1.TotpCredential"),
					},
					{
						Name: proto.String("response"), Number: proto.Int32(3), Label: &optional, Type: &messageType,
						TypeName: proto.String(".powermanage.authfixture.v1.WebAuthnCredential"),
					},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("build descriptor fixture: %v", err)
	}
	return file
}
