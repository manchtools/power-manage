package archtest

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestControlServiceOIDCShape(t *testing.T) {
	service, err := findService(packageFiles(ContractPackage), "ControlService")
	if err != nil {
		t.Fatalf("find ControlService: %v", err)
	}
	methods := service.Methods()
	wantTypes := map[string][2]string{
		"RefreshSession": {
			"powermanage.v1.RefreshSessionRequest",
			"powermanage.v1.RefreshSessionResponse",
		},
		"StartOidcSession": {
			"powermanage.v1.StartOidcSessionRequest",
			"powermanage.v1.StartOidcSessionResponse",
		},
		"CompleteOidcSession": {
			"powermanage.v1.CompleteOidcSessionRequest",
			"powermanage.v1.CompleteOidcSessionResponse",
		},
	}
	for name, expected := range wantTypes {
		method := methods.ByName(protoreflect.Name(name))
		if method == nil {
			t.Fatalf("ControlService method %s is missing", name)
		}
		if method.IsStreamingClient() || method.IsStreamingServer() {
			t.Fatalf("%s must be unary", method.FullName())
		}
		if got := string(method.Input().FullName()); got != expected[0] {
			t.Fatalf("%s input = %s; want %s", method.FullName(), got, expected[0])
		}
		if got := string(method.Output().FullName()); got != expected[1] {
			t.Fatalf("%s output = %s; want %s", method.FullName(), got, expected[1])
		}
	}
}
