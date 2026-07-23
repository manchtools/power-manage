package archtest

import (
	"slices"
	"testing"
)

func TestControlServiceOIDCShape(t *testing.T) {
	service, err := findService(packageFiles(ContractPackage), "ControlService")
	if err != nil {
		t.Fatalf("find ControlService: %v", err)
	}
	methods := service.Methods()
	if methods.Len() != 3 {
		t.Fatalf("ControlService methods = %d; want refresh plus OIDC start and completion", methods.Len())
	}
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
			"powermanage.v1.RefreshSessionResponse",
		},
	}
	var names []string
	for index := range methods.Len() {
		method := methods.Get(index)
		name := string(method.Name())
		names = append(names, name)
		if method.IsStreamingClient() || method.IsStreamingServer() {
			t.Fatalf("%s must be unary", method.FullName())
		}
		expected, ok := wantTypes[name]
		if !ok {
			t.Fatalf("unexpected ControlService method %s", method.FullName())
		}
		if got := string(method.Input().FullName()); got != expected[0] {
			t.Fatalf("%s input = %s; want %s", method.FullName(), got, expected[0])
		}
		if got := string(method.Output().FullName()); got != expected[1] {
			t.Fatalf("%s output = %s; want %s", method.FullName(), got, expected[1])
		}
	}
	slices.Sort(names)
	want := []string{"CompleteOidcSession", "RefreshSession", "StartOidcSession"}
	if !slices.Equal(names, want) {
		t.Fatalf("ControlService methods = %v; want %v", names, want)
	}
}
