package archtest

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestPkiServiceRotationShape(t *testing.T) {
	files := packageFiles(ContractPackage)
	service, err := findService(files, "PkiService")
	if err != nil {
		t.Fatalf("find PkiService: %v", err)
	}
	methods := service.Methods()
	if methods.Len() != 9 {
		t.Fatalf("PkiService methods = %d; want seven lifecycle methods plus two trust confirmations", methods.Len())
	}
	confirmAgent := methods.ByName("ConfirmAgentTrustState")
	confirmGateway := methods.ByName("ConfirmGatewayTrustState")
	for _, method := range []protoreflect.MethodDescriptor{confirmAgent, confirmGateway} {
		if method == nil || method.IsStreamingClient() || method.IsStreamingServer() {
			t.Fatalf("trust-state confirmation method = %v; want a unary method", method)
		}
		assertMessageFields(t, method.Input(), []string{
			"certificate_der", "claimed_class", "generation", "revision", "root_fingerprints",
			"crl_issuer_fingerprint", "crl_sequence", "signature",
		})
		assertMessageFields(t, method.Output(), nil)
		assertBytesBounds(t, method.Input().Fields().ByName("certificate_der"), 1, 65536)
		assertRepeatedBytesBounds(t, method.Input().Fields().ByName("root_fingerprints"), 1, 2, 32, 32)
		issuerRules := fieldRules(requirePkiField(t, method.Input().Fields().ByName("crl_issuer_fingerprint"))).GetBytes()
		if issuerRules == nil || issuerRules.Len == nil || issuerRules.GetLen() != 32 {
			t.Fatalf("%s CRL issuer rules = %v; want optional exact len=32", method.Input().FullName(), issuerRules)
		}
		assertBytesBounds(t, method.Input().Fields().ByName("signature"), 1, 8192)
	}
	if confirmAgent.Input() != confirmGateway.Input() || confirmAgent.Output() != confirmGateway.Output() {
		t.Fatal("agent and gateway confirmation RPCs must share one request/response definition; reporter authorization comes from the procedure")
	}

	bundle, err := findRegistry(files, "CATrustBundle")
	if err != nil {
		t.Fatalf("find CATrustBundle: %v", err)
	}
	assertMessageFields(t, bundle, []string{
		"generation", "revision", "root_certificate_der", "transition_certificate_der", "crl_issuer_fingerprint", "crl_sequence",
	})
	if field := requirePkiField(t, bundle.Fields().ByName("root_certificate_der")); !field.IsList() || field.Kind() != protoreflect.BytesKind {
		t.Fatalf("CATrustBundle.root_certificate_der = (%v, list %v); want repeated bytes", field.Kind(), field.IsList())
	}
	assertRepeatedBytesBounds(t, bundle.Fields().ByName("root_certificate_der"), 1, 2, 1, 65536)
	transitionRules := fieldRules(requirePkiField(t, bundle.Fields().ByName("transition_certificate_der"))).GetBytes()
	if transitionRules == nil || transitionRules.MaxLen == nil || transitionRules.GetMaxLen() != 65536 || transitionRules.MinLen != nil {
		t.Fatalf("CATrustBundle.transition_certificate_der rules = %v; want optional max_len=65536", transitionRules)
	}
	issuerRules := fieldRules(requirePkiField(t, bundle.Fields().ByName("crl_issuer_fingerprint"))).GetBytes()
	if issuerRules == nil || issuerRules.Len == nil || issuerRules.GetLen() != 32 {
		t.Fatalf("CATrustBundle.crl_issuer_fingerprint rules = %v; want optional exact len=32", issuerRules)
	}

	for _, methodName := range []protoreflect.Name{"EnrollAgent", "RenewAgent", "EnrollGateway", "RenewGateway"} {
		method := methods.ByName(methodName)
		if method == nil {
			t.Fatalf("PkiService.%s is absent", methodName)
		}
		fields := method.Output().Fields()
		if agent := fields.ByName("agent_trust_bundle"); agent == nil || agent.Message() != bundle {
			t.Fatalf("%s.agent_trust_bundle does not use the shared CATrustBundle", method.Output().FullName())
		}
		if gateway := fields.ByName("gateway_trust_bundle"); gateway == nil || gateway.Message() != bundle {
			t.Fatalf("%s.gateway_trust_bundle does not use the shared CATrustBundle", method.Output().FullName())
		}
	}
}

func assertRepeatedBytesBounds(
	t *testing.T,
	field protoreflect.FieldDescriptor,
	minItems uint64,
	maxItems uint64,
	minBytes uint64,
	maxBytes uint64,
) {
	t.Helper()
	field = requirePkiField(t, field)
	if !field.IsList() || field.IsMap() || field.Kind() != protoreflect.BytesKind {
		t.Fatalf("%s = (%v, list %v, map %v); want repeated bytes", field.FullName(), field.Kind(), field.IsList(), field.IsMap())
	}
	rules := fieldRules(field).GetRepeated()
	if rules == nil || rules.MinItems == nil || rules.MaxItems == nil ||
		rules.GetMinItems() != minItems || rules.GetMaxItems() != maxItems || rules.Items == nil {
		t.Fatalf("%s repeated rules = %v; want %d..%d items", field.FullName(), rules, minItems, maxItems)
	}
	bytesRules := rules.Items.GetBytes()
	if minBytes == maxBytes {
		if bytesRules == nil || bytesRules.Len == nil || bytesRules.GetLen() != minBytes {
			t.Fatalf("%s item bytes rules = %v; want exact len=%d", field.FullName(), bytesRules, minBytes)
		}
		return
	}
	if bytesRules == nil || bytesRules.MinLen == nil || bytesRules.MaxLen == nil ||
		bytesRules.GetMinLen() != minBytes || bytesRules.GetMaxLen() != maxBytes {
		t.Fatalf("%s item bytes rules = %v; want %d..%d bytes", field.FullName(), bytesRules, minBytes, maxBytes)
	}
}
