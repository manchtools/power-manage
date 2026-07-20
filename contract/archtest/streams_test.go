package archtest

// SPEC-003 M5 stream-protocol shape pins ([WIRE-28/29], §3.2, plan choices
// 1–7). These fail RED before the M5 protos land: findService / findRegistry /
// findEnum return the missing-subject error, and the Discover floors fail when
// a service has no RPCs or an oneof no members. Nothing here references a
// generated Go type that does not yet exist, so the package compiles and the
// failures are runtime assertions on the behaviour under test.

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// --- exact-set RPC surface (the G-2a floor rises, plan §"Test authorship") ---

// TestGuard_AgentServiceRPCs pins AgentService to exactly ONE bidi RPC
// `Stream(stream AgentFrame) returns (stream ServerFrame)` (plan choice 1):
// the ONE agent stream (§3.2). Self-discovering over the service's methods
// with a matches-zero floor; a second RPC, or a non-streaming Stream, or a
// wrong frame type all fail.
func TestGuard_AgentServiceRPCs(t *testing.T) {
	got := Discover(t, "AgentService RPCs", 1, func() ([]string, error) {
		svc, err := findService(packageFiles(ContractPackage), "AgentService")
		if err != nil {
			return nil, err
		}
		return methodNames(svc), nil
	})
	assertExact(t, "AgentService RPCs", got, []string{"Stream"})
	assertStreamRPC(t, "AgentService", "Stream", true, true, "AgentFrame", "ServerFrame")
}

// TestGuard_InternalServiceRPCs pins InternalService to exactly {Stream (bidi
// GatewayFrame→ControlFrame), ValidateTerminalToken (unary)} — the GW-3 stream
// plus the terminal-token unary (plan choices 1, 7). No sealed-credential RPC
// is minted (choice 8): its absence is part of the exact set.
func TestGuard_InternalServiceRPCs(t *testing.T) {
	got := Discover(t, "InternalService RPCs", 2, func() ([]string, error) {
		svc, err := findService(packageFiles(ContractPackage), "InternalService")
		if err != nil {
			return nil, err
		}
		return methodNames(svc), nil
	})
	assertExact(t, "InternalService RPCs", got, []string{"Stream", "ValidateTerminalToken"})
	assertStreamRPC(t, "InternalService", "Stream", true, true, "GatewayFrame", "ControlFrame")
	// ValidateTerminalToken is UNARY (choice 7): a streaming token check would
	// be a second freshness path.
	assertStreamRPC(t, "InternalService", "ValidateTerminalToken", false, false,
		"ValidateTerminalTokenRequest", "ValidateTerminalTokenResponse")
}

// --- frame oneof member sets, both directions, required (plan choice 1) ---

// TestGuard_AgentFrameMembers: AgentFrame.frame oneof is exactly
// {hello: Hello, report: DeviceSigned, artifact_fetch_request:
// ArtifactFetchRequest}, required (plan choice 1). The signed sync manifest is
// deliberately NOT a member — it rides SignedCommand (a second manifest
// carriage would be a second freshness path).
func TestGuard_AgentFrameMembers(t *testing.T) {
	got := Discover(t, "AgentFrame.frame oneof members", 3, func() ([]string, error) {
		return frameOneofMemberNames("AgentFrame")
	})
	assertFrameMembers(t, "AgentFrame", got, map[string]string{
		"hello":                  "Hello",
		"report":                 "DeviceSigned",
		"artifact_fetch_request": "ArtifactFetchRequest",
	})
}

// TestGuard_ServerFrameMembers: ServerFrame.frame oneof is exactly
// {welcome: Welcome, command: SignedCommand, artifact_chunk: ArtifactChunk,
// artifact_fetch_error: ArtifactFetchError}, required (plan choice 1).
func TestGuard_ServerFrameMembers(t *testing.T) {
	got := Discover(t, "ServerFrame.frame oneof members", 4, func() ([]string, error) {
		return frameOneofMemberNames("ServerFrame")
	})
	assertFrameMembers(t, "ServerFrame", got, map[string]string{
		"welcome":              "Welcome",
		"command":              "SignedCommand",
		"artifact_chunk":       "ArtifactChunk",
		"artifact_fetch_error": "ArtifactFetchError",
	})
}

// TestGuard_GatewayFrameMembers: GatewayFrame.frame oneof is exactly
// {device_connected: DeviceConnected, device_disconnected: DeviceDisconnected,
// device_report: DeviceReport, terminal_recording_chunk: TerminalRecordingChunk,
// artifact_fetch_relay: ArtifactFetchRelay}, required (plan choice 1; GW-3).
func TestGuard_GatewayFrameMembers(t *testing.T) {
	got := Discover(t, "GatewayFrame.frame oneof members", 5, func() ([]string, error) {
		return frameOneofMemberNames("GatewayFrame")
	})
	assertFrameMembers(t, "GatewayFrame", got, map[string]string{
		"device_connected":         "DeviceConnected",
		"device_disconnected":      "DeviceDisconnected",
		"device_report":            "DeviceReport",
		"terminal_recording_chunk": "TerminalRecordingChunk",
		"artifact_fetch_relay":     "ArtifactFetchRelay",
	})
}

// TestGuard_ControlFrameMembers: ControlFrame.frame oneof is exactly
// {push_command: PushCommand, crl_update: CrlUpdate, artifact_chunk_relay:
// ArtifactChunkRelay, artifact_error_relay: ArtifactErrorRelay}, required
// (plan choice 1; GW-3).
func TestGuard_ControlFrameMembers(t *testing.T) {
	got := Discover(t, "ControlFrame.frame oneof members", 4, func() ([]string, error) {
		return frameOneofMemberNames("ControlFrame")
	})
	assertFrameMembers(t, "ControlFrame", got, map[string]string{
		"push_command":         "PushCommand",
		"crl_update":           "CrlUpdate",
		"artifact_chunk_relay": "ArtifactChunkRelay",
		"artifact_error_relay": "ArtifactErrorRelay",
	})
}

// --- Hello / Welcome (plan choice 2) ---

// TestWelcome_NoFields pins the [WIRE-17]/[WIRE-30] negative space: Welcome is
// deliberately EMPTY (a protocol acknowledgment). Everything server-authoritative
// rides signed material; no unsigned Welcome field a relay could rewrite, no
// Welcome-driven update field, no identity field. A field appearing on Welcome
// MUST fail this test (plan choice 2).
func TestWelcome_NoFields(t *testing.T) {
	md, err := findRegistry(packageFiles(ContractPackage), "Welcome")
	if err != nil {
		t.Fatalf("Welcome message: %v", err)
	}
	if n := md.Fields().Len(); n != 0 {
		t.Errorf("Welcome has %d field(s) %v, want ZERO — any server-authoritative value rides signed material ([WIRE-17]); Welcome-driven update or identity fields are banned ([WIRE-30]/[WIRE-18]); a new Welcome field needs a spec change (plan choice 2)", n, msgFieldNames(md))
	}
}

// TestHello_Capabilities pins Hello to exactly {capabilities} — repeated
// string, per-item pattern ^[a-z0-9-]+$ and max_len 64 (AG-12a boot-probe set,
// plan choice 2). The token grammar stays open until SPEC-004 pins the probe
// vocabulary.
func TestHello_Capabilities(t *testing.T) {
	md, err := findRegistry(packageFiles(ContractPackage), "Hello")
	if err != nil {
		t.Fatalf("Hello message: %v", err)
	}
	assertExact(t, "Hello fields", msgFieldNames(md), []string{"capabilities"})
	f := md.Fields().ByName("capabilities")
	if f == nil {
		t.Fatal("Hello has no capabilities field")
	}
	if f.Number() != 1 {
		t.Errorf("Hello.capabilities field number = %d, want 1 (wire contract)", f.Number())
	}
	if !f.IsList() || f.Kind() != protoreflect.StringKind {
		t.Fatalf("Hello.capabilities must be `repeated string` (got list=%v kind=%v)", f.IsList(), f.Kind())
	}
	items := fieldRules(f).GetRepeated().GetItems().GetString()
	if got := items.GetPattern(); got != "^[a-z0-9-]+$" {
		t.Errorf("Hello.capabilities item pattern = %q, want %q (plan choice 2)", got, "^[a-z0-9-]+$")
	}
	if got := items.GetMaxLen(); got != 64 {
		t.Errorf("Hello.capabilities item max_len = %d, want 64 (plan choice 2)", got)
	}
}

// --- addressing wrappers, no dual fields (plan choice 3) ---

// TestDeviceReport_Shape: DeviceReport wraps a DeviceSigned as {report}
// (required), field 1, and carries NO device_id — the envelope's own device_id
// is the sole addressing claim ([WIRE-9] anti-dual-field, plan choice 3).
func TestDeviceReport_Shape(t *testing.T) {
	md := requireMessage(t, "DeviceReport")
	assertExact(t, "DeviceReport fields", msgFieldNames(md), []string{"report"})
	assertMessageField(t, md, "report", 1, "DeviceSigned", true)
	assertNoField(t, md, "device_id") // anti-dual-field pin
}

// TestPushCommand_Shape: PushCommand wraps a SignedCommand as {command}
// (required), field 1, and carries NO device_id — target_device_id inside the
// envelope is the addressing claim ([WIRE-9], plan choice 3).
func TestPushCommand_Shape(t *testing.T) {
	md := requireMessage(t, "PushCommand")
	assertExact(t, "PushCommand fields", msgFieldNames(md), []string{"command"})
	assertMessageField(t, md, "command", 1, "SignedCommand", true)
	assertNoField(t, md, "device_id") // anti-dual-field pin
}

// TestArtifactFetchRelay_Shape: artifact frames carry no in-message device
// field ([WIRE-28]), so the internal stream wraps them with the addressing
// ULID: {device_id: string ULID = 1, request: ArtifactFetchRequest required
// = 2} (composition, not near-copy — plan choice 3).
func TestArtifactFetchRelay_Shape(t *testing.T) {
	md := requireMessage(t, "ArtifactFetchRelay")
	assertExact(t, "ArtifactFetchRelay fields", msgFieldNames(md), []string{"device_id", "request"})
	assertULIDField(t, md, "device_id", 1)
	assertMessageField(t, md, "request", 2, "ArtifactFetchRequest", true)
}

// TestArtifactChunkRelay_Shape: {device_id: string ULID = 1, chunk:
// ArtifactChunk required = 2} (plan choice 3).
func TestArtifactChunkRelay_Shape(t *testing.T) {
	md := requireMessage(t, "ArtifactChunkRelay")
	assertExact(t, "ArtifactChunkRelay fields", msgFieldNames(md), []string{"chunk", "device_id"})
	assertULIDField(t, md, "device_id", 1)
	assertMessageField(t, md, "chunk", 2, "ArtifactChunk", true)
}

// TestArtifactErrorRelay_Shape: {device_id: string ULID = 1, error:
// ArtifactFetchError required = 2} (plan choice 3).
func TestArtifactErrorRelay_Shape(t *testing.T) {
	md := requireMessage(t, "ArtifactErrorRelay")
	assertExact(t, "ArtifactErrorRelay fields", msgFieldNames(md), []string{"device_id", "error"})
	assertULIDField(t, md, "device_id", 1)
	assertMessageField(t, md, "error", 2, "ArtifactFetchError", true)
}

// TestDeviceConnected_Shape: exactly {device_id: string ULID = 1} — stream
// presence is registration; on reconnect the gateway re-reports its set as
// DeviceConnected frames (plan choices 1, 3).
func TestDeviceConnected_Shape(t *testing.T) {
	md := requireMessage(t, "DeviceConnected")
	assertExact(t, "DeviceConnected fields", msgFieldNames(md), []string{"device_id"})
	assertULIDField(t, md, "device_id", 1)
}

// TestDeviceDisconnected_Shape: exactly {device_id: string ULID = 1}
// (plan choices 1, 3).
func TestDeviceDisconnected_Shape(t *testing.T) {
	md := requireMessage(t, "DeviceDisconnected")
	assertExact(t, "DeviceDisconnected fields", msgFieldNames(md), []string{"device_id"})
	assertULIDField(t, md, "device_id", 1)
}

// TestCrlUpdate_Shape: exactly {crl: bytes min_len 1 = 1} — a standard X.509
// DER CRL; PKI-6's issued_at/sequence are the DER thisUpdate/crlNumber inside
// the CA signature, so no proto wrapper duplicates them (plan choice 6,
// [WIRE-14] lesson).
func TestCrlUpdate_Shape(t *testing.T) {
	md := requireMessage(t, "CrlUpdate")
	assertExact(t, "CrlUpdate fields", msgFieldNames(md), []string{"crl"})
	f := requireFieldNum(t, md, "crl", 1)
	if f.Kind() != protoreflect.BytesKind {
		t.Fatalf("CrlUpdate.crl kind = %v, want bytes", f.Kind())
	}
	if got := fieldRules(f).GetBytes().GetMinLen(); got != 1 {
		t.Errorf("CrlUpdate.crl bytes.min_len = %d, want 1 — an empty CRL is a degenerate update ([WIRE-2])", got)
	}
}

// TestTerminalRecordingChunk_Shape: {session_id: string ULID = 1, direction:
// TerminalDirection (defined_only, not_in 0) = 2, data: bytes min_len 1 = 3}
// (GW-7; operator decision 44 — input AND output; ordering is stream order, no
// sequence field until reassembly is demanded — plan choice 5).
func TestTerminalRecordingChunk_Shape(t *testing.T) {
	md := requireMessage(t, "TerminalRecordingChunk")
	assertExact(t, "TerminalRecordingChunk fields", msgFieldNames(md), []string{"data", "direction", "session_id"})
	assertULIDField(t, md, "session_id", 1)
	assertBoundedEnumField(t, md, "direction", 2, "TerminalDirection")
	d := requireFieldNum(t, md, "data", 3)
	if d.Kind() != protoreflect.BytesKind {
		t.Fatalf("TerminalRecordingChunk.data kind = %v, want bytes", d.Kind())
	}
	if got := fieldRules(d).GetBytes().GetMinLen(); got != 1 {
		t.Errorf("TerminalRecordingChunk.data bytes.min_len = %d, want 1 ([WIRE-2])", got)
	}
}

// TestTerminalDirection_Values: enum {UNSPECIFIED=0, INPUT=1, OUTPUT=2} — the
// closed direction set (plan choice 5, operator decision 44). UNSPECIFIED=0 is
// [WIRE-4] hygiene; exactly the two live directions exist.
func TestTerminalDirection_Values(t *testing.T) {
	assertEnumValues(t, "TerminalDirection", map[protoreflect.EnumNumber]string{
		0: "_UNSPECIFIED",
		1: "_INPUT",
		2: "_OUTPUT",
	})
}

// TestValidateTerminalTokenRequest_Shape: {token: string min_len 1, max_len
// 512 = 1} — an opaque token only; the caller is the gateway certificate
// ([WIRE-18]: no self-asserted identity — plan choice 7).
func TestValidateTerminalTokenRequest_Shape(t *testing.T) {
	md := requireMessage(t, "ValidateTerminalTokenRequest")
	assertExact(t, "ValidateTerminalTokenRequest fields", msgFieldNames(md), []string{"token"})
	f := requireFieldNum(t, md, "token", 1)
	if f.Kind() != protoreflect.StringKind {
		t.Fatalf("ValidateTerminalTokenRequest.token kind = %v, want string", f.Kind())
	}
	sr := fieldRules(f).GetString()
	if sr.GetMinLen() != 1 || sr.GetMaxLen() != 512 {
		t.Errorf("ValidateTerminalTokenRequest.token rules = min_len %d, max_len %d; want 1 and 512 (plan choice 7)", sr.GetMinLen(), sr.GetMaxLen())
	}
	// [WIRE-18]: no self-asserted identity field rides the request.
	assertNoField(t, md, "device_id")
	assertNoField(t, md, "gateway_id")
}

// TestValidateTerminalTokenResponse_Shape: {device_id ULID = 1, session_id
// ULID = 2, user_id ULID = 3} — the binding the gateway needs to bridge
// (GW-7); control enforces the [WIRE-19] connection-set check before answering
// (plan choice 7).
func TestValidateTerminalTokenResponse_Shape(t *testing.T) {
	md := requireMessage(t, "ValidateTerminalTokenResponse")
	assertExact(t, "ValidateTerminalTokenResponse fields", msgFieldNames(md), []string{"device_id", "session_id", "user_id"})
	assertULIDField(t, md, "device_id", 1)
	assertULIDField(t, md, "session_id", 2)
	assertULIDField(t, md, "user_id", 3)
}

// ---------------------------------------------------------------------------
// shared assertion helpers
// ---------------------------------------------------------------------------

func methodNames(svc protoreflect.ServiceDescriptor) []string {
	var out []string
	ms := svc.Methods()
	for i := 0; i < ms.Len(); i++ {
		out = append(out, string(ms.Get(i).Name()))
	}
	sort.Strings(out)
	return out
}

// assertExact compares got against want as sets, both directions.
func assertExact(t *testing.T, what string, got, want []string) {
	t.Helper()
	gs := append([]string(nil), got...)
	ws := append([]string(nil), want...)
	sort.Strings(gs)
	sort.Strings(ws)
	if len(gs) != len(ws) {
		t.Fatalf("%s = %v, want exactly %v", what, gs, ws)
	}
	for i := range ws {
		if gs[i] != ws[i] {
			t.Fatalf("%s = %v, want exactly %v", what, gs, ws)
		}
	}
}

// assertStreamRPC pins a method's streaming flags and frame types.
func assertStreamRPC(t *testing.T, svcName, method string, wantClientStream, wantServerStream bool, wantIn, wantOut string) {
	t.Helper()
	svc, err := findService(packageFiles(ContractPackage), protoreflect.Name(svcName))
	if err != nil {
		t.Fatalf("%s: %v", svcName, err)
	}
	m := svc.Methods().ByName(protoreflect.Name(method))
	if m == nil {
		t.Fatalf("%s has no %s RPC", svcName, method)
	}
	if m.IsStreamingClient() != wantClientStream || m.IsStreamingServer() != wantServerStream {
		t.Errorf("%s.%s streaming = (client %v, server %v), want (client %v, server %v) (plan choice 1)",
			svcName, method, m.IsStreamingClient(), m.IsStreamingServer(), wantClientStream, wantServerStream)
	}
	if in := string(m.Input().Name()); in != wantIn {
		t.Errorf("%s.%s input = %s, want %s (plan choice 1)", svcName, method, in, wantIn)
	}
	if out := string(m.Output().Name()); out != wantOut {
		t.Errorf("%s.%s output = %s, want %s (plan choice 1)", svcName, method, out, wantOut)
	}
}

// frameOneofMemberNames returns the member field names of msgName's non-synthetic
// `frame` oneof, or the missing-subject error (so the Discover floor fails RED
// before the frame protos land). Split out so each TestGuard_XFrameMembers can
// call Discover DIRECTLY in its own body (G-000-3 conformance).
func frameOneofMemberNames(msgName string) ([]string, error) {
	md, err := findRegistry(packageFiles(ContractPackage), protoreflect.Name(msgName))
	if err != nil {
		return nil, err
	}
	oo := oneofByName(md, "frame")
	if oo == nil {
		return nil, fmt.Errorf("%s has no non-synthetic `frame` oneof — the ONE bidi stream multiplexes N payload classes via the oneof discriminant (plan choice 1)", msgName)
	}
	var names []string
	fs := oo.Fields()
	for i := 0; i < fs.Len(); i++ {
		names = append(names, string(fs.Get(i).Name()))
	}
	return names, nil
}

// assertFrameMembers pins a frame message's `frame` oneof to exactly wantMembers
// (name→member type short name), both directions, and requires the oneof. got is
// the already-discovered member-name slice from the test's own Discover call.
func assertFrameMembers(t *testing.T, msgName string, got []string, wantMembers map[string]string) {
	t.Helper()
	var wantNames []string
	for n := range wantMembers {
		wantNames = append(wantNames, n)
	}
	assertExact(t, msgName+".frame members", got, wantNames)

	md, err := findRegistry(packageFiles(ContractPackage), protoreflect.Name(msgName))
	if err != nil {
		t.Fatalf("%s: %v", msgName, err)
	}
	oo := oneofByName(md, "frame")
	if oo == nil {
		t.Fatalf("%s has no `frame` oneof", msgName)
	}
	types := oneofMemberTypes(oo)
	for name, wantType := range wantMembers {
		if got := types[name]; got != wantType {
			t.Errorf("%s.frame.%s type = %s, want %s (plan choice 1)", msgName, name, got, wantType)
		}
	}
	if !oneofRequired(oo) {
		t.Errorf("%s.frame oneof must carry (buf.validate.oneof).required = true — an unset frame is an untyped payload (plan choice 1)", msgName)
	}
}

func requireMessage(t *testing.T, name string) protoreflect.MessageDescriptor {
	t.Helper()
	md, err := findRegistry(packageFiles(ContractPackage), protoreflect.Name(name))
	if err != nil {
		t.Fatalf("%s message: %v", name, err)
	}
	return md
}

func requireFieldNum(t *testing.T, md protoreflect.MessageDescriptor, name string, num protoreflect.FieldNumber) protoreflect.FieldDescriptor {
	t.Helper()
	f := md.Fields().ByName(protoreflect.Name(name))
	if f == nil {
		t.Fatalf("%s has no %s field", md.Name(), name)
	}
	if f.Number() != num {
		t.Errorf("%s.%s field number = %d, want %d (wire contract)", md.Name(), name, f.Number(), num)
	}
	return f
}

func assertNoField(t *testing.T, md protoreflect.MessageDescriptor, name string) {
	t.Helper()
	if md.Fields().ByName(protoreflect.Name(name)) != nil {
		t.Errorf("%s carries a %s field — the envelope's own addressing claim is authoritative; a second ID field is the [WIRE-9]/[WIRE-18] anti-dual-field ban", md.Name(), name)
	}
}

func assertULIDField(t *testing.T, md protoreflect.MessageDescriptor, name string, num protoreflect.FieldNumber) {
	t.Helper()
	f := requireFieldNum(t, md, name, num)
	if f.Kind() != protoreflect.StringKind {
		t.Fatalf("%s.%s kind = %v, want string (ULID)", md.Name(), name, f.Kind())
	}
	if !hasULIDRule(f) {
		t.Errorf("%s.%s does not carry the predefined ULID rule ([WIRE-5])", md.Name(), name)
	}
}

func assertMessageField(t *testing.T, md protoreflect.MessageDescriptor, name string, num protoreflect.FieldNumber, wantType string, wantRequired bool) {
	t.Helper()
	f := requireFieldNum(t, md, name, num)
	m := f.Message()
	if m == nil {
		t.Fatalf("%s.%s is not a message field (kind %v), want message %s", md.Name(), name, f.Kind(), wantType)
	}
	if string(m.Name()) != wantType {
		t.Errorf("%s.%s type = %s, want %s (plan choice 3 — composition by type reference)", md.Name(), name, m.Name(), wantType)
	}
	if wantRequired && !fieldRules(f).GetRequired() {
		t.Errorf("%s.%s must carry (buf.validate.field).required = true — an absent message field is not an empty one ([WIRE-2])", md.Name(), name)
	}
}

// assertBoundedEnumField pins an enum field's type and the descriptor-derived
// {defined_only, not_in: [0]} bound pair ([WIRE-2], [WIRE-4], AC-2).
func assertBoundedEnumField(t *testing.T, md protoreflect.MessageDescriptor, name string, num protoreflect.FieldNumber, wantEnum string) {
	t.Helper()
	f := requireFieldNum(t, md, name, num)
	if f.Kind() != protoreflect.EnumKind {
		t.Fatalf("%s.%s kind = %v, want enum %s", md.Name(), name, f.Kind(), wantEnum)
	}
	if got := string(f.Enum().Name()); got != wantEnum {
		t.Errorf("%s.%s enum type = %s, want %s", md.Name(), name, got, wantEnum)
	}
	er := fieldRules(f).GetEnum()
	zeroBanned := false
	for _, v := range er.GetNotIn() {
		if v == 0 {
			zeroBanned = true
		}
	}
	if !er.GetDefinedOnly() || !zeroBanned {
		t.Errorf("%s.%s must carry enum rules {defined_only: true, not_in: [0]} — bounds come from the descriptor and UNSPECIFIED is always invalid at boundaries ([WIRE-2], [WIRE-4])", md.Name(), name)
	}
}

// assertEnumValues pins an enum to exactly the wanted number→name-suffix set,
// both directions — the closed value set with [WIRE-4] hygiene.
func assertEnumValues(t *testing.T, enumName string, want map[protoreflect.EnumNumber]string) {
	t.Helper()
	ed, err := findEnum(packageFiles(ContractPackage), protoreflect.Name(enumName))
	if err != nil {
		t.Fatalf("%s enum: %v", enumName, err)
	}
	vals := ed.Values()
	if vals.Len() != len(want) {
		var got []string
		for i := 0; i < vals.Len(); i++ {
			got = append(got, fmt.Sprintf("%s=%d", vals.Get(i).Name(), vals.Get(i).Number()))
		}
		t.Fatalf("%s has %d values %v, want exactly %d — the set is closed; a value with no implementation is dead contract surface ([WIRE-4])", enumName, vals.Len(), got, len(want))
	}
	for num, suffix := range want {
		v := vals.ByNumber(num)
		if v == nil {
			t.Errorf("%s has no value at number %d (want name ending %q)", enumName, num, suffix)
			continue
		}
		if !strings.HasSuffix(string(v.Name()), suffix) {
			t.Errorf("%s value at %d = %s, want a name ending %q", enumName, num, v.Name(), suffix)
		}
	}
}
