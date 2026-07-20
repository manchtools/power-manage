package archtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"

	// Register the fixture descriptors (test-only import — production
	// archtest never links the planted violations).
	_ "github.com/manchtools/power-manage/contract/archtest/internal/fixturepb/powermanage/fixture/v1"
)

const fixturePackage = "powermanage.fixture.v1"

// TestGuard_ServiceSurface pins the §3.2 service set (SPEC-003): exactly the
// FOUR proto-defined services exist. The amended §3.2 (operator commit
// e9b8c29, resolving issue #18) demotes ScimService (SCIM v2 is
// application/scim+json by RFC — proto would violate [WIRE-10]) and
// ExportService (standard OTLP) to NON-proto boundaries: no proto declaration
// is minted for either ([WIRE-4] — an RPC surface with no proto consumer is
// dead contract). A missing service is unimplemented surface; an extra one —
// including a re-added ScimService/ExportService proto — is surface the spec
// never approved.
func TestGuard_ServiceSurface(t *testing.T) {
	got := Discover(t, "contract services", 4, func() ([]string, error) {
		return services(packageFiles(ContractPackage)), nil
	})
	want := []string{
		"powermanage.v1.AgentService",
		"powermanage.v1.ControlService",
		"powermanage.v1.InternalService",
		"powermanage.v1.PkiService",
	}
	sort.Strings(want)
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("service %s missing — the §3.2 surface is normative (SPEC-003)", w)
		}
	}
	for _, g := range got {
		if !contains(want, g) {
			t.Errorf("service %s is not in the amended §3.2 four-proto-service set — ScimService/ExportService are non-proto boundaries ([WIRE-4], operator commit e9b8c29); new services need a spec change first (SPEC-003)", g)
		}
	}
}

// TestGuard_ValidateTagCoverage is G-1 (SPEC-003 AC-1): every field of
// every message reachable from the six services carries buf.validate
// rules. The population anchor is the file set — a walk that finds fewer
// files than the contract has is broken, not clean.
func TestGuard_ValidateTagCoverage(t *testing.T) {
	files := Discover(t, "contract proto files", 11, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	for _, v := range untaggedFields(files) {
		t.Errorf("%s — add the constraint or the field ships unvalidated (G-1, SPEC-003)", v)
	}
}

// TestGuard_EnumHygiene is the G-2 descriptor half (SPEC-003 AC-2): every
// contract enum starts at *_UNSPECIFIED = 0. The erroring-default switch
// half wires up with the first contract-enum switch (M3).
func TestGuard_EnumHygiene(t *testing.T) {
	files := Discover(t, "contract proto files", 11, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	for _, v := range enumHygieneViolations(files) {
		t.Errorf("%s — fix the enum, never the guard (G-2, SPEC-003)", v)
	}
}

// TestGuard_ValidateTagCoverage_Liveness: the fixture plants an untagged
// reachable field, an untagged field one closure hop away, tagged fields,
// and an unreachable message — exactly the two planted violations flag.
func TestGuard_ValidateTagCoverage_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got := untaggedFields(files)
	want := []string{
		"powermanage.fixture.v1.FixtureRequest.untagged_name",
		"powermanage.fixture.v1.NestedParams.untagged_inner",
	}
	if len(got) != len(want) {
		t.Fatalf("fixture violations = %v, want exactly %v — the guard can no longer go red for the planted shapes", got, want)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w+":") {
			t.Errorf("violation %d = %q, want it to flag %s", i, got[i], w)
		}
	}
	for _, g := range got {
		for _, never := range []string{"tagged_id", "tagged_out", "never_flagged", "FixtureRequest.nested"} {
			if strings.Contains(g, never) {
				t.Errorf("guard flagged %q — that shape is planted as conforming", g)
			}
		}
	}
}

// TestGuard_EnumHygiene_Liveness: the bad fixture enum flags, the good one
// stays clean.
func TestGuard_EnumHygiene_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got := enumHygieneViolations(files)
	if len(got) != 1 || !strings.HasPrefix(got[0], "powermanage.fixture.v1.FixtureBadEnum:") {
		t.Fatalf("fixture enum violations = %v, want exactly one flagging FixtureBadEnum", got)
	}
}

// TestDescwalk_FixtureShapes pins the walk mechanics against known fixture
// shapes: service enumeration, reachability closure through a field hop,
// unreachable exclusion, and nested+top-level enum listing.
func TestDescwalk_FixtureShapes(t *testing.T) {
	files := packageFiles(fixturePackage)
	if got := services(files); len(got) != 1 || got[0] != "powermanage.fixture.v1.FixtureService" {
		t.Fatalf("services = %v, want exactly FixtureService", got)
	}
	reach := reachableMessages(files)
	for _, w := range []string{"FixtureRequest", "FixtureResponse", "NestedParams"} {
		if _, ok := reach[protoreflect.FullName(fixturePackage+"."+w)]; !ok {
			t.Errorf("reachable set misses %s", w)
		}
	}
	if _, ok := reach[protoreflect.FullName(fixturePackage+".UnreachableLoose")]; ok {
		t.Errorf("UnreachableLoose is not service-reachable but the closure included it")
	}
	if _, ok := reach[protoreflect.FullName("google.protobuf.Timestamp")]; ok {
		t.Errorf("google.protobuf.Timestamp is referenced but defined outside the audited files — the closure must stop at foreign messages, not audit their internals")
	}
	es := enums(files)
	if len(es) != 2 {
		t.Fatalf("enums = %d, want the two fixture enums", len(es))
	}
}

// TestGuard_ActionRegistry pins the ActionParams oneof to exactly the 21
// closed catalog types ([WIRE-12]; CAT-1, SPEC-014), both directions —
// a missing member is unimplementable surface, an extra one is a type the
// catalog never approved.
func TestGuard_ActionRegistry(t *testing.T) {
	got := Discover(t, "ActionParams oneof members", 21, func() ([]string, error) {
		registry, err := findRegistry(packageFiles(ContractPackage), "ActionParams")
		if err != nil {
			return nil, err
		}
		var names []string
		oneofs := registry.Oneofs()
		for i := 0; i < oneofs.Len(); i++ {
			fields := oneofs.Get(i).Fields()
			for j := 0; j < fields.Len(); j++ {
				names = append(names, string(fields.Get(j).Name()))
			}
		}
		sort.Strings(names)
		return names, nil
	})
	want := []string{
		"admin_policy", "agent_update", "app_image", "directory", "encryption",
		"file", "flatpak", "group", "lps", "package", "package_file", "reboot",
		"repository", "service", "shell", "ssh", "sshd", "sync", "update",
		"user", "wifi",
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("registry member %s missing — the catalog is closed at the 21 types (CAT-1, SPEC-014)", w)
		}
	}
	for _, g := range got {
		if !contains(want, g) {
			t.Errorf("registry member %s is not a catalog type — adding one is a contract+executor+spec change (CAT-1, SPEC-014)", g)
		}
	}
	// An empty ActionParams is an action with no executable type: the oneof
	// itself must demand a selected member — `params required` on Action
	// only guarantees the wrapper exists.
	registry, err := findRegistry(packageFiles(ContractPackage), "ActionParams")
	if err != nil {
		t.Fatalf("registry lookup: %v", err)
	}
	oo := registry.Oneofs().Get(0)
	rules, _ := proto.GetExtension(oo.Options(), validate.E_Oneof).(*validate.OneofRules)
	if !rules.GetRequired() {
		t.Errorf("ActionParams oneof %s must carry (buf.validate.oneof).required = true — an unset member is untyped surface [WIRE-12]", oo.Name())
	}
}

// TestGuard_ActionParamsAuthority is G-3 (SPEC-003): exactly one
// ActionParams exists and no field outside it references a member type —
// the predecessor duplicated this oneof across five messages and the
// copies diverged.
func TestGuard_ActionParamsAuthority(t *testing.T) {
	files := Discover(t, "contract proto files", 11, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	violations, err := registryViolations(files, "ActionParams")
	if err != nil {
		t.Fatalf("registry walk failed: %v (G-3, SPEC-003)", err)
	}
	for _, v := range violations {
		t.Errorf("%s (G-3, SPEC-003)", v)
	}
}

// TestGuard_ActionParamsAuthority_Liveness: the fixture registry analog
// plants a direct member embed and a second oneof — both flag; embedding
// the registry itself stays clean.
func TestGuard_ActionParamsAuthority_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got, err := registryViolations(files, "FixtureActionParams")
	if err != nil {
		t.Fatalf("fixture registry walk failed: %v", err)
	}
	want := []string{
		"powermanage.fixture.v1.FixtureDirectEmbed.direct",
		"powermanage.fixture.v1.FixtureSecondOneof.a2",
		"powermanage.fixture.v1.FixtureSecondOneof.b2",
	}
	if len(got) != len(want) {
		t.Fatalf("fixture violations = %v, want exactly the three planted shapes %v", got, want)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w+":") {
			t.Errorf("violation %d = %q, want it to flag %s", i, got[i], w)
		}
	}
	for _, g := range got {
		if strings.Contains(g, "FixtureConformingEmbed") {
			t.Errorf("guard flagged %q — embedding the registry is the conforming form", g)
		}
	}
}

// TestGuard_ExplicitPresence is G-4 (SPEC-003, [WIRE-6]): no plain bool in
// the registry subtree without a recorded two-value rationale.
func TestGuard_ExplicitPresence(t *testing.T) {
	files := Discover(t, "contract proto files", 11, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	violations, err := plainBoolViolations(files, "ActionParams")
	if err != nil {
		t.Fatalf("registry subtree walk failed: %v (G-4, SPEC-003)", err)
	}
	for _, v := range violations {
		t.Errorf("%s (G-4, SPEC-003)", v)
	}
}

// TestGuard_ExplicitPresence_Liveness: the planted plain bool flags; the
// optional sibling stays clean.
func TestGuard_ExplicitPresence_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got, err := plainBoolViolations(files, "FixtureActionParams")
	if err != nil {
		t.Fatalf("fixture subtree walk failed: %v", err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "powermanage.fixture.v1.FixtureBoolParams.plain_flag:") {
		t.Fatalf("fixture violations = %v, want exactly the planted plain_flag", got)
	}
	for _, g := range got {
		if strings.Contains(g, "opt_flag") {
			t.Errorf("guard flagged %q — optional bool is the conforming form", g)
		}
		if strings.Contains(g, "oneof_flag") {
			t.Errorf("guard flagged %q — oneof membership is explicit presence too", g)
		}
		if strings.Contains(g, "google.protobuf.BoolValue") {
			t.Errorf("guard flagged %q — foreign well-known types are referenced surface; the subtree closure must stop at them", g)
		}
	}
}

// TestGuard_EnumBounds enforces the descriptor-derived bound pair on every
// enum field of every service-reachable message ([WIRE-2], AC-2). No longer
// vacuous as of M5: ArtifactFetchError.code (ArtifactFetchErrorCode) and
// TerminalRecordingChunk.direction (TerminalDirection) are the first
// service-reachable enum fields (docs/plans/spec-003-m5.md choice 13, which
// retires the M2 vacuity ceiling of docs/plans/spec-003-m2.md choice 4); the
// liveness row still proves the walk can go red.
func TestGuard_EnumBounds(t *testing.T) {
	files := Discover(t, "contract proto files", 11, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	for _, v := range enumBoundViolations(files) {
		t.Errorf("%s (G-1 enum half, SPEC-003)", v)
	}
}

// TestGuard_EnumBounds_Liveness: the carrier's untagged enum field flags;
// its fully-tagged sibling stays clean.
func TestGuard_EnumBounds_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got := enumBoundViolations(files)
	if len(got) != 1 || !strings.HasPrefix(got[0], "powermanage.fixture.v1.FixtureEnumCarrier.untagged_enum:") {
		t.Fatalf("fixture violations = %v, want exactly the planted untagged_enum", got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "powermanage.fixture.v1.FixtureEnumCarrier.tagged_enum:") {
			t.Errorf("guard flagged %q — the bound pair is the conforming form", g)
		}
	}
}

// TestAction_Shape pins the one action shape ([WIRE-13], plan choice 3):
// exactly {id, name, params} with the recorded tags — enrichment composes
// around this shape, never onto it.
func TestAction_Shape(t *testing.T) {
	action, err := findRegistry(packageFiles(ContractPackage), "Action")
	if err != nil {
		t.Fatalf("Action message: %v", err)
	}
	fields := action.Fields()
	var names []string
	for i := 0; i < fields.Len(); i++ {
		names = append(names, string(fields.Get(i).Name()))
	}
	sort.Strings(names)
	want := []string{"id", "name", "params"}
	if len(names) != len(want) {
		t.Fatalf("Action fields = %v, want exactly %v — enrichment is composition, not new fields [WIRE-13]", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Fatalf("Action fields = %v, want exactly %v", names, want)
		}
	}
	// Field numbers are wire contract: evolution re-tags in place (AC-13),
	// so an accidental renumbering must be loud.
	for name, tag := range map[string]protoreflect.FieldNumber{"id": 1, "name": 2, "params": 3} {
		if got := fields.ByName(protoreflect.Name(name)).Number(); got != tag {
			t.Errorf("Action.%s field number = %d, want %d", name, got, tag)
		}
	}
	rulesOf := func(name protoreflect.Name) *validate.FieldRules {
		f := fields.ByName(name)
		rules, _ := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
		return rules
	}
	if ulid, _ := proto.GetExtension(rulesOf("id").GetString(), powermanagev1.E_Ulid).(bool); !ulid {
		t.Errorf("Action.id does not carry the predefined ULID rule [WIRE-5]")
	}
	nameRules := rulesOf("name").GetString()
	if nameRules.GetMinLen() != 1 || nameRules.GetMaxLen() != 200 {
		t.Errorf("Action.name rules = min_len %d, max_len %d; want 1 and 200 (plan choice 3)", nameRules.GetMinLen(), nameRules.GetMaxLen())
	}
	if !rulesOf("params").GetRequired() {
		t.Errorf("Action.params must be required — an action without params is untyped surface")
	}
}

// TestGuard_SignatureDomains is G-5 (SPEC-003 AC-5, AC-7, plan choice 10 +
// operator commit e9b8c29 closing [WIRE-20a]): the signature-domain constants
// are self-discovered from contract/sign source (AST scan, never a hand list)
// and pinned, exact-set both directions, to the closed catalogs of §3.4
// command types (the [WIRE-14] formula "power-manage:cmd:"+type+":v1") AND the
// amended §3.6 result types (the [WIRE-20a] formula
// "power-manage:result:"+type+":v1"). The two families are disjoint, every
// constant binds a unique domain, and EACH family is proven pairwise isolated —
// a signature framed under one domain never verifies under another, across the
// command framing (SignCommand/VerifyCommand) AND the result framing
// (SignResult/VerifyResult).
//
// INV-6 cross-repo-parity ceiling: this guard proves round-trip + isolation for
// every domain, but INV-6 additionally requires >=1 sign site AND >=1
// fail-closed verify site per domain OUTSIDE contract. At M3/M5 both sites are
// contract/sign itself; the cross-repo half arms with the SPEC-013 agent
// chokepoint (commands) and the SPEC-005/007 control result path (results) —
// extend this guard there, never weaken it to backfill.
//
// The pairwise matrices flip command_type / result_type, themselves covered
// fields, so alone they prove type isolation; that the domain string is IN the
// preimage is pinned separately by the golden-framing tests. AC-5/AC-7 hold
// through the composition (domains are 1:1 with types).
//
// Guards: INV-5.
func TestGuard_SignatureDomains(t *testing.T) {
	consts := Discover(t, "contract/sign *SignatureDomain constants", 14, ScanSignatureDomains)

	// Exact set, both directions, against the two formulas over the closed
	// §3.4 command catalog ([WIRE-14]) and §3.6 result catalog ([WIRE-20a]).
	commandCatalog := []string{
		"action", "osquery", "logquery", "inventory",
		"luks-revoke", "lps-pubkey", "terminal-grant", "sync-manifest",
	}
	resultCatalog := []string{
		"execution", "compliance", "inventory", "alert", "osquery", "logquery",
	}
	const cmdPrefix = "power-manage:cmd:"
	const resultPrefix = "power-manage:result:"
	wantCount := len(commandCatalog) + len(resultCatalog)

	wantValue := map[string]bool{}
	for _, ct := range commandCatalog {
		wantValue[cmdPrefix+ct+":v1"] = true
	}
	for _, rt := range resultCatalog {
		wantValue[resultPrefix+rt+":v1"] = true
	}
	// Disjoint families: the [WIRE-14] and [WIRE-20a] formulas must never
	// collapse to the same domain string, or a command signature and a result
	// signature could share a domain. Distinct-value count proves it.
	if len(wantValue) != wantCount {
		t.Fatalf("the command and result domain formulas collide — the two families must be disjoint ([WIRE-14] vs [WIRE-20a]); got %d distinct expected domains, want %d", len(wantValue), wantCount)
	}

	gotValue := map[string]bool{}
	valueOwner := map[string]string{}
	for _, c := range consts {
		gotValue[c.Value] = true
		if !wantValue[c.Value] {
			t.Errorf("constant %s = %q is not a domain for any closed §3.4 command type ([WIRE-14]) or §3.6 result type ([WIRE-20a]) — a domain must equal \"power-manage:cmd:\"+type+\":v1\" for one of the 8 command types or \"power-manage:result:\"+type+\":v1\" for one of the 6 result types (G-5, AC-5/AC-7, SPEC-003)", c.Name, c.Value)
		}
		// Duplicate-value detection spans BOTH families: two names for one
		// domain is a second registry that can drift (review finding).
		if prev, dup := valueOwner[c.Value]; dup {
			t.Errorf("constants %s and %s both bind domain %q — each domain has exactly one constant (G-5 exact-set)", prev, c.Name, c.Value)
		}
		valueOwner[c.Value] = c.Name
	}
	for want := range wantValue {
		if !gotValue[want] {
			t.Errorf("no *SignatureDomain constant carries value %q — every closed command AND result type needs its domain constant so no unregistered preimage is ever framed (G-5, AC-5/AC-7, SPEC-003)", want)
		}
	}
	// Exact-set means exact COUNT: 8 §3.4 command domains + 6 §3.6 result
	// domains = 14.
	if len(consts) != wantCount {
		t.Errorf("discovered %d *SignatureDomain constants, want exactly %d — 8 command domains + 6 result domains; remove duplicate or extra domain constants (G-5 exact-set)", len(consts), wantCount)
	}

	// Partition the DISCOVERED constants into the two families by formula
	// (still self-discovering — not the catalog lists above) to drive the two
	// crypto matrices. A value matching neither prefix is a malformed domain.
	var commandTypes, resultTypes []string
	for _, c := range consts {
		switch {
		case strings.HasPrefix(c.Value, cmdPrefix):
			commandTypes = append(commandTypes, strings.TrimSuffix(strings.TrimPrefix(c.Value, cmdPrefix), ":v1"))
		case strings.HasPrefix(c.Value, resultPrefix):
			resultTypes = append(resultTypes, strings.TrimSuffix(strings.TrimPrefix(c.Value, resultPrefix), ":v1"))
		default:
			t.Errorf("constant %s = %q matches neither the command nor the result domain formula (G-5)", c.Name, c.Value)
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA P-256 key: %v", err)
	}
	pub := &priv.PublicKey
	const target = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	// --- command family: round-trip + pairwise isolation (SignCommand) ---
	// A 30 s durable-class window satisfies every per-type bound (<= 60 s
	// terminal-grant, and no instant cap when Instant=false), so a round-trip
	// failure can only be about the domain, never freshness.
	newCmd := func(ct string) *powermanagev1.SignedCommand {
		return &powermanagev1.SignedCommand{
			Payload:        []byte("g5-domain-payload"),
			CommandType:    ct,
			TargetDeviceId: target,
			IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
			ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000030},
		}
	}
	cmdOpts := sign.VerifyOptions{DeviceID: target, Now: time.Unix(1700000005, 0).UTC(), Instant: false}
	for _, ct := range commandTypes {
		cmd := newCmd(ct)
		if err := sign.SignCommand(priv, cmd); err != nil {
			t.Errorf("SignCommand under domain %q: %v (G-5 round-trip)", ct, err)
			continue
		}
		if _, err := sign.VerifyCommand(pub, cmd, cmdOpts); err != nil {
			t.Errorf("VerifyCommand rejected a valid envelope under its own domain %q: %v (G-5 round-trip)", ct, err)
		}
	}
	for _, a := range commandTypes {
		for _, b := range commandTypes {
			if a == b {
				continue
			}
			cmd := newCmd(a)
			if err := sign.SignCommand(priv, cmd); err != nil {
				t.Errorf("SignCommand under domain %q: %v", a, err)
				continue
			}
			cmd.CommandType = b // A's signature must not verify under B's domain
			payload, err := sign.VerifyCommand(pub, cmd, cmdOpts)
			if err == nil {
				t.Errorf("a command signature framed under domain %q verified after re-typing to %q — signature domains must be pairwise isolated (G-5, AC-5, SPEC-003)", a, b)
			}
			if payload != nil {
				t.Errorf("cross-domain command verification %q->%q returned a non-nil payload on failure (G-5)", a, b)
			}
		}
	}

	// --- result family: round-trip + pairwise isolation (SignResult) ---
	// Results carry no expires_at (records, not commands, plan-003-m4 choice 2);
	// the domain string is the only per-type discriminant, so isolation mirrors
	// the command matrix exactly ([WIRE-20a], AC-7).
	newResult := func(rt string) *powermanagev1.DeviceSigned {
		return &powermanagev1.DeviceSigned{
			Payload:    []byte("g5-result-domain-payload"),
			ResultType: rt,
			DeviceId:   target,
			IssuedAt:   &timestamppb.Timestamp{Seconds: 1700000000},
		}
	}
	resultOpts := sign.ResultVerifyOptions{DeviceID: target}
	for _, rt := range resultTypes {
		env := newResult(rt)
		if err := sign.SignResult(priv, env); err != nil {
			t.Errorf("SignResult under domain %q: %v (G-5 result round-trip)", rt, err)
			continue
		}
		if _, err := sign.VerifyResult(pub, env, resultOpts); err != nil {
			t.Errorf("VerifyResult rejected a valid envelope under its own domain %q: %v (G-5 result round-trip)", rt, err)
		}
	}
	for _, a := range resultTypes {
		for _, b := range resultTypes {
			if a == b {
				continue
			}
			env := newResult(a)
			if err := sign.SignResult(priv, env); err != nil {
				t.Errorf("SignResult under domain %q: %v", a, err)
				continue
			}
			env.ResultType = b // A's result signature must not verify under B's domain
			payload, err := sign.VerifyResult(pub, env, resultOpts)
			if err == nil {
				t.Errorf("a result signature framed under domain %q verified after re-typing to %q — result signature domains must be pairwise isolated (G-5, AC-7, [WIRE-20a])", a, b)
			}
			if payload != nil {
				t.Errorf("cross-domain result verification %q->%q returned a non-nil payload on failure (G-5)", a, b)
			}
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// removalVerbs is the AC-9 / [WIRE-26] never-list: removal-by-omission is the
// SOLE cleanup authority, so the sync-manifest surface carries no deletion
// vocabulary. Matched as a case-insensitive substring of the snake_case field
// name — "removed_ids" and "soft_delete_at" both flag.
var removalVerbs = []string{"remove", "delete", "tombstone", "revoke"}

// messageClosure returns the transitive downward closure of root within the
// audited files: root plus every message reachable through its field message
// types (and map values), stopping at messages defined outside files. A
// foreign well-known type (google.protobuf.Timestamp) is referenced surface,
// not manifest surface to audit — the closure must not walk into it.
func messageClosure(files []protoreflect.FileDescriptor, root protoreflect.MessageDescriptor) []protoreflect.MessageDescriptor {
	audited := make(map[string]bool, len(files))
	for _, fd := range files {
		audited[fd.Path()] = true
	}
	seen := map[protoreflect.FullName]protoreflect.MessageDescriptor{}
	var visit func(md protoreflect.MessageDescriptor)
	visit = func(md protoreflect.MessageDescriptor) {
		if !audited[md.ParentFile().Path()] {
			return
		}
		if _, ok := seen[md.FullName()]; ok {
			return
		}
		seen[md.FullName()] = md
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if f.IsMap() {
				if v := f.MapValue(); v.Message() != nil {
					visit(v.Message())
				}
				continue
			}
			if m := f.Message(); m != nil {
				visit(m)
			}
		}
	}
	visit(root)
	var out []protoreflect.MessageDescriptor
	for _, md := range seen {
		out = append(out, md)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}

// removalVerbViolations returns a violation per field across closure whose
// snake_case name carries a removal verb.
func removalVerbViolations(closure []protoreflect.MessageDescriptor) []string {
	var out []string
	for _, md := range closure {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			name := strings.ToLower(string(f.Name()))
			for _, verb := range removalVerbs {
				if strings.Contains(name, verb) {
					out = append(out, fmt.Sprintf("%s: manifest field name carries removal verb %q — removal-by-omission is the SOLE cleanup authority; the sync-manifest surface has no delete/remove/tombstone/revoke vocabulary (AC-9, [WIRE-26])", f.FullName(), verb))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestGuard_ManifestNoRemovalVerbs is the AC-9 schema never-check (plan
// choice 8): removal-by-omission is the sole cleanup authority, so no field
// anywhere in the SyncManifest closure carries deletion vocabulary. It is
// self-discovering with matches-zero protection through the harness
// (G-000-3): findRegistry demands exactly one SyncManifest, so the ABSENCE
// of the manifest message FAILS the guard (the never-check has no subject)
// rather than passing vacuously, and the Discover floor of 4 (manifest +
// Occurrence + MaintenanceWindow + Intervals) fails if the closure walk
// stops descending the manifest's message graph.
func TestGuard_ManifestNoRemovalVerbs(t *testing.T) {
	closure := Discover(t, "SyncManifest closure messages", 4, func() ([]protoreflect.MessageDescriptor, error) {
		files := packageFiles(ContractPackage)
		root, err := findRegistry(files, "SyncManifest")
		if err != nil {
			return nil, fmt.Errorf("SyncManifest lookup: %w — the manifest message must exist exactly once for the removal-verb never-check to have a subject (AC-9, [WIRE-26])", err)
		}
		return messageClosure(files, root), nil
	})
	for _, v := range removalVerbViolations(closure) {
		t.Errorf("%s", v)
	}
}

// TestGuard_ManifestNoRemovalVerbs_Liveness: the fixture plants a top-level
// removal-verb field (FixtureManifest.removed_ids) and one a closure hop away
// (FixtureManifestEntry.tombstone_key); the walk must flag exactly those two
// and leave the clean sibling fields alone — proof the never-check can go red
// and descends into the manifest closure, not just its top message.
func TestGuard_ManifestNoRemovalVerbs_Liveness(t *testing.T) {
	closure := Discover(t, "FixtureManifest closure messages", 2, func() ([]protoreflect.MessageDescriptor, error) {
		files := packageFiles(fixturePackage)
		root, err := findRegistry(files, "FixtureManifest")
		if err != nil {
			return nil, fmt.Errorf("FixtureManifest lookup: %w", err)
		}
		return messageClosure(files, root), nil
	})
	got := removalVerbViolations(closure)
	want := []string{
		"powermanage.fixture.v1.FixtureManifest.removed_ids",
		"powermanage.fixture.v1.FixtureManifestEntry.tombstone_key",
	}
	if len(got) != len(want) {
		t.Fatalf("fixture removal-verb violations = %v, want exactly %v — the never-check can no longer go red for the planted shapes", got, want)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w+":") {
			t.Errorf("violation %d = %q, want it to flag %s", i, got[i], w)
		}
	}
	for _, g := range got {
		for _, clean := range []string{"occurrence_ids", "assignment_key", "entry"} {
			if strings.Contains(g, clean) {
				t.Errorf("guard flagged %q — that field is planted as clean manifest vocabulary", g)
			}
		}
	}
}

// TestSyncManifest_IntervalsRequired pins the [WIRE-26] presence demand:
// every sync response carries server-set intervals, and for a message field
// absence is not emptiness, so the schema requires it. Regression for the
// PR #17 review finding on untagged SyncManifest fields. The remaining
// untagged fields are deliberate, not gaps: epoch/generation validity is
// relational (manifest.Newer against agent state — inexpressible as a field
// rule; a vacuous bound would satisfy G-1's letter while validating
// nothing) and empty occurrences/maintenance_windows are load-bearing
// removal-by-omission. M5 must resolve their tagging when the manifest
// becomes reachable from a service method (G-1 scope).
func TestSyncManifest_IntervalsRequired(t *testing.T) {
	md, err := findRegistry(packageFiles(ContractPackage), "SyncManifest")
	if err != nil {
		t.Fatalf("SyncManifest lookup: %v", err)
	}
	f := md.Fields().ByName("intervals")
	if f == nil {
		t.Fatal("SyncManifest has no intervals field — [WIRE-26] mandates server-set intervals in every manifest")
	}
	rules, _ := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
	if !rules.GetRequired() {
		t.Errorf("SyncManifest.intervals must carry (buf.validate.field).required = true — every sync response carries server-set intervals, and an absent message field is not an empty one ([WIRE-26])")
	}
}
