package archtest

import (
	"regexp"
	"strings"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestULIDRule_Pattern evaluates the shipped ULID rule against the ULID
// grammar's edges. The regex is extracted from the descriptor (ground
// truth, never a copy) and compiled with RE2 — the same semantics CEL's
// matches() runs. A 26-char ULID encodes 128 bits, so the first character
// is 0–7: the overflow row is the regression for the rule accepting 8–Z
// there.
func TestULIDRule_Pattern(t *testing.T) {
	var ext protoreflect.ExtensionDescriptor
	for _, fd := range packageFiles(ContractPackage) {
		exts := fd.Extensions()
		for i := 0; i < exts.Len(); i++ {
			if exts.Get(i).Name() == "ulid" {
				ext = exts.Get(i)
			}
		}
	}
	if ext == nil {
		t.Fatal("predefined ULID rule not found in the contract descriptors [WIRE-5]")
	}
	predef, _ := proto.GetExtension(ext.Options(), validate.E_Predefined).(*validate.PredefinedRules)
	if predef == nil || len(predef.GetCel()) != 1 {
		t.Fatalf("ulid extension carries no single predefined CEL rule: %v", predef)
	}
	expr := predef.GetCel()[0].GetExpression()
	parts := strings.Split(expr, "'")
	if len(parts) != 3 {
		t.Fatalf("cannot extract the regex literal from %q", expr)
	}
	re, err := regexp.Compile(parts[1])
	if err != nil {
		t.Fatalf("shipped ULID regex does not compile: %v", err)
	}
	valid := []string{
		"01ARZ3NDEKTSV4RRFFQ69G5FAV", // canonical spec example
		"00000000000000000000000000", // zero
		"7ZZZZZZZZZZZZZZZZZZZZZZZZZ", // max 128-bit value
	}
	invalid := []string{
		"80000000000000000000000000", // overflow: first char must be 0–7
		"8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
		"01arz3ndektsv4rrffq69g5fav",  // lowercase
		"01ARZ3NDEKTSV4RRFFQ69G5FA",   // 25 chars
		"01ARZ3NDEKTSV4RRFFQ69G5FAVX", // 27 chars
		"01ARZ3NDEKTSV4RRFFQ69G5FAI",  // I outside Crockford
		"01ARZ3NDEKTSV4RRFFQ69G5FAL",  // L
		"01ARZ3NDEKTSV4RRFFQ69G5FAO",  // O
		"01ARZ3NDEKTSV4RRFFQ69G5FAU",  // U
	}
	for _, s := range valid {
		if !re.MatchString(s) {
			t.Errorf("valid ULID %q rejected by the shipped rule", s)
		}
	}
	for _, s := range invalid {
		if re.MatchString(s) {
			t.Errorf("invalid ULID %q accepted by the shipped rule", s)
		}
	}
}
