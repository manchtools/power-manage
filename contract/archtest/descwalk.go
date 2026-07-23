// Package archtest holds the contract's descriptor-walk guards (SPEC-003
// G-1, G-2 descriptor half). It lives inside contract because the import
// direction is one-way both ways (INV-19): contract cannot use
// sdk/guardtest, and sdk cannot link the generated descriptors this
// package walks. The matches-zero Discover helper is deliberately
// duplicated here for the same reason.
package archtest

import (
	"fmt"
	"sort"
	"strings"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Register the contract's file descriptors; the walks below discover
	// everything within the package from the registry, never from a list.
	_ "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
)

// ContractPackage is the proto package every walk anchors on.
const ContractPackage = "powermanage.v1"

// packageFiles returns the registered file descriptors whose proto package
// is exactly pkg, sorted by path.
func packageFiles(pkg string) []protoreflect.FileDescriptor {
	var files []protoreflect.FileDescriptor
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) == pkg {
			files = append(files, fd)
		}
		return true
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path() < files[j].Path() })
	return files
}

// allMessages returns every message declared by files, including nested and
// service-unreachable messages. Negative-surface guards must cover dormant
// declarations too: a later RPC must not activate a previously unseen shape.
func allMessages(files []protoreflect.FileDescriptor) []protoreflect.MessageDescriptor {
	var out []protoreflect.MessageDescriptor
	var walk func(protoreflect.MessageDescriptors)
	walk = func(messages protoreflect.MessageDescriptors) {
		for i := 0; i < messages.Len(); i++ {
			message := messages.Get(i)
			out = append(out, message)
			walk(message.Messages())
		}
	}
	for _, file := range files {
		walk(file.Messages())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}

// localCredentialFieldViolations is GUARD-007-6: local password, TOTP, and
// WebAuthn credentials cannot exist in the contract under disguised casing or
// separator styles. Generic external credential identifiers remain legal.
func localCredentialFieldViolations(messages []protoreflect.MessageDescriptor) []string {
	var violations []string
	for _, message := range messages {
		fields := message.Fields()
		for i := 0; i < fields.Len(); i++ {
			field := fields.Get(i)
			name := normalizedIdentifier(string(field.Name()))
			jsonName := normalizedIdentifier(field.JSONName())
			typeName := ""
			if field.Message() != nil {
				typeName = normalizedIdentifier(string(field.Message().FullName()))
			} else if field.Enum() != nil {
				typeName = normalizedIdentifier(string(field.Enum().FullName()))
			}
			if forbiddenLocalCredential(name) ||
				forbiddenLocalCredential(jsonName) ||
				forbiddenLocalCredential(typeName) {
				violations = append(violations, fmt.Sprintf(
					"%s: field name, JSON name, or type exposes a forbidden local credential",
					field.FullName(),
				))
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func normalizedIdentifier(value string) string {
	var normalized strings.Builder
	normalized.Grow(len(value))
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			normalized.WriteRune(r)
		}
	}
	return normalized.String()
}

func forbiddenLocalCredential(value string) bool {
	return strings.Contains(value, "password") ||
		strings.Contains(value, "totp") ||
		strings.Contains(value, "webauthn")
}

// services returns the full names of every service declared in files.
func services(files []protoreflect.FileDescriptor) []string {
	var out []string
	for _, fd := range files {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			out = append(out, string(svcs.Get(i).FullName()))
		}
	}
	sort.Strings(out)
	return out
}

// reachableMessages returns every message transitively reachable from the
// services' method inputs and outputs: field message types, map value
// types, and their closures. Messages outside the boundary (declared but
// unreferenced) are deliberately not included — G-1 covers what crosses
// the wire. Messages defined outside the audited files (imported
// well-known types like google.protobuf.Timestamp) are referenced surface,
// not defined surface: their internal fields are not ours to tag, so the
// closure stops at them.
func reachableMessages(files []protoreflect.FileDescriptor) map[protoreflect.FullName]protoreflect.MessageDescriptor {
	audited := make(map[string]bool, len(files))
	for _, fd := range files {
		audited[fd.Path()] = true
	}
	seen := make(map[protoreflect.FullName]protoreflect.MessageDescriptor)
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
	for _, fd := range files {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			methods := svcs.Get(i).Methods()
			for j := 0; j < methods.Len(); j++ {
				visit(methods.Get(j).Input())
				visit(methods.Get(j).Output())
			}
		}
	}
	return seen
}

// enums returns every enum declared in files, top-level and nested.
func enums(files []protoreflect.FileDescriptor) []protoreflect.EnumDescriptor {
	var out []protoreflect.EnumDescriptor
	var fromMessages func(mds protoreflect.MessageDescriptors)
	fromMessages = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			for j := 0; j < md.Enums().Len(); j++ {
				out = append(out, md.Enums().Get(j))
			}
			fromMessages(md.Messages())
		}
	}
	for _, fd := range files {
		for i := 0; i < fd.Enums().Len(); i++ {
			out = append(out, fd.Enums().Get(i))
		}
		fromMessages(fd.Messages())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}

// untaggedExemptions are the sanctioned deliberately-unconstrained fields,
// keyed by full name WITH a per-entry rationale (the guards skill's
// allowlist rule: specific identity, stated reason — never a growing list).
var untaggedExemptions = map[protoreflect.FullName]string{
	// The full uint64 range is legal resume input; the bound is the
	// artifact's size, enforced server-side (ART-2, SPEC-010) — a tag here
	// would over-constrain legitimate resume ([WIRE-2], plan-003-m5 choice 4).
	"powermanage.v1.ArtifactFetchRequest.offset": "resume offset — bounds are the artifact's size, server-side (ART-2)",
	"powermanage.v1.ArtifactChunk.offset":        "chunk offset — bounds are the artifact's size, server-side (ART-2)",
}

// untaggedFields returns a violation per field of every service-reachable
// message in files that carries no buf.validate rules ([WIRE-2], G-1).
// M1 demands presence of constraints; constraint sufficiency
// (type/format/length/range per field class) tightens in M2 with the
// first real fields.
//
// MESSAGE-typed members of a (buf.validate.oneof).required oneof are
// credited structurally: buf lint rejects field-level `required` on oneof
// members, so for a message member the oneof-level demand is the only
// expressible constraint — the frame discriminant IS the validation
// ([WIRE-2]; the member types' own fields stay in the walk). A SCALAR
// member is NOT credited: it can and must carry its own type/format rules,
// and skipping it would fail open (PR #19 review).
func untaggedFields(files []protoreflect.FileDescriptor) []string {
	var out []string
	for _, md := range reachableMessages(files) {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if _, exempt := untaggedExemptions[f.FullName()]; exempt {
				continue
			}
			if oo := f.ContainingOneof(); oo != nil && !oo.IsSynthetic() && oneofRequired(oo) && f.Message() != nil {
				continue
			}
			rules, _ := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
			if rules == nil || (rules.Type == nil && rules.Cel == nil && rules.Required == nil) {
				out = append(out, fmt.Sprintf("%s: boundary field carries no buf.validate rules — absence leaves unvalidated surface [WIRE-2]", f.FullName()))
			}
		}
	}
	sort.Strings(out)
	return out
}

// oneofRequired reports whether oneof carries (buf.validate.oneof).required.
func oneofRequired(oneof protoreflect.OneofDescriptor) bool {
	rules, _ := proto.GetExtension(oneof.Options(), validate.E_Oneof).(*validate.OneofRules)
	return rules.GetRequired()
}

// enumHygieneViolations returns a violation per enum in files whose zero
// value is not *_UNSPECIFIED ([WIRE-4], G-2 descriptor half).
func enumHygieneViolations(files []protoreflect.FileDescriptor) []string {
	var out []string
	for _, ed := range enums(files) {
		zero := ed.Values().ByNumber(0)
		switch {
		case zero == nil:
			out = append(out, fmt.Sprintf("%s: enum has no zero value — every enum starts at *_UNSPECIFIED = 0 [WIRE-4]", ed.FullName()))
		case !strings.HasSuffix(string(zero.Name()), "_UNSPECIFIED"):
			out = append(out, fmt.Sprintf("%s: zero value %s is not *_UNSPECIFIED — a meaningful zero value makes absence indistinguishable from intent [WIRE-4]", ed.FullName(), zero.Name()))
		}
	}
	sort.Strings(out)
	return out
}
