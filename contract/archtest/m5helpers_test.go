package archtest

// Shared descriptor helpers for the SPEC-003 M5 stream-frame and deny-list /
// near-copy guard tests. Every message the frames introduce is looked up by
// STRING through the descriptor registry (findRegistry / findService /
// findEnum), never by generated Go type — so this package compiles before the
// M5 protos land and each test fails at RUNTIME with the guard's own
// missing-subject error, exactly as findRegistry already does.

import (
	"fmt"
	"sort"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
)

// fieldRules returns the buf.validate field rules on f, or nil when the field
// carries none.
func fieldRules(f protoreflect.FieldDescriptor) *validate.FieldRules {
	rules, _ := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
	return rules
}

// hasULIDRule reports whether f carries the predefined (powermanage.v1.ulid)
// string rule ([WIRE-5]).
func hasULIDRule(f protoreflect.FieldDescriptor) bool {
	sr := fieldRules(f).GetString()
	if sr == nil {
		return false
	}
	ulid, _ := proto.GetExtension(sr, powermanagev1.E_Ulid).(bool)
	return ulid
}

// findService returns the single service in files whose short name is name, or
// an error when it is missing or duplicated — the missing-subject error that
// makes an exact-set RPC guard fail loudly before the service gains its RPCs.
func findService(files []protoreflect.FileDescriptor, name protoreflect.Name) (protoreflect.ServiceDescriptor, error) {
	var found []protoreflect.ServiceDescriptor
	for _, fd := range files {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			if svcs.Get(i).Name() == name {
				found = append(found, svcs.Get(i))
			}
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("found %d services named %s, want exactly one (SPEC-003 §3.2)", len(found), name)
	}
	return found[0], nil
}

// findEnum returns the single enum in files (top-level or nested) whose short
// name is name, or an error when it is missing or duplicated.
func findEnum(files []protoreflect.FileDescriptor, name protoreflect.Name) (protoreflect.EnumDescriptor, error) {
	var found []protoreflect.EnumDescriptor
	for _, ed := range enums(files) {
		if ed.Name() == name {
			found = append(found, ed)
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("found %d enums named %s, want exactly one", len(found), name)
	}
	return found[0], nil
}

// msgFieldNames returns the sorted snake_case field names of md.
func msgFieldNames(md protoreflect.MessageDescriptor) []string {
	var names []string
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		names = append(names, string(fields.Get(i).Name()))
	}
	sort.Strings(names)
	return names
}

// oneofByName returns the (non-synthetic) oneof named name on md, or nil.
func oneofByName(md protoreflect.MessageDescriptor, name protoreflect.Name) protoreflect.OneofDescriptor {
	oo := md.Oneofs().ByName(name)
	if oo == nil || oo.IsSynthetic() {
		return nil
	}
	return oo
}

// oneofMemberTypes maps each member field name of oneof to the short name of
// its message type; a scalar/enum member maps to a "«non-message»" sentinel so
// a mis-typed frame member is loud rather than silently skipped.
func oneofMemberTypes(oneof protoreflect.OneofDescriptor) map[string]string {
	out := map[string]string{}
	fields := oneof.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if m := f.Message(); m != nil {
			out[string(f.Name())] = string(m.Name())
		} else {
			out[string(f.Name())] = "«non-message:" + f.Kind().String() + "»"
		}
	}
	return out
}

// oneofRequired reports whether oneof carries (buf.validate.oneof).required.
func oneofRequired(oneof protoreflect.OneofDescriptor) bool {
	rules, _ := proto.GetExtension(oneof.Options(), validate.E_Oneof).(*validate.OneofRules)
	return rules.GetRequired()
}

// allMessages returns every message declared in files, top-level and nested.
func allMessages(files []protoreflect.FileDescriptor) []protoreflect.MessageDescriptor {
	var out []protoreflect.MessageDescriptor
	var walk func(mds protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			out = append(out, md)
			walk(md.Messages())
		}
	}
	for _, fd := range files {
		walk(fd.Messages())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}
