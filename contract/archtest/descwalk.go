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

// untaggedFields returns a violation per field of every service-reachable
// message in files that carries no buf.validate rules ([WIRE-2], G-1).
// M1 demands presence of constraints; constraint sufficiency
// (type/format/length/range per field class) tightens in M2 with the
// first real fields.
func untaggedFields(files []protoreflect.FileDescriptor) []string {
	var out []string
	for _, md := range reachableMessages(files) {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			rules, _ := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
			if rules == nil || (rules.Type == nil && rules.Cel == nil && rules.Required == nil) {
				out = append(out, fmt.Sprintf("%s: boundary field carries no buf.validate rules — absence leaves unvalidated surface [WIRE-2]", f.FullName()))
			}
		}
	}
	sort.Strings(out)
	return out
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
