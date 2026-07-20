package archtest

// The ActionParams registry walks (SPEC-003 G-3, G-4; [WIRE-12], [WIRE-6]).
// Everything discovers from the descriptor: the registry message anchors on
// its name, member types come from its oneof, and violations are any use of
// a member type outside the registry — the rule that makes the
// predecessor's five-copy oneof drift unrepresentable.

import (
	"fmt"
	"sort"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// findRegistry returns the single message in files whose short name is name,
// or an error when it is missing or duplicated ([WIRE-12]: exactly one).
func findRegistry(files []protoreflect.FileDescriptor, name protoreflect.Name) (protoreflect.MessageDescriptor, error) {
	var found []protoreflect.MessageDescriptor
	var walk func(mds protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			if md.Name() == name {
				found = append(found, md)
			}
			walk(md.Messages())
		}
	}
	for _, fd := range files {
		walk(fd.Messages())
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("found %d messages named %s, want exactly one [WIRE-12]", len(found), name)
	}
	return found[0], nil
}

// registryMembers returns the message types of every oneof member of the
// registry, keyed by full name.
func registryMembers(registry protoreflect.MessageDescriptor) map[protoreflect.FullName]bool {
	members := map[protoreflect.FullName]bool{}
	oneofs := registry.Oneofs()
	for i := 0; i < oneofs.Len(); i++ {
		fields := oneofs.Get(i).Fields()
		for j := 0; j < fields.Len(); j++ {
			if m := fields.Get(j).Message(); m != nil {
				members[m.FullName()] = true
			}
		}
	}
	return members
}

// registryViolations is G-3: a violation for every field outside the
// registry whose message type is a registry member type — a direct embed or
// a second oneof both re-create the parallel copy [WIRE-12] deletes.
// Embedding the registry message itself is the conforming form.
func registryViolations(files []protoreflect.FileDescriptor, name protoreflect.Name) ([]string, error) {
	registry, err := findRegistry(files, name)
	if err != nil {
		return nil, err
	}
	members := registryMembers(registry)
	var out []string
	var walk func(mds protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			if md.FullName() != registry.FullName() {
				fields := md.Fields()
				for j := 0; j < fields.Len(); j++ {
					f := fields.Get(j)
					if m := f.Message(); m != nil && members[m.FullName()] {
						out = append(out, fmt.Sprintf("%s: references registry member type %s outside %s — embed the one registry, never a member directly [WIRE-12]", f.FullName(), m.Name(), name))
					}
				}
			}
			walk(md.Messages())
		}
	}
	for _, fd := range files {
		walk(fd.Messages())
	}
	sort.Strings(out)
	return out, nil
}

// registrySubtree returns the registry message plus the transitive closure
// of its member types and every message in files that embeds the registry —
// the population G-4 walks. As in reachableMessages, the closure stops at
// messages defined outside the audited files: a well-known type's internal
// plain bool (google.protobuf.BoolValue.value) is referenced surface, not
// ours to audit.
func registrySubtree(files []protoreflect.FileDescriptor, registry protoreflect.MessageDescriptor) []protoreflect.MessageDescriptor {
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
			if m := fields.Get(i).Message(); m != nil {
				visit(m)
			}
		}
	}
	visit(registry)
	var embed func(mds protoreflect.MessageDescriptors)
	embed = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			fields := md.Fields()
			for j := 0; j < fields.Len(); j++ {
				if m := fields.Get(j).Message(); m != nil && m.FullName() == registry.FullName() {
					visit(md)
				}
			}
			embed(md.Messages())
		}
	}
	for _, fd := range files {
		embed(fd.Messages())
	}
	var out []protoreflect.MessageDescriptor
	for _, md := range seen {
		out = append(out, md)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}

// plainBoolAllowlist holds the recorded two-value rationales (G-4). A plain
// bool is sanctioned ONLY with an entry here explaining why absence and
// false genuinely coincide. Empty on purpose — [WIRE-6] expects none.
var plainBoolAllowlist = map[protoreflect.FullName]string{}

// plainBoolViolations is G-4: any non-optional plain bool in the registry
// subtree fails unless allowlisted — "unset" silently meaning "false" is
// the unset-disables-your-unit footgun class [WIRE-6].
func plainBoolViolations(files []protoreflect.FileDescriptor, name protoreflect.Name) ([]string, error) {
	registry, err := findRegistry(files, name)
	if err != nil {
		return nil, err
	}
	// Floor: the registry itself plus every oneof member. visit(registry)
	// always seeds one entry, so a bare < 1 check could never fire; anchoring
	// on the member count makes a broken member walk loud.
	subtree := registrySubtree(files, registry)
	if want := 1 + len(registryMembers(registry)); len(subtree) < want {
		return nil, fmt.Errorf("registry subtree walk found %d messages, want at least %d (registry + members) — the walk broke, not the contract", len(subtree), want)
	}
	var out []string
	for _, md := range subtree {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			// HasPresence, not HasOptionalKeyword: `optional` and oneof
			// membership both give a bool explicit presence.
			if f.Kind() != protoreflect.BoolKind || f.HasPresence() {
				continue
			}
			if _, sanctioned := plainBoolAllowlist[f.FullName()]; sanctioned {
				continue
			}
			out = append(out, fmt.Sprintf("%s: plain bool in the registry subtree — give it explicit presence (`optional` or oneof membership) or record a two-value rationale in the allowlist [WIRE-6]", f.FullName()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// enumBoundViolations enforces the descriptor-derived enum bound pair on
// every enum-typed field of every service-reachable message: `defined_only`
// makes the bound the descriptor's value set, `not_in: [0]` makes
// UNSPECIFIED always invalid at boundaries ([WIRE-2], [WIRE-4], AC-2).
func enumBoundViolations(files []protoreflect.FileDescriptor) []string {
	var out []string
	for _, md := range reachableMessages(files) {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if f.Kind() != protoreflect.EnumKind {
				continue
			}
			rules, _ := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
			er := rules.GetEnum()
			zeroBanned := false
			for _, v := range er.GetNotIn() {
				if v == 0 {
					zeroBanned = true
				}
			}
			if !er.GetDefinedOnly() || !zeroBanned {
				out = append(out, fmt.Sprintf("%s: enum field must carry enum rules {defined_only: true, not_in: [0]} — bounds come from the descriptor and UNSPECIFIED is always invalid at boundaries [WIRE-2, WIRE-4]", f.FullName()))
			}
		}
	}
	sort.Strings(out)
	return out
}
