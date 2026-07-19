package enumdefault

import (
	"fmt"

	pb "example.com/gen/statepb"
)

// Planted violation: an enum switch with no default at all.
func nameOf(s pb.State) string {
	switch s {
	case pb.State_ACTIVE:
		return "active"
	case pb.State_DISABLED:
		return "disabled"
	}
	return ""
}

// Planted violation: a default that neither returns nor panics — the
// unknown enum value is silently swallowed.
func describe(s pb.State) string {
	out := "unknown"
	switch s {
	case pb.State_ACTIVE:
		out = "active"
	default:
		out = fmt.Sprintf("%d", s)
	}
	return out
}

// Planted violation: the default's "return" sits inside a nested closure —
// the enclosing clause itself never errors.
func silent(s pb.State) string {
	switch s {
	case pb.State_ACTIVE:
		return "active"
	default:
		emit := func() string { return "swallowed" }
		_ = emit
	}
	return ""
}

// Planted violation: all case expressions parenthesized — still an enum
// switch, still needs an erroring default.
func wrapped(s pb.State) string {
	switch s {
	case (pb.State_ACTIVE):
		return "active"
	}
	return ""
}
