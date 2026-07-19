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
