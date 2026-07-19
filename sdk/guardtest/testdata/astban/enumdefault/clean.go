package enumdefault

import (
	"fmt"

	pb "example.com/gen/statepb"
)

// Clean: the enum switch errors on the unknown value.
func nameOfClean(s pb.State) (string, error) {
	switch s {
	case pb.State_ACTIVE:
		return "active", nil
	case pb.State_DISABLED:
		return "disabled", nil
	default:
		return "", fmt.Errorf("unknown state %d", s)
	}
}

// Clean: a switch with no enum cases is not an enum switch.
func classify(n int) string {
	switch n {
	case 0:
		return "zero"
	}
	return "nonzero"
}
