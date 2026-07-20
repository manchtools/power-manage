// Package narrow provides range-checked numeric narrowing ([SDK-6],
// SPEC-004): a conversion that cannot represent the value exactly returns an
// error instead of silently truncating or wrapping. The historic failure
// mode: an unchecked uint32→uint16 narrowing produced a 0×0 PTY.
package narrow

import (
	"errors"
	"fmt"
)

// ErrOutOfRange is returned when a value does not fit the destination type.
var ErrOutOfRange = errors.New("value out of range for destination type")

// integer covers the built-in integer kinds. Hand-rolled — the SDK takes no
// dependency for one constraint.
type integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// To converts v to D, failing closed when the value does not survive the
// round trip exactly. The sign comparison catches the same-bit-width
// signed↔unsigned flips (uint16 65535 → int8 -1) that the round trip alone
// would miss.
func To[D, S integer](v S) (D, error) {
	d := D(v)
	if S(d) != v || (d < 0) != (v < 0) {
		return 0, fmt.Errorf("%w: %v", ErrOutOfRange, v)
	}
	return d, nil
}
