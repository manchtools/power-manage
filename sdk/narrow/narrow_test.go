package narrow

import (
	"errors"
	"math"
	"testing"
)

// AC-7: the narrowing helper rejects out-of-range values with an error; a
// uint32 value above uint16 range never silently truncates. The historic bug
// class: an unchecked uint32→uint16 narrowing produced a zero-size PTY.
func TestTo_ExactValuesCross(t *testing.T) {
	// Exact boundary values survive.
	if v, err := To[uint16](uint32(0)); err != nil || v != 0 {
		t.Errorf("To[uint16](0) = (%d, %v), want (0, nil)", v, err)
	}
	if v, err := To[uint16](uint32(math.MaxUint16)); err != nil || v != math.MaxUint16 {
		t.Errorf("To[uint16](65535) = (%d, %v), want (65535, nil)", v, err)
	}
	if v, err := To[int8](int64(math.MinInt8)); err != nil || v != math.MinInt8 {
		t.Errorf("To[int8](-128) = (%d, %v), want (-128, nil)", v, err)
	}
	if v, err := To[int8](int64(math.MaxInt8)); err != nil || v != math.MaxInt8 {
		t.Errorf("To[int8](127) = (%d, %v), want (127, nil)", v, err)
	}

	// One past the boundary errors — never truncates, never wraps.
	if v, err := To[uint16](uint32(math.MaxUint16 + 1)); !errors.Is(err, ErrOutOfRange) || v != 0 {
		t.Errorf("To[uint16](65536) = (%d, %v), want (0, ErrOutOfRange) — 65536 must not wrap to 0 silently", v, err)
	}
	if v, err := To[uint16](uint32(math.MaxUint16 + 2)); !errors.Is(err, ErrOutOfRange) || v != 0 {
		t.Errorf("To[uint16](65537) = (%d, %v), want (0, ErrOutOfRange) — 65537 must not wrap to 1", v, err)
	}
	if _, err := To[int8](int64(math.MinInt8 - 1)); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("To[int8](-129) err = %v, want ErrOutOfRange", err)
	}

	// The AC-7 literal: a uint32 above uint16 range.
	if v, err := To[uint16](uint32(70000)); !errors.Is(err, ErrOutOfRange) || v != 0 {
		t.Errorf("To[uint16](70000) = (%d, %v), want (0, ErrOutOfRange)", v, err)
	}

	// Negative → unsigned errors (sign cannot be represented).
	if _, err := To[uint16](int(-1)); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("To[uint16](-1) err = %v, want ErrOutOfRange", err)
	}
	if _, err := To[uint64](int8(-1)); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("To[uint64](int8(-1)) err = %v, want ErrOutOfRange (round-trip alone would pass; the sign check must catch it)", err)
	}

	// Unsigned → signed with the same bit width: high values sign-flip and
	// must error even though the raw round trip is exact.
	if _, err := To[int8](uint16(math.MaxUint16)); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("To[int8](uint16 max) err = %v, want ErrOutOfRange", err)
	}
	if _, err := To[int64](uint64(math.MaxUint64)); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("To[int64](uint64 max) err = %v, want ErrOutOfRange (sign flip)", err)
	}

	// Widening always succeeds, including negatives.
	if v, err := To[int64](int32(-5)); err != nil || v != -5 {
		t.Errorf("To[int64](-5) = (%d, %v), want (-5, nil)", v, err)
	}
	if v, err := To[uint64](uint8(200)); err != nil || v != 200 {
		t.Errorf("To[uint64](200) = (%d, %v), want (200, nil)", v, err)
	}
	// Same-type pass-through.
	if v, err := To[int](int(42)); err != nil || v != 42 {
		t.Errorf("To[int](42) = (%d, %v), want (42, nil)", v, err)
	}
}
