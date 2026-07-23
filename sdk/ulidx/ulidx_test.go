package ulidx

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNew_EncodesTimeAndCheckedRandomnessAsCanonicalULID(t *testing.T) {
	original := randomReader
	t.Cleanup(func() { randomReader = original })
	randomReader = strings.NewReader(string([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}))

	now := time.Date(2026, time.July, 23, 12, 34, 56, 789_000_000, time.UTC)
	id, err := New(now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const want = "01KY7FHJ4N000G40R40M30E209"
	if id != want {
		t.Fatalf("New = %q; want timestamp-and-entropy encoding %q", id, want)
	}
}

func TestNew_RejectsInvalidTimeAndRandomFailure(t *testing.T) {
	original := randomReader
	t.Cleanup(func() { randomReader = original })

	for _, invalid := range []time.Time{
		{},
		time.UnixMilli(-1),
		time.UnixMilli(1 << 48),
	} {
		id, err := New(invalid)
		if id != "" || err == nil ||
			err.Error() != "ulidx: time is outside the 48-bit timestamp range" {
			t.Fatalf("New(%s) = (%q, %v); want empty ID and validation error", invalid, id, err)
		}
	}

	wantErr := errors.New("entropy unavailable")
	randomReader = errorReader{err: wantErr}
	if id, err := New(time.UnixMilli(1)); !errors.Is(err, wantErr) || id != "" {
		t.Fatalf("New with failed entropy = (%q, %v); want wrapped %v", id, err, wantErr)
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

var _ io.Reader = errorReader{}
