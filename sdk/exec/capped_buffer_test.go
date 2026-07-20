package exec

import (
	"strings"
	"sync"
	"testing"
)

// A child that emits gigabytes must not pin the parent's memory: CappedBuffer
// is the shared, bounded io.Writer output buffers are wrapped in — it
// accumulates up to a cap, then discards the rest and marks the output
// truncated, matching the "[output truncated]" convention the exec capture
// uses.
//
// Contract:
//   - under the cap: content is preserved verbatim, not marked truncated;
//   - over the cap: stored content never exceeds the cap, a single
//     truncation marker is appended, and Truncated() reports true;
//   - Write ALWAYS reports the full len(p) consumed and a nil error, so
//     an io.Copy feeding it from a child pipe never sees a short write
//     and the child is drained (not wedged on a blocked pipe).
func TestCappedBuffer_UnderCap(t *testing.T) {
	b := NewCappedBuffer(100)
	n, err := b.Write([]byte("hello world"))
	if err != nil || n != len("hello world") {
		t.Fatalf("Write = (%d,%v), want (%d,nil)", n, err, len("hello world"))
	}
	if b.Truncated() {
		t.Errorf("Truncated() = true, want false")
	}
	if got := b.String(); got != "hello world" {
		t.Errorf("String() = %q, want %q", got, "hello world")
	}
}

func TestCappedBuffer_OverCapTruncatesAndMarks(t *testing.T) {
	const cap = 64
	b := NewCappedBuffer(cap)

	big := strings.Repeat("A", cap*4)
	n, err := b.Write([]byte(big))
	if err != nil {
		t.Fatalf("Write err = %v", err)
	}
	// Write must report the full input consumed even though we dropped
	// the overflow — otherwise io.Copy treats it as ErrShortWrite.
	if n != len(big) {
		t.Errorf("Write n = %d, want %d (full input reported consumed)", n, len(big))
	}
	if !b.Truncated() {
		t.Errorf("Truncated() = false, want true")
	}

	out := b.String()
	if !strings.HasSuffix(out, "[output truncated]") {
		t.Errorf("String() = %q, want trailing truncation marker", out)
	}
	// The retained 'A' run must not exceed the cap (marker excluded).
	body := strings.TrimSuffix(out, "\n[output truncated]")
	if len(body) > cap {
		t.Errorf("retained body = %d bytes, want <= cap %d", len(body), cap)
	}
	if strings.Count(body, "A") != len(body) {
		t.Errorf("retained body contains unexpected bytes: %q", body)
	}
}

// Truncation across MULTIPLE writes: the cap is on cumulative bytes, and
// the marker is appended exactly once regardless of how many writes
// crossed the boundary.
func TestCappedBuffer_MultiWriteCumulativeCap(t *testing.T) {
	const cap = 10
	b := NewCappedBuffer(cap)
	for i := 0; i < 5; i++ {
		if _, err := b.Write([]byte("XXXXX")); err != nil { // 25 bytes total
			t.Fatalf("Write: %v", err)
		}
	}
	out := b.String()
	if strings.Count(out, "[output truncated]") != 1 {
		t.Errorf("marker count = %d, want exactly 1 in %q", strings.Count(out, "[output truncated]"), out)
	}
	body := strings.TrimSuffix(out, "\n[output truncated]")
	if len(body) > cap {
		t.Errorf("retained = %d, want <= %d", len(body), cap)
	}
}

// A negative cap clamps to zero (retain nothing); Bytes returns a copy with the
// truncation marker when input was dropped, and a non-aliasing copy otherwise.
func TestCappedBuffer_NegativeCapAndBytes(t *testing.T) {
	b := NewCappedBuffer(-5) // clamps to 0
	n, err := b.Write([]byte("x"))
	if err != nil || n != 1 {
		t.Fatalf("Write = (%d,%v), want (1,nil)", n, err)
	}
	if !b.Truncated() {
		t.Error("a zero-cap buffer must mark truncated on any write")
	}
	if got := string(b.Bytes()); !strings.HasSuffix(got, "[output truncated]") || strings.Contains(got, "x") {
		t.Errorf("Bytes() = %q, want only the truncation marker (nothing retained)", got)
	}

	// Non-truncated Bytes() returns a COPY of the retained content (no marker).
	b2 := NewCappedBuffer(100)
	if _, err := b2.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	out := b2.Bytes()
	if string(out) != "hello" {
		t.Errorf("Bytes() = %q, want hello", out)
	}
	out[0] = 'X' // must not alias the internal buffer
	if b2.String() != "hello" {
		t.Errorf("Bytes() aliased the internal buffer; String() = %q, want hello", b2.String())
	}
}

// CappedBuffer is written from concurrent copy goroutines; it must be safe
// under concurrent writers (the race detector is the real check here).
func TestCappedBuffer_ConcurrentWritesSafe(t *testing.T) {
	b := NewCappedBuffer(1 << 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = b.Write([]byte("line\n"))
			}
		}()
	}
	wg.Wait()
	// No assertion on exact content (interleaving is nondeterministic);
	// sanity: it did not panic and produced something.
	if b.String() == "" {
		t.Errorf("expected some buffered output")
	}
}
