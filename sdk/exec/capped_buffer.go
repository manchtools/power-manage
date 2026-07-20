package exec

import (
	"io"
	"slices"
	"sync"
)

// truncationMarker is appended once to a CappedBuffer's rendered output
// when input exceeded the cap. It matches the marker the streaming exec core
// uses for its own captured streams so downstream consumers see one convention.
const truncationMarker = "\n[output truncated]"

// CappedBuffer is a concurrency-safe io.Writer that accumulates at most
// `cap` bytes and then discards the rest, recording that truncation
// happened. It is the shared bound consumers wrap per-command output
// buffers in, so a child process emitting unbounded output cannot
// exhaust the parent's memory.
//
// Write always reports the FULL len(p) as consumed and a nil error, even
// when bytes are dropped, so an io.Copy feeding it from a child's pipe
// never observes a short write (which it would treat as ErrShortWrite and
// abort, potentially wedging the child on a full pipe). Overflow is
// silently dropped; String/Bytes append the truncation marker so the
// loss is visible to a human reader.
type CappedBuffer struct {
	mu        sync.Mutex
	buf       []byte
	cap       int
	truncated bool
}

// NewCappedBuffer returns a CappedBuffer that retains at most cap bytes.
func NewCappedBuffer(cap int) *CappedBuffer {
	if cap < 0 {
		cap = 0
	}
	return &CappedBuffer{cap: cap}
}

// Write appends as much of p as fits under the cap and discards the rest,
// marking the buffer truncated if anything was dropped. It always returns
// (len(p), nil).
func (b *CappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	remaining := b.cap - len(b.buf)
	if remaining <= 0 {
		if len(p) > 0 {
			b.truncated = true
		}
		return len(p), nil
	}
	if len(p) > remaining {
		b.buf = append(b.buf, p[:remaining]...)
		b.truncated = true
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

// Truncated reports whether any input was dropped because of the cap.
func (b *CappedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

// String returns the retained output, with a single truncation marker
// appended if input was dropped.
func (b *CappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return string(b.buf) + truncationMarker
	}
	return string(b.buf)
}

// Bytes returns the retained output (with the truncation marker appended
// if input was dropped). The returned slice is a copy; callers may retain
// it without aliasing the buffer.
func (b *CappedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		out := make([]byte, 0, len(b.buf)+len(truncationMarker))
		out = append(out, b.buf...)
		out = append(out, truncationMarker...)
		return out
	}
	return slices.Clone(b.buf)
}

// compile-time guard: CappedBuffer satisfies io.Writer.
var _ io.Writer = (*CappedBuffer)(nil)
