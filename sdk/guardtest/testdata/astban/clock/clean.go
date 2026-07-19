package clock

import "time"

// Clean: time is used for types and constants only; instants come from the
// injected clock seam.
type clocked struct {
	now func() time.Time
}

func (c clocked) stamp() time.Time { return c.now() }
