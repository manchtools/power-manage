package clock

import (
	"net"
	"time"
)

// Planted violations: unabstracted time.Now, including inside a SetDeadline
// argument (the seam-less deadline is caught at its time.Now site).
func stamp() time.Time { return time.Now() }

func deadline(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
}
