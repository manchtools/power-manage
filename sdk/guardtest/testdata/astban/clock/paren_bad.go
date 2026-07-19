package clock

import "time"

// Planted violations: a parenthesized callee still calls time.Now, and a
// call inside a closure is still a call — neither wrapping may evade the
// ban.
func parenthesized() time.Time { return (time.Now)() }

var inClosure = func() time.Time { return time.Now() }
