package clock

import . "time"

// Planted violation: a dot-import must not hide the call either.
func dotStamp() Time { return Now() }
