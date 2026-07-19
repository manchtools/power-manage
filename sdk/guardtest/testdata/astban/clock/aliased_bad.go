package clock

import tm "time"

// Planted violation: the import alias must not hide the call.
func aliasedStamp() tm.Time { return tm.Now() }
