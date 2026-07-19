package clock

import time "example.com/fakeclock"

// Decoy: a package aliased AS `time` from another path — its .Now() must
// NOT be flagged; flagging it means the scan matches names, not imports.
func decoyStamp() time.Instant { return time.Now() }
