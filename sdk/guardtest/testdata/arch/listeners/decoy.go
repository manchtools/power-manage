package listeners

import net "example.com/fakenet"

// Decoy: a same-named alias from an unrelated package must NOT flag —
// the scan resolves imports, it does not match names.
func decoy() error { return net.Listen("tcp", ":5") }
