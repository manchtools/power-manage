package listeners

import . "net"

// Planted violation: dot-imported Listen resolves unqualified.
func dotted() (Listener, error) { return Listen("tcp", ":4") }
