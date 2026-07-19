package listeners

import nl "net"

// Planted violations: aliased import, paren-wrapped callee, a call inside
// a closure (attributed to the enclosing var), a serve-family method call
// on a custom server, and ListenConfig's Listen method.
func aliased() (nl.Listener, error) { return nl.Listen("tcp", ":1") }

func parend() (nl.Listener, error) { return (nl.Listen)("tcp", ":2") }

var inClosure = func() (nl.Listener, error) { return nl.Listen("tcp", ":3") }

type server struct{}

func (server) ListenAndServe() error { return nil }

func method() error {
	var srv server
	return srv.ListenAndServe()
}

func viaConfig() (nl.Listener, error) {
	var lc nl.ListenConfig
	return lc.Listen(nil, "tcp", ":6")
}
