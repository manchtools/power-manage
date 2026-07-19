package listeners

import nl "net"

// Attribution fixtures: the second spec of a var block and same-named
// methods on two types must each key under their own declaration.
var (
	blockA = 1
	blockB = func() (nl.Listener, error) { return nl.Listen("tcp", ":8") }
)

type first struct{}

func (first) run() error { return nil }

type second struct{}

func (second) run() (nl.Listener, error) { return nl.Listen("tcp", ":9") }
