// Fixture gateway binary: reaches the eventstore only transitively,
// through relay's blank import.
package main

import "example.com/gwpure/internal/relay"

func main() { relay.Run() }
