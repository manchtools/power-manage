package relay

import (
	_ "example.com/gwpure/internal/eventstore" // planted violation: a blank import still links

	"example.com/gwpure/internal/frames"
)

func Run() { frames.Cap() }
