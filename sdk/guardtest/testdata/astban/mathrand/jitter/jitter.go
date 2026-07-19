package jitter

import (
	"math/rand"
	"time"
)

// Allowlisted use: backoff jitter is the sanctioned math/rand exception
// (INV-8) — the caller allows this path explicitly.
func backoff(base time.Duration) time.Duration {
	return base + time.Duration(rand.Int63n(int64(base)))
}
