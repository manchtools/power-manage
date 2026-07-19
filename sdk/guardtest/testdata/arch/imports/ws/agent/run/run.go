package run

// Planted violation: agent imports server — the licensing breach (GPL
// binary linking AGPL code). Aliased import must not evade path matching.
import srv "example.com/pm/server/core"

var N = srv.N
