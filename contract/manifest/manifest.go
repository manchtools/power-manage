// Package manifest carries the sync-manifest monotonicity rule of SPEC-003
// §3.8 ([WIRE-26], AC-9): the monotonic (epoch, generation) pair is the
// durable-class anti-replay authority. The agent rejects any manifest whose
// pair is not strictly newer than its last accepted pair and keeps the
// prior verified state.
package manifest

// Newer reports whether (epoch, generation) is strictly newer than
// (lastEpoch, lastGeneration) — lexicographic, epoch dominant. An equal
// pair is NOT newer: replaying the last accepted manifest is a rejection.
func Newer(epoch, generation, lastEpoch, lastGeneration uint64) bool {
	if epoch != lastEpoch {
		return epoch > lastEpoch
	}
	return generation > lastGeneration
}
