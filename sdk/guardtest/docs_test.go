package guardtest

import "testing"

// TestGuard_ConfigReads_Liveness: the fixture plants knobs that are never
// read — in an inline section, a named section type, and an embedded
// section — next to knobs that are; only the unread ones may be flagged,
// exactly once each. A cross-package section type is un-enumerable from
// the AST and must fail closed as its own violation, never skip.
func TestGuard_ConfigReads_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		return ConfigReadViolations(root, "reportConfig")
	}
	RequireViolation(t, "config read sites", scan, "testdata/arch/docs/unread")
	v, err := scan("testdata/arch/docs/unread")
	if err != nil {
		t.Fatalf("scanning the read-site fixture: %v", err)
	}
	requireFlagged(t, v,
		[]string{
			"reportConfig.Tuning.UnreadKnob",
			"reportConfig.Store.Retries",
			"reportConfig.CacheSection.TTL",
			"reportConfig.Ext",
			"reportConfig.RemoteSection",
			"reportConfig.winSection",
		},
		[]string{
			"reportConfig.Tuning.UsedKnob",
			"reportConfig.Store.Path",
			"reportConfig.CacheSection.Refresh",
		})
}
