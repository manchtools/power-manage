package guardtest

import "testing"

// TestGuard_ConfigReads_Liveness: the fixture plants knobs that are never
// read — one in an inline section, one in a named section type — next to
// knobs that are; only the unread ones may be flagged, exactly once each.
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
		[]string{"reportConfig.Tuning.UnreadKnob", "reportConfig.Store.Retries"},
		[]string{"reportConfig.Tuning.UsedKnob", "reportConfig.Store.Path"})
}
