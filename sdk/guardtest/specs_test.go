package guardtest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	defendedActorsLine = regexp.MustCompile(`(?m)^- \*\*Defended actors:\*\*[ \t]+([^\r\n]*\S)[ \t]*$`)
	statusHeaderLine   = regexp.MustCompile(`(?m)^Status:[^\r\n]*$`)
	canonicalStatus    = regexp.MustCompile("^Status: See `00-index\\.md` \\(single status ledger\\)$")
)

func hasDefendedActors(preamble string) bool {
	match := defendedActorsLine.FindStringSubmatch(preamble)
	return len(match) == 2 && !strings.EqualFold(strings.TrimSpace(match[1]), "TBD")
}

func hasCanonicalStatus(preamble string) bool {
	headers := statusHeaderLine.FindAllString(preamble, -1)
	return len(headers) == 1 && canonicalStatus.MatchString(headers[0])
}

type reviewedSpec struct {
	path     string
	preamble string
}

func reviewedSpecs(root string, first, last int) ([]reviewedSpec, error) {
	dir := filepath.Join(root, "docs", "content", "01-specs")
	var specs []reviewedSpec
	for n := first; n <= last; n++ {
		matches, err := filepath.Glob(filepath.Join(dir, fmt.Sprintf("%03d-*.md", n)))
		if err != nil {
			return nil, fmt.Errorf("listing SPEC-%03d: %w", n, err)
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("SPEC-%03d matched %d files, want exactly one", n, len(matches))
		}
		body, err := os.ReadFile(matches[0])
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(matches[0]), err)
		}
		text := string(body)
		end := strings.Index(text, "## 5. Rejection paths")
		if end < 0 {
			return nil, fmt.Errorf("%s has no §5 rejection-path heading", filepath.Base(matches[0]))
		}
		specs = append(specs, reviewedSpec{path: matches[0], preamble: text[:end]})
	}
	return specs, nil
}

// TestGuard_SpecActors enforces SPEC-001 AC-6: every security-relevant spec
// names the actor it defends against before its rejection table.
func TestGuard_SpecActors(t *testing.T) {
	specs := Discover(t, "SPEC-003..016 actor declarations", 14, func() ([]reviewedSpec, error) {
		return reviewedSpecs(RepoRoot(t), 3, 16)
	})
	for _, spec := range specs {
		if !hasDefendedActors(spec.preamble) {
			t.Errorf("%s names no defended actor before §5 (SPEC-001 AC-6)", filepath.Base(spec.path))
		}
	}
}

func TestSpecActors_Liveness(t *testing.T) {
	for name, declaration := range map[string]string{
		"missing":     "No threat declaration.",
		"blank":       "- **Defended actors:**    ",
		"placeholder": "- **Defended actors:** TBD",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "docs", "content", "01-specs")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			body := "# SPEC-003\n\n" + declaration + "\n\n## 5. Rejection paths\n"
			if err := os.WriteFile(filepath.Join(dir, "003-fixture.md"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			specs, err := reviewedSpecs(root, 3, 3)
			if err != nil {
				t.Fatalf("reviewedSpecs: %v", err)
			}
			if len(specs) != 1 || hasDefendedActors(specs[0].preamble) {
				t.Fatalf("actor liveness fixture was not detected: %+v", specs)
			}
		})
	}
}

func TestSpecHeaders_DeferToStatusLedger(t *testing.T) {
	specs := Discover(t, "SPEC-000..017 headers", 18, func() ([]reviewedSpec, error) {
		return reviewedSpecs(RepoRoot(t), 0, 17)
	})
	for _, spec := range specs {
		if !hasCanonicalStatus(spec.preamble) {
			t.Errorf("%s carries a second status instead of deferring to 00-index.md", filepath.Base(spec.path))
		}
	}
}

func TestSpecHeaders_Liveness(t *testing.T) {
	if !hasCanonicalStatus("Status: See `00-index.md` (single status ledger)\n") {
		t.Fatal("exact canonical status header was rejected")
	}
	for name, preamble := range map[string]string{
		"embedded":         "Prose says Status: See `00-index.md` but has no header.\n",
		"duplicate":        "Status: See `00-index.md` (single status ledger)\nStatus: READY\n",
		"inline secondary": "Status: See `00-index.md` (single status ledger) / READY\n",
		"wrong":            "Status: READY\n",
	} {
		t.Run(name, func(t *testing.T) {
			if hasCanonicalStatus(preamble) {
				t.Fatalf("invalid status fixture accepted: %q", preamble)
			}
		})
	}
}
