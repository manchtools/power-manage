#!/usr/bin/env bash
# Guard: this repository is self-contained. No references to external repos,
# their issue trackers, old design documents, or AI attribution may appear in
# tracked content. CLAUDE.md and .claude/ (tooling instructions) are exempt,
# as is this script (it names the patterns).
set -u -o pipefail

PATTERNS=(
  'REWRITE_SPEC'                 # the untracked design document — never referenced
  'manchtools/power-manage-'     # old polyrepo slugs, module paths, and their issues
  '\bADR [0-9]{4}'               # old ADR numbering
  'Co-Authored-By'               # attribution trailers
  'noreply@anthropic\.com'
  'claude\.com/claude-code'
)

FAIL=0
for p in "${PATTERNS[@]}"; do
  # grep exit codes: 0 = hits (finding), 1 = clean, >1 = grep itself failed.
  # Conflating "grep broke" with "clean" would make this guard fail open.
  hits=$(grep -rInE "$p" . \
    --exclude-dir=.git --exclude-dir=.claude --exclude-dir=node_modules \
    --exclude-dir=bin --exclude-dir=dist \
    --exclude=CLAUDE.md --exclude=.gitignore --exclude=check-self-contained.sh \
    --exclude=check-conventions.sh --exclude=check-conventions_test.sh)
  rc=$?
  if [ "$rc" -gt 1 ]; then
    printf '\nGUARD ERROR: grep failed (exit %s) on pattern: %s\n' "$rc" "$p"
    FAIL=1
  elif [ "$rc" -eq 0 ]; then
    printf '\nFORBIDDEN external reference (pattern: %s):\n%s\n' "$p" "$hits"
    FAIL=1
  fi
done

if [ "$FAIL" -ne 0 ]; then
  echo
  echo "self-contained check FAILED — inline the rationale instead of referencing it."
  exit 1
fi
echo "self-contained: OK"
