#!/usr/bin/env bash
# Guard: this repository is self-contained. No references to external repos,
# their issue trackers, old design documents, or AI attribution may appear in
# tracked content. CLAUDE.md and .claude/ (tooling instructions) are exempt,
# as is this script (it names the patterns). The conventions lint and its
# self-test are exempt from the attribution group only — see below.
set -u -o pipefail

EXTERNAL_PATTERNS=(
  'REWRITE_SPEC'                 # the untracked design document — never referenced
  'manchtools/power-manage-'     # old polyrepo slugs, module paths, and their issues
  '\bADR [0-9]{4}'               # old ADR numbering
)
# Matched case-insensitively — a casing variant must not evade. The
# conventions lint and its self-test carry these literals as matcher
# data/fixtures; those two files are exempt from THIS group only and
# stay scanned for external references above.
ATTRIBUTION_PATTERNS=(
  'Co-Authored-By'
  'noreply@anthropic\.com'
  'claude\.com/claude-code'
)

FAIL=0

scan() { # scan <grep matcher flags> <pattern> <extra grep args...>
  local flags="$1" p="$2" hits rc
  shift 2
  # grep exit codes: 0 = hits (finding), 1 = clean, >1 = grep itself failed.
  # Conflating "grep broke" with "clean" would make this guard fail open.
  hits=$(grep -rIn "$flags" "$p" . \
    --exclude-dir=.git --exclude-dir=.claude --exclude-dir=node_modules \
    --exclude-dir=bin --exclude-dir=dist \
    --exclude=CLAUDE.md --exclude=.gitignore --exclude=check-self-contained.sh \
    "$@")
  rc=$?
  if [ "$rc" -gt 1 ]; then
    printf '\nGUARD ERROR: grep failed (exit %s) on pattern: %s\n' "$rc" "$p"
    FAIL=1
  elif [ "$rc" -eq 0 ]; then
    printf '\nFORBIDDEN external reference (pattern: %s):\n%s\n' "$p" "$hits"
    FAIL=1
  fi
}

for p in "${EXTERNAL_PATTERNS[@]}"; do
  scan -E "$p"
done
for p in "${ATTRIBUTION_PATTERNS[@]}"; do
  scan -iE "$p" --exclude=check-conventions.sh --exclude=check-conventions_test.sh
done

if [ "$FAIL" -ne 0 ]; then
  echo
  echo "self-contained check FAILED — inline the rationale instead of referencing it."
  exit 1
fi
echo "self-contained: OK"
