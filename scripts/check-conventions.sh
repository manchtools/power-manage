#!/usr/bin/env bash
# CI conventions check (SPEC-002 AC-8, G-002-8): conventional commits
# [VER-2], vYYYY.MM.PP tag format [VER-1], no AI attribution [META-4].
# Modes keep the script runnable against fixture repos offline; the
# workflow passes GitHub context in. This file names the attribution
# patterns and is exempt from check-self-contained.sh for that reason.
set -u -o pipefail

SUBJECT_RE='^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\([a-z0-9._/-]+\))?!?: .+'
TAG_RE='^v20[0-9]{2}\.(0[1-9]|1[0-2])\.[0-9]{2}$'
# Test-owned threat model — red/green rows live in
# check-conventions_test.sh; file CONTENTS stay check-self-contained.sh's
# job, this covers commit messages and PR bodies.
ATTR_PATTERNS=(
  'Co-Authored-By'
  'noreply@anthropic\.com'
  'claude\.com/claude-code'
  '[Gg]enerated (with|by) [A-Z]'
  '🤖'
)

fail=0

check_attribution() { # check_attribution <label> <text>
  local p
  for p in "${ATTR_PATTERNS[@]}"; do
    if grep -qE "$p" <<<"$2"; then
      echo "conventions: $1 carries attribution (pattern: $p) [META-4]"
      fail=1
    fi
  done
}

mode="${1:-}"
case "$mode" in
  commits)
    range="${2:?usage: check-conventions.sh commits <range>}"
    mapfile -t shas < <(git rev-list --no-merges "$range")
    if [ "${#shas[@]}" -eq 0 ]; then
      echo "conventions: zero commits examined in range $range — the lint must see at least one commit (G-002-8)"
      exit 1
    fi
    for sha in "${shas[@]}"; do
      subject=$(git log -1 --format=%s "$sha")
      if ! grep -qE "$SUBJECT_RE" <<<"$subject"; then
        echo "conventions: commit ${sha:0:7} subject is not a conventional commit [VER-2]: $subject"
        fail=1
      fi
      check_attribution "commit ${sha:0:7}" "$(git log -1 --format=%B "$sha")"
    done
    ;;
  ci-commits)
    # Workflow entry: resolve the examined range from GitHub context.
    # An empty or unknown base (first/forced push) falls back to the
    # head commit alone — still ≥1 commit examined, never zero.
    base="${2:-}"
    head="${3:?usage: check-conventions.sh ci-commits <base> <head>}"
    if [ -z "$base" ] || ! git cat-file -e "$base" 2>/dev/null; then
      exec "$0" commits "$head~1..$head"
    fi
    exec "$0" commits "$base..$head"
    ;;
  pr-body-file)
    f="${2:?usage: check-conventions.sh pr-body-file <file>}"
    check_attribution "PR body" "$(cat "$f")"
    ;;
  tag)
    t="${2:?usage: check-conventions.sh tag <name>}"
    if ! grep -qE "$TAG_RE" <<<"$t"; then
      echo "conventions: tag $t does not match vYYYY.MM.PP [VER-1]"
      fail=1
    fi
    ;;
  *)
    echo "usage: check-conventions.sh commits <range> | ci-commits <base> <head> | pr-body-file <file> | tag <name>"
    exit 2
    ;;
esac

if [ "$fail" -eq 0 ]; then
  echo "conventions: OK"
fi
exit "$fail"
