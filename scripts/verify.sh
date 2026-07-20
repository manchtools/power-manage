#!/usr/bin/env bash
# Canonical verification gate (SPEC-000 AC-1, G-000-4). Run from the repo root
# before every commit. All output is tee'd to a log; never judge by the tail
# of a truncated stream.
set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${VERIFY_LOG:-/tmp/pm-verify-$$.log}"
FAILED=0

say()  { printf '\n==> %s\n' "$*" | tee -a "$LOG"; }
fail() { echo "FAIL: $*" | tee -a "$LOG"; FAILED=1; }

run() {
  local desc="$1"; shift
  say "$desc"
  if ! "$@" 2>&1 | tee -a "$LOG"; then
    fail "$desc"
  fi
}

# A required tool that is missing is a failure, never a silent skip — a gate
# with a stage quietly disabled is fail-open (INV-1/INV-3 doctrine).
require() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 not installed — required by the gate"
}

# Module walk: discovered from the repo layout, never hand-maintained (META-2).
MODULES=()
while IFS= read -r modfile; do
  MODULES+=("$(dirname "${modfile#./}")")
done < <(find . -mindepth 2 -maxdepth 2 -name go.mod -not -path './.*' | sort)

# Matches-zero floor (G-000-4): the repo has four modules; discovering fewer
# means discovery broke, not that there is nothing to check.
if [ "${#MODULES[@]}" -lt 4 ]; then
  fail "module discovery found ${#MODULES[@]} module(s); floor is 4"
fi

if [ "${#MODULES[@]}" -gt 0 ]; then
  say "modules: ${MODULES[*]}"
  require staticcheck

  # gofmt: fail on any diff or parse error (generated code under gen/ exempt).
  say "gofmt"
  if ! GOFMT_OUT=$(gofmt -l "${MODULES[@]}" 2>&1); then
    fail "gofmt — parse error"
  fi
  UNFORMATTED=$(grep -v '/gen/' <<<"$GOFMT_OUT" || true)
  if [ -n "$UNFORMATTED" ]; then
    fail "gofmt — unformatted or unparseable files:"
    echo "$UNFORMATTED" | tee -a "$LOG"
  fi

  for m in "${MODULES[@]}"; do
    # Modules with no Go sources yet (scaffold phase): reported, not hidden.
    if ! find "$m" -name '*.go' -not -path '*/gen/*' | grep -q .; then
      say "$m: no Go sources yet — skipped (reported, not hidden)"
      continue
    fi
    run "$m: go vet"        go vet -C "$m" ./...
    run "$m: staticcheck"   env -C "$m" staticcheck ./...
    run "$m: go test"       go test -C "$m" ./... -count=1 -race

    # Dormant guards are reported, not hidden: without -v a skipped
    # TestGuard_* is invisible in go test output, so surface any here.
    GUARD_SKIPS=$(go test -C "$m" ./... -count=1 -run 'TestGuard_' -v 2>/dev/null | grep '^--- SKIP: TestGuard_' || true)
    if [ -n "$GUARD_SKIPS" ]; then
      say "$m: dormant guards (reported, not hidden)"
      echo "$GUARD_SKIPS" | tee -a "$LOG"
    fi
  done
fi

# Proto lint + generated-code sync (only once protos exist). Deliberately
# NO buf-breaking gate: proto evolution re-tags in place with no reserved
# markers (AC-13, SPEC-003) — exactly what a breaking gate would reject.
if [ -f contract/buf.yaml ] && find contract/proto -name '*.proto' 2>/dev/null | grep -q .; then
  require buf
  if command -v buf >/dev/null 2>&1; then
    run "contract: buf lint" env -C contract buf lint
    # Regeneration must be a no-op against the working tree: a stale or
    # hand-edited gen/ changes under buf generate and fails here; CI runs
    # this against the committed state, so forgetting to commit gen/ fails
    # there ([WIRE-2] machine-readable tags depend on gen matching source).
    run "contract: generated code in sync" bash -c '
      cd contract || exit 1
      snapshot() { find gen -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum | sha256sum; }
      before=$(snapshot)
      buf generate || exit 1
      after=$(snapshot)
      if [ "$before" != "$after" ]; then
        echo "contract/gen was out of sync with the proto sources — buf generate changed it; commit the regenerated output and never hand-edit it (AC-13, SPEC-003)"
        exit 1
      fi'
  fi
fi

# The gate tests itself. PM_VERIFY_SKIP_SELFTEST=1 is the explicit named
# bypass the self-test uses when invoking this script against fixtures.
if [ "${PM_VERIFY_SKIP_SELFTEST:-0}" != "1" ]; then
  run "scripts: verify.sh self-test" "$SCRIPT_DIR/verify_test.sh"
  run "scripts: conventions self-test" "$SCRIPT_DIR/check-conventions_test.sh"
fi

say "result"
if [ "$FAILED" -ne 0 ]; then
  echo "VERIFY FAILED — full log: $LOG" | tee -a "$LOG"
  exit 1
fi
echo "VERIFY OK — full log: $LOG" | tee -a "$LOG"
