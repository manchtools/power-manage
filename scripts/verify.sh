#!/usr/bin/env bash
# Canonical verification gate. Run from the repo root before every commit.
# All output is tee'd to a log; never judge by the tail of a truncated stream.
set -u -o pipefail

LOG="${VERIFY_LOG:-/tmp/pm-verify-$$.log}"
FAILED=0

say() { printf '\n==> %s\n' "$*" | tee -a "$LOG"; }

run() {
  local desc="$1"; shift
  say "$desc"
  if ! "$@" 2>&1 | tee -a "$LOG"; then
    echo "FAIL: $desc" | tee -a "$LOG"
    FAILED=1
  fi
}

MODULES=(contract sdk server agent)

# gofmt: fail on any diff
say "gofmt"
UNFORMATTED=$(gofmt -l "${MODULES[@]}" 2>/dev/null | grep -v '/generated/' || true)
if [ -n "$UNFORMATTED" ]; then
  echo "FAIL: gofmt — unformatted files:" | tee -a "$LOG"
  echo "$UNFORMATTED" | tee -a "$LOG"
  FAILED=1
fi

for m in "${MODULES[@]}"; do
  # Skip modules that have no Go files yet (scaffold phase).
  if ! find "$m" -name '*.go' -not -path '*/generated/*' | grep -q .; then
    say "$m: no Go sources yet — skipped (reported, not hidden)"
    continue
  fi
  run "$m: go vet"          go vet -C "$m" ./...
  if command -v staticcheck >/dev/null 2>&1; then
    run "$m: staticcheck"   env -C "$m" staticcheck ./...
  else
    echo "SKIP: staticcheck not installed" | tee -a "$LOG"
  fi
  run "$m: go test"         go test -C "$m" ./... -count=1
done

# Proto lint + breaking (only once protos exist)
if [ -f contract/buf.yaml ] && find contract/proto -name '*.proto' 2>/dev/null | grep -q .; then
  if command -v buf >/dev/null 2>&1; then
    run "contract: buf lint" env -C contract buf lint
    if git -C . rev-parse --verify origin/main >/dev/null 2>&1; then
      run "contract: buf breaking" env -C contract buf breaking --against "../.git#branch=origin/main,subdir=contract"
    fi
  else
    echo "SKIP: buf not installed" | tee -a "$LOG"
  fi
fi

say "result"
if [ "$FAILED" -ne 0 ]; then
  echo "VERIFY FAILED — full log: $LOG" | tee -a "$LOG"
  exit 1
fi
echo "VERIFY OK — full log: $LOG" | tee -a "$LOG"
