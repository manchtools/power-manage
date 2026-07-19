#!/usr/bin/env bash
# Tests for scripts/verify.sh (SPEC-000 §6.2, G-000-4). Runs the gate against
# generated fixture repos in a temp dir — never against this repository.
# Scenarios: a failing check propagates to a nonzero exit; a module added to
# the repo is picked up without editing the script; module discovery has a
# matches-zero floor.
set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$SCRIPT_DIR/verify.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
pass()  { echo "ok   - $*"; }
flunk() { echo "FAIL - $*"; FAILURES=1; }

# write_module <fixture-root> <name> <ok|failing>
write_module() {
  local root="$1" name="$2" kind="$3"
  mkdir -p "$root/$name"
  printf 'module fixture/%s\n\ngo 1.26\n' "$name" > "$root/$name/go.mod"
  cat > "$root/$name/lib.go" <<EOF
package $name

func Ok() bool { return true }
EOF
  if [ "$kind" = failing ]; then
    cat > "$root/$name/lib_test.go" <<EOF
package $name

import "testing"

func TestOk(t *testing.T) {
	if Ok() {
		t.Fatal("planted failure: fixture module $name")
	}
}
EOF
  else
    cat > "$root/$name/lib_test.go" <<EOF
package $name

import "testing"

func TestOk(t *testing.T) {
	if !Ok() {
		t.Fatal("Ok() = false")
	}
}
EOF
  fi
}

# run_verify <fixture-root> <out-file>; global RC carries the exit code.
RC=0
run_verify() {
  local dir="$1" out="$2"
  RC=0
  (cd "$dir" && PM_VERIFY_SKIP_SELFTEST=1 VERIFY_LOG="$out.log" "$VERIFY") \
    > "$out" 2>&1 || RC=$?
}

dump_on_flunk() { # <out-file> — full output, never truncated
  echo "--- captured gate output ($1):"
  cat "$1"
  echo "--- end of captured gate output"
}

# Scenario 1: four passing modules — gate is green and every module's test
# stage actually ran (discovery found them all).
FIX1="$WORK/fix1"
for m in m1 m2 m3 m4; do write_module "$FIX1" "$m" ok; done
run_verify "$FIX1" "$WORK/s1.out"
if [ "$RC" -eq 0 ] \
   && grep -q 'm1: go test' "$WORK/s1.out" \
   && grep -q 'm2: go test' "$WORK/s1.out" \
   && grep -q 'm3: go test' "$WORK/s1.out" \
   && grep -q 'm4: go test' "$WORK/s1.out"; then
  pass "green fixture exits 0 and runs every discovered module's tests"
else
  flunk "green fixture: want exit 0 + a test stage per module, got exit $RC"
  dump_on_flunk "$WORK/s1.out"
fi

# Scenario 2: an injected failing check propagates to a nonzero exit.
FIX2="$WORK/fix2"
for m in m1 m2 m4; do write_module "$FIX2" "$m" ok; done
write_module "$FIX2" m3 failing
run_verify "$FIX2" "$WORK/s2.out"
if [ "$RC" -ne 0 ] && grep -q 'FAIL: m3: go test' "$WORK/s2.out"; then
  pass "failing check propagates to a nonzero exit"
else
  flunk "failing check: want nonzero exit + 'FAIL: m3: go test' in output, got exit $RC"
  dump_on_flunk "$WORK/s2.out"
fi

# Scenario 3: a module added to the repo is picked up WITHOUT editing the
# script — its planted failure must turn the gate red.
write_module "$FIX1" m5 failing
run_verify "$FIX1" "$WORK/s3.out"
if [ "$RC" -ne 0 ] && grep -q 'FAIL: m5: go test' "$WORK/s3.out"; then
  pass "newly added module is discovered and its failure turns the gate red"
else
  flunk "added module: want nonzero exit + 'FAIL: m5: go test' in output, got exit $RC"
  dump_on_flunk "$WORK/s3.out"
fi

# Scenario 4: matches-zero floor — discovering fewer than four modules means
# discovery broke, and the gate must fail rather than pass on the remainder.
FIX4="$WORK/fix4"
for m in m1 m2 m3; do write_module "$FIX4" "$m" ok; done
run_verify "$FIX4" "$WORK/s4.out"
if [ "$RC" -ne 0 ] && grep -qi 'module discovery' "$WORK/s4.out"; then
  pass "discovery below the module floor fails the gate"
else
  flunk "discovery floor: want nonzero exit naming module discovery, got exit $RC"
  dump_on_flunk "$WORK/s4.out"
fi

# Scenario 5: a Go file that gofmt cannot parse must fail the gofmt stage
# itself — not slip through to be caught only by later stages.
FIX5="$WORK/fix5"
for m in m1 m2 m3 m4; do write_module "$FIX5" "$m" ok; done
printf 'package m1\n\nfunc Broken( {\n' > "$FIX5/m1/lib.go"
run_verify "$FIX5" "$WORK/s5.out"
if [ "$RC" -ne 0 ] && grep -q 'FAIL: gofmt' "$WORK/s5.out"; then
  pass "unparseable Go file fails the gofmt stage"
else
  flunk "gofmt parse error: want nonzero exit + 'FAIL: gofmt' in output, got exit $RC"
  dump_on_flunk "$WORK/s5.out"
fi

echo
if [ "$FAILURES" -ne 0 ]; then
  echo "verify_test: FAILED"
  exit 1
fi
echo "verify_test: OK"
