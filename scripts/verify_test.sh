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

write_empty_module() {
  local root="$1" name="$2"
  mkdir -p "$root/$name"
  printf 'module fixture/%s\n\ngo 1.26\n' "$name" > "$root/$name/go.mod"
}

# run_verify <fixture-root> <out-file>; global RC carries the exit code.
RC=0
run_verify() {
  local dir="$1" out="$2"
  RC=0
  (cd "$dir" && PATH="$dir/.test-bin:$PATH" PM_VERIFY_SKIP_SELFTEST=1 VERIFY_LOG="$out.log" "$VERIFY") \
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

# Scenario 6: module discovery must survive a large file census. The skip
# predicate once piped find into `grep -q`, which exits at its first match;
# under pipefail the SIGPIPE that kills find made the whole pipeline "fail",
# and a module with a hundred sources was silently skipped as "no Go sources
# yet" — a fail-open gate (this repo's own sdk module hit exactly this). The
# census is sized past the pipe capacity plus grep's first read, so the old
# predicate lost the race deterministically, not flakily.
FIX6="$WORK/fix6"
for m in m1 m2 m3 m4; do write_module "$FIX6" "$m" ok; done
PAD="$(printf 'a%.0s' $(seq 1 220))"
for i in $(seq 1 700); do
  printf 'package m1\n' > "$FIX6/m1/census_${PAD}_${i}.go"
done
run_verify "$FIX6" "$WORK/s6.out"
if [ "$RC" -eq 0 ] && grep -q 'm1: go test' "$WORK/s6.out" \
   && ! grep -q 'm1: no Go sources' "$WORK/s6.out"; then
  pass "large-census module is still discovered and tested (no SIGPIPE skip)"
else
  flunk "large census: want exit 0 + 'm1: go test', got exit $RC"
  dump_on_flunk "$WORK/s6.out"
fi

# Scenario 7: generated-code verification must never mutate committed output,
# even when the generator deletes its target and then fails.
FIX7="$WORK/fix7"
for m in contract m2 m3 m4; do write_empty_module "$FIX7" "$m"; done
mkdir -p "$FIX7/contract/proto" "$FIX7/contract/gen" "$FIX7/.test-bin"
printf 'version: v2\nclean: true\n' > "$FIX7/contract/buf.yaml"
printf 'syntax = "proto3";\n' > "$FIX7/contract/proto/x.proto"
printf 'committed\n' > "$FIX7/contract/gen/stable.txt"
cat > "$FIX7/.test-bin/buf" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = lint ]; then exit 0; fi
out=.
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then out="$2"; shift 2; continue; fi
  shift
done
rm -rf "$out/gen"
exit 42
EOF
chmod +x "$FIX7/.test-bin/buf"
run_verify "$FIX7" "$WORK/s7.out"
if [ "$RC" -ne 0 ] \
   && grep -q 'FAIL: contract: generated code in sync' "$WORK/s7.out" \
   && [ "$(cat "$FIX7/contract/gen/stable.txt" 2>/dev/null)" = committed ]; then
  pass "failed Buf generation leaves committed output unchanged"
else
  flunk "failed Buf generation: want nonzero exit and intact contract/gen, got exit $RC"
  dump_on_flunk "$WORK/s7.out"
fi

# Scenario 8: docref is a strict, non-vacuous gate when configured.
FIX8="$WORK/fix8"
for m in m1 m2 m3 m4; do write_empty_module "$FIX8" "$m"; done
mkdir -p "$FIX8/.test-bin"
printf '[check]\nlevel = "strict"\n' > "$FIX8/docref.toml"
cat > "$FIX8/.test-bin/docref" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = check ]; then exit 0; fi
if [ "$1" = ls ]; then printf '{"refs":[]}\n'; exit 0; fi
exit 2
EOF
chmod +x "$FIX8/.test-bin/docref"
run_verify "$FIX8" "$WORK/s8.out"
if [ "$RC" -ne 0 ] && grep -Eqi 'docref.*(zero|reference)|(zero|reference).*docref' "$WORK/s8.out"; then
  pass "zero docref references fail the gate"
else
  flunk "zero docref floor: want nonzero exit naming docref references, got exit $RC"
  dump_on_flunk "$WORK/s8.out"
fi

# Scenario 9: docref drift fails even when the index is non-empty.
FIX9="$WORK/fix9"
for m in m1 m2 m3 m4; do write_empty_module "$FIX9" "$m"; done
mkdir -p "$FIX9/.test-bin"
printf '[check]\nlevel = "strict"\n' > "$FIX9/docref.toml"
cat > "$FIX9/.test-bin/docref" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = check ]; then exit 1; fi
if [ "$1" = ls ]; then printf '{"refs":[{"ref":"x"}]}\n'; exit 0; fi
exit 2
EOF
chmod +x "$FIX9/.test-bin/docref"
run_verify "$FIX9" "$WORK/s9.out"
if [ "$RC" -ne 0 ] && grep -q 'FAIL: documentation: docref' "$WORK/s9.out"; then
  pass "stale docref claim fails the gate"
else
  flunk "stale docref: want nonzero exit naming the docref stage, got exit $RC"
  dump_on_flunk "$WORK/s9.out"
fi

# Scenario 10: sqlc drift verification runs its generator in a temporary copy.
# A generator that deletes its output and fails must leave the committed query
# layer untouched while still making the gate fail.
FIX10="$WORK/fix10"
for m in agent contract sdk server; do write_empty_module "$FIX10" "$m"; done
mkdir -p "$FIX10/server/internal/store/migrations" \
  "$FIX10/server/internal/store/queries" \
  "$FIX10/server/internal/store/generated" \
  "$FIX10/.test-bin"
cp "$SCRIPT_DIR/../server/Makefile" "$FIX10/server/Makefile"
printf 'version: "2"\n' > "$FIX10/server/internal/store/sqlc.yaml"
printf '%s\n' '-- schema fixture' > "$FIX10/server/internal/store/migrations/001.sql"
printf '%s\n' '-- query fixture' > "$FIX10/server/internal/store/queries/query.sql"
printf 'committed\n' > "$FIX10/server/internal/store/generated/stable.txt"
cat > "$FIX10/.test-bin/docker" <<'EOF'
#!/usr/bin/env bash
mount=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = -v ]; then mount="$2"; shift 2; continue; fi
  shift
done
host="${mount%%:*}"
if [ -n "$host" ]; then rm -rf "$host/generated"; fi
exit 42
EOF
chmod +x "$FIX10/.test-bin/docker"
run_verify "$FIX10" "$WORK/s10.out"
if [ "$RC" -ne 0 ] \
   && grep -q 'FAIL: server: generated SQL in sync' "$WORK/s10.out" \
   && [ "$(cat "$FIX10/server/internal/store/generated/stable.txt" 2>/dev/null)" = committed ]; then
  pass "failed sqlc generation leaves committed output unchanged"
else
  flunk "failed sqlc generation: want nonzero exit and intact generated output, got exit $RC"
  dump_on_flunk "$WORK/s10.out"
fi

ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if grep -q '@latest' "$ROOT/.github/workflows/ci.yml"; then
  flunk "CI verification tools float on @latest"
else
  pass "CI verification tool versions are pinned"
fi
if grep -Eq 'DOCREF_VERSION: "?v[0-9]+\.[0-9]+\.[0-9]+"?$' "$ROOT/.github/workflows/ci.yml" \
   && grep -q 'docref-linux-x64' "$ROOT/.github/workflows/ci.yml"; then
  pass "CI installs a pinned docref release"
else
  flunk "CI does not install a pinned docref release"
fi
if grep -q 'run `buf breaking`' "$ROOT/.claude/rules/contract.md"; then
  flunk "contract contributor rule contradicts SPEC-003 AC-13"
else
  pass "contract contributor rule matches the no-buf-breaking decision"
fi
if grep -Eq 'go build ./server/cmd|go build ./agent/cmd' "$ROOT/README.md"; then
  flunk "README presents unimplemented binaries as buildable"
else
  pass "README labels unimplemented binaries as planned"
fi

echo
if [ "$FAILURES" -ne 0 ]; then
  echo "verify_test: FAILED"
  exit 1
fi
echo "verify_test: OK"
