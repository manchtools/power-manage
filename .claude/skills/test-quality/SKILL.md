---
name: test-quality
description: What a test must prove and how — real backends, real handlers, correct/absent/wrong triads, rejection paths. Activates when writing or reviewing any test.
---

# Test quality

A green suite that exercises stubs proves nothing. Tests assert INTENT (the
spec's acceptance criteria), never implementation details.

## Non-negotiables

- **Real Postgres** via testcontainers — one shared container per package test
  binary, template-cloned per test. Never mock the database. The un-covered
  edge path run against a mock is a likely-broken path wearing a green badge.
- **Real handlers** — construct the actual handler with the actual store.
  Never stub the thing under test; the handler test proves validation and
  authorization actually run.
- **Correct / absent / wrong** for every request field. The "wrong" case must
  violate the field's actual validate constraint, not a strawman.
- **A rejection test for every authorization gate**: unauthenticated, wrong
  permission, out-of-scope grant, cross-actor (must yield NotFound, not
  PermissionDenied — existence must not leak).
- **One scenario per test function**, named `Test<Method>_<Scenario>`. A
  complementary positive-path sanity check inside a rejection test is the one
  allowed exception.
- **Rejection / first-transition / empty-result / malformed-input paths get
  tests against the real backend.** These edges are where latent bugs live;
  treat every uncovered edge as suspect until a test exercises it.

## SDK / agent specifics

- SDK behaviors that touch real package managers, systemd, or the filesystem
  run INSIDE containers (per-distro lanes) — never host-proxied, never faked
  with recorded output.
- Run integration tests under a non-English locale at least once in CI
  (ja_JP/zh_CN); parsers must force C locale on the Command they read
  (locale-dependent output drift is a recurring real-world failure).
- Reboot/shutdown tests use the real runner but must never reach a real
  `shutdown` binary — the container boundary is the safety net, verified.

## Anti-patterns (findings, not style notes)

- Asserting on internal helper calls instead of observable behavior.
- Table tests where the "wrong" rows don't violate the actual constraint.
- Skipping the red check: every new test observed failing before the
  implementation lands.
- Tests passing because of a shared-fixture accident (order dependence).
- A mocked authorization layer — the test then proves the mock.
- Sub-agent/delegated audit verdicts accepted unverified: "code is correct"
  and "a test proves it" are different claims; re-verify contested findings
  against the actual code and tests yourself.
