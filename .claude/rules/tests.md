---
paths:
  - "**/*_test.go"
---

# Test quality

Tests assert INTENT (the spec's acceptance criteria), never implementation
details. A green suite that exercises stubs proves nothing.

- **Real Postgres** via testcontainers (shared container per package binary,
  template-cloned per test). Never mock the database.
- **Real handlers** with the real store — the handler test proves validation
  and authorization actually run. A mocked authorization layer proves the
  mock.
- **Correct / absent / wrong** for every request field; the wrong case must
  violate the field's actual constraint, not a strawman.
- **A rejection test per authorization gate**: unauthenticated, wrong
  permission, out-of-scope grant, cross-actor → NotFound (never
  PermissionDenied).
- One scenario per test function, `Test<Method>_<Scenario>`; a complementary
  positive-path sanity check inside a rejection test is the one exception.
- Every new test is OBSERVED failing, for the right reason, before the
  implementation lands. Bug fix ⇒ regression test that fails on the buggy
  version.
- Rejection / first-transition / empty-result / malformed-input paths run
  against the real backend — the uncovered edge is a likely-broken path.
- **Never weaken an existing test to make it pass** (see CLAUDE.md — a
  failing test is a finding). Guards: name them `TestGuard_<Invariant>`,
  self-discovering population, matches-zero protected (see the `guards`
  skill).
