---
paths:
  - "contract/**"
---

# Contract module (protos)

- **No `reserved` markers** — re-tag in place. V1 makes clean breaks: no
  compat shims, no deprecation aliases.
- Every boundary-crossing field carries a validate tag (type, format, length,
  range). Booleans whose absence differs from `false` use explicit-presence
  (`optional`).
- ONE ActionParams registry — a new action type registers there; no parallel
  parameter unions.
- `buf lint` clean; run `buf breaking` and justify intentional breaks in the
  PR description.
- Generated output (`gen/`) is never hand-edited; regenerate with
  `buf generate`.
- This module imports nothing in-repo (INV-19) and stays MIT — it is a
  dependency leaf both architecturally and license-wise.
- The generated TS contract is published as a package per release — TS
  consumers exist; don't break JSON names casually.
