# Power Manage

Linux device management: declarative desired state, offline-autonomous agents,
event-sourced control plane, compliance evidence as a first-class product.

This is the canonical monorepo. The web UI lives in a separate repository and is
explicitly out of scope here.

## Modules

| Directory   | What it is                                                       | License   |
|-------------|------------------------------------------------------------------|-----------|
| `contract/` | Protobuf sources and generated Go/TS — the wire contract         | MIT       |
| `sdk/`      | Pure OS capability library (mechanism, never policy; no proto)   | MIT       |
| `server/`   | Control server, gateway binary, event store, PKI                 | AGPL-3.0  |
| `agent/`    | Device agent (static binary, runs as root, offline scheduler)    | GPL-3.0   |

Each module directory carries its own `LICENSE` file, which is authoritative for
that subtree. **Everything outside the four module directories** — this README,
`go.work`, CI workflows, `scripts/`, `install.sh`, and all other root-level
tooling — **is licensed under the MIT License** (see `contract/LICENSE` for the
text, applied to these files with the same copyright holder).

Dependency direction is one-way and guarded: `contract` and `sdk` import no
in-repo module; `agent` and `server` import only `contract` and `sdk`. This is
simultaneously the architecture boundary and the licensing boundary.

## Development

Everything is spec-driven. Start here:

1. [`docs/content/01-specs/00-index.md`](docs/content/01-specs/00-index.md) — the spec series, build
   order, and implementation status ledger.
2. [`docs/content/01-specs/000-development-process.md`](docs/content/01-specs/000-development-process.md)
   — the mandatory pipeline: spec → failing tests → implementation → verification.
3. [`docs/content/02-decisions/01-operator-decisions.md`](docs/content/02-decisions/01-operator-decisions.md) — preserved operator decisions.
   These are final; do not re-litigate them.

<!-- docref: begin src=scripts/verify.sh:ad5bd804 -->
Verification gate (run before every commit):

```bash
./scripts/verify.sh
```
<!-- docref: end -->

## Planned binaries

The control, gateway, and agent binaries land with SPEC-005, SPEC-012, and
SPEC-013. The current implemented surface is the `contract` and `sdk` library
foundation; use the verification gate above until those binary milestones land.

Versioning: `vYYYY.MM.PP`. Conventional commits.
