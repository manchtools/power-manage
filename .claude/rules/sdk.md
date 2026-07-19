---
paths:
  - "sdk/**"
---

# SDK module

- **Mechanism, never policy.** The SDK exposes OS capability; callers decide
  what to do with it. No allow/deny decisions, no name-list identity checks
  (key on UID 0, not "root").
- Proto-free and imports nothing in-repo (INV-19) — a `contract` import here
  is an architecture AND license violation.
- Capability comes from probing (which backends exist on this host), not
  from distro name switches.
- Package-var seams on everything that touches the host, so callers and
  tests can stub without interfaces.
- Tests that exercise real package managers / systemd / filesystems run
  INSIDE per-distro containers — never host-proxied, never recorded output.
- Parsers force the C locale on any command output they read; CI runs a
  non-English-locale lane (ja_JP/zh_CN) to prove it.
- Command construction rejects argv injection structurally (values starting
  with `-`, embedded separators) — validated before the seam, not after.
