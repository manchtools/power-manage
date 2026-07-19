---
paths:
  - "agent/**"
---

# Agent module

- Runs as root; ships as ONE static binary (`CGO_ENABLED=0`); hardening via
  unit directives + MAC, never a user switch.
- **Executes no system binary directly** — every OS interaction goes through
  the SDK probe (AG-12a). A raw `exec.Command` here is a finding.
- Offline autonomy is the product: no staleness kill-switch; the last
  CA-signed manifest keeps applying indefinitely. The signed manifest is the
  ONLY desired-state source.
- The unit reconciler never restarts the agent's own unit; SERVICE actions
  refuse `power-manage-agent.service`.
- Verify before acting: command signature (domain, identity, freshness),
  artifact digest at the fetch chokepoint, CRL freshness rules — all
  fail-closed.
- Key custody: mTLS and X25519 sealing private keys are 0600 root and never
  leave the device; sealed secrets are unsealed in memory at apply time only.
- The enrollment socket is mode 0666 DELIBERATELY (operator decision,
  reversed twice) — the registration token is the authorization; do not
  tighten.
- Reboot/shutdown test paths must never reach a real shutdown binary — the
  container boundary is the verified safety net.
