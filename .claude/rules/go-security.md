---
paths:
  - "**/*.go"
---

# Security defaults

Five actors are always probing: external unauthenticated, low-privilege user,
trusted admin, compromised relay/gateway, on-path network attacker.

## Fail closed

- Revocation/CRL state unavailable → deny.
- Decode error on persisted security state → deny, never skip-and-continue.
- Unknown enum from the wire → reject the message.
- Verifier/signer not wired at boot → refuse to boot.
- Authorization helper returning (allowed, err): err ⇒ NOT allowed.

## Boundary

- Every boundary-crossing proto field carries a validate constraint (type,
  format, length, range — `required` alone is insufficient).
- Validate at the interceptor AND in the handler; validate-then-authorize
  order.
- Every mutation carries the owner/tenant in the WHERE clause AND checks it
  at the handler.
- Non-owner access returns NotFound uniformly — never PermissionDenied;
  existence is information.
- Every state-changing RPC is audit-logged; audit failure fails the request.

## Crypto

- `crypto/rand` only — `math/rand` for a nonce/key/token/challenge/ID is a
  finding.
- Every AEAD/HKDF call carries a domain-separation info tag / AAD.
- Signature verification checks domain tag, identity binding, AND freshness —
  all three before acting on content.
- Public-key validation isolates standard-library serialization calls that can
  panic on malformed coordinates and converts those panics to validation
  errors; hostile key material must never crash the process.
- Constant-time comparison for secrets. ULIDs for identifiers.

## Secrets

- Never in logs, error messages, events, panics, or argv; authentication,
  session, and enrollment secrets never use URLs; stdin or file indirection
  only.
- Artifact and checksum fetch URLs reject userinfo, matching the repository's
  other URL validators. Query content remains valid unless its governing spec
  says otherwise; strip query and fragment from every error and never log the
  raw URL.
- At-rest secrets are AEAD-wrapped with AAD binding them to their owner row.
- Watch the two leak classes that pass review: the timing/error oracle
  (distinct errors for "not found" vs "not yours") and the helpful debug log
  that prints a credential-bearing payload — grep your own diff for log calls
  before committing.
