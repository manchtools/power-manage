---
name: secure-defaults
description: Security patterns binding on every code change — fail-closed, boundary validation, crypto discipline, no existence leaks, no secret leaks. Activates when writing or reviewing any code.
---

# Secure defaults

Every change is security-relevant. The threat model has five actors: external
unauthenticated, low-privilege user, trusted admin, a compromised
relay/gateway, and an on-path network attacker. Code as if all five are
probing your change.

## Fail closed — always

- Revocation/CRL state unavailable → deny.
- Decode error on persisted security state (grants, certs, envelopes) → deny,
  never "skip and continue".
- Unknown enum value from the wire → reject the message.
- A verifier/signer dependency not wired at boot → refuse to boot, not
  best-effort at request time.
- An authorization helper that returns (allowed, err): err ⇒ NOT allowed.

## Boundary discipline

- Every proto field crossing a trust boundary carries a validate constraint —
  type, format, length, range. `required` alone is insufficient.
- Validate at the interceptor AND in the handler (defense in depth), in
  validate-then-authorize order.
- Every mutation carries the owner/tenant in the WHERE clause AND checks it at
  the handler level.
- Non-owner access returns NotFound uniformly — never PermissionDenied.
  Existence is information.
- Every state-changing RPC is audit-logged; audit failure fails the request,
  not silently the log.

## Crypto discipline

- `crypto/rand` only. `math/rand` for a nonce, key, token, challenge, or ID
  is a finding, full stop.
- Every AEAD/HKDF call carries a domain-separation info tag / AAD. Naked
  calls are findings.
- Signature verification checks the domain tag, the identity binding, AND
  freshness (issued_at/expires_at) — all three, before acting on content.
- Compare secrets with constant-time comparison.
- ULIDs (`crypto/rand` entropy) for identifiers — never UUID.

## Secret hygiene

- Never log: private keys, tokens, passwords, AEAD keys, sealed payloads,
  challenges before consumption, enrollment tokens.
- Secrets never appear in URLs, error messages, events, or panics.
- Secrets read from stdin or file — never argv (visible in /proc), never env
  when a file works.
- At-rest secrets are AEAD-wrapped with AAD binding them to their owner row;
  a ciphertext moved to another row must fail to decrypt.

## Two leak classes that pass review

- **The timing/error oracle**: distinct error messages or measurably distinct
  timing for "not found" vs "not yours" vs "wrong password". Return the same
  code, same message, comparable work.
- **The helpful log line**: a debug log added during development that prints
  a request payload containing a credential. Grep your own diff for log calls
  before committing.
