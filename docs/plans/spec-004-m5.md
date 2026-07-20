# SPEC-004 M5 — Crypto (`sdk/crypto`)

Milestone: SPEC-004 §9 M5 **[SDK-13, SDK-14]**, AC-16/AC-17 (spec `docs/content/01-specs/004-sdk-core.md`).
Type: **trust-boundary** — the failing tests are authored by the `test-writer` agent before implementation.
Builds-on: M1 (guards G-3/G-5/G-6, dormant), M4 done. New branch `spec-004-m5-crypto` off merged main.
Port source: predecessor `../power-manage/sdk/crypto/` (stdlib-only crypto).

## Scope

`sdk/crypto` — the SDK's sole seal/open implementation (SPEC-003 AC-8: `contract`
defines only message shape + info constants; **all crypto lives here**). Stdlib
`crypto/*` only (Go 1.26 has `crypto/ecdh`, `crypto/hkdf`, `crypto/aes`,
`crypto/cipher`, `crypto/sha256`, `crypto/rand`, `crypto/subtle`,
`crypto/hmac`). **No new deps, no `x/crypto`, no in-repo imports (INV-19/G-8).**

In scope (AC-16, AC-17): AES-256-GCM AEAD surface; X25519+HKDF-SHA256+AES-256-GCM
sealed transport; mandatory-non-empty-AAD API (no nil-AAD form exists); mandatory
non-empty `info` (domain separation); **symmetric empty-key AND empty-plaintext
rejection at seal AND open** (SDK-14/WIRE-25 — a behavior change from the
predecessor, which allowed empty plaintext); constant-time compares; length-
prefix/domain-separation preimage framing helper; `crypto/rand` error propagation
(fail closed). Arm dormant guards G-3, G-5, G-6.

Deferred (recorded, non-material):
- **Folding `fetch/fetch.go`'s sha256 pin digest into `sdk/crypto`** (the G-5
  `hashImportAllow["crypto/sha256"] → "fetch/fetch.go"` sunset). The allowlist
  entry stays valid (fetch still imports sha256; the orphan check passes), so
  this is hygiene, not correctness — folded when M5's digest helper has a second
  consumer, to avoid a cross-package refactor risking a half-applied change.
- `ulidx` ULID generator ([SDK-13] "IDs are ULIDs via `ulidx`"). No ULID
  minting happens in the seal/open surface; the generator has no consumer this
  milestone and nothing to port. Built when a caller needs to mint IDs.

## Package layout — new `sdk/crypto` (package 10; bump the floor 9→10)

- `crypto.go` — package doc, error sentinels, `constantTimeEqual` (subtle),
  `framePreimage` (length-prefix + domain-separation helper), the `randReader`
  seam.
- `aead.go` — `SealWithAAD` / `OpenWithAAD` (AES-256-GCM).
- `seal.go` — `GenerateX25519`, `ParseX25519PublicKey`, `SealToPublicKey`,
  `OpenWithPrivateKey`, the `Sealed` output struct.
- `*_test.go` peers (**test-writer authors these first**).

Floor: `sdk/guardtest/imports.go` `modulePackageFloors["sdk"]` **9 → 10**.

## API surface

### `aead.go` — symmetric AES-256-GCM
| Fn | Signature | Behavior |
|---|---|---|
| `SealWithAAD` | `(key, plaintext, aad []byte) ([]byte, error)` | key must be 32 bytes (`ErrInvalidKey`); `aad` non-empty (`ErrAADRequired`); **plaintext non-empty (`ErrEmptyPlaintext`)**. Fresh random 96-bit nonce (via `randReader`), output `nonce(12)‖ct‖tag(16)`. |
| `OpenWithAAD` | `(key, ciphertext, aad []byte) ([]byte, error)` | same key/aad rejects; `len < 12+16` → `ErrMalformedCiphertext`; GCM open; a decrypt to **empty** plaintext is rejected symmetrically (`ErrEmptyPlaintext`). |

### `seal.go` — X25519+HKDF-SHA256+AES-256-GCM sealed transport
| Fn | Signature | Behavior |
|---|---|---|
| `GenerateX25519` | `() (*ecdh.PrivateKey, error)` | X25519 keypair via `randReader`. |
| `ParseX25519PublicKey` | `(raw []byte) (*ecdh.PublicKey, error)` | exactly 32 bytes. |
| `SealToPublicKey` | `(recipient *ecdh.PublicKey, plaintext, aad []byte, info string) (Sealed, error)` | reject empty `info` (`ErrInfoRequired`), empty `aad`, empty `plaintext`. Ephemeral keygen; `shared = ECDH(eph.priv, recipient)`; `salt = framePreimage("pm-seal-salt:v1", eph.pub, recipient.bytes)`; `key = hkdf.Key(sha256.New, shared, salt, info, 32)`; `SealWithAAD(key, plaintext, aad)`. Returns `Sealed{EphemeralPublicKey(32), Ciphertext(nonce‖ct‖tag)}` — the two byte fields of contract `SealedBlob`. |
| `OpenWithPrivateKey` | `(priv *ecdh.PrivateKey, sealed Sealed, aad []byte, info string) ([]byte, error)` | reject nil `priv` and empty `info`/`aad`; parse `EphemeralPublicKey` (32); recompute `shared = ECDH(priv, ephPub)` and the **identical** salt `framePreimage("pm-seal-salt:v1", ephPub, priv.PublicKey().Bytes())` — the recipient bytes are the private key's own public key, so seal and open derive the same key — then identical HKDF; `OpenWithAAD`. Fail closed (error, no plaintext) on AAD/info/context mismatch or malformed input. |

`Sealed` maps 1:1 to `contract.SealedBlob{ephemeral_public_key, ciphertext}`; the
caller (server/agent, out of scope) reads the info/context constants from
`contract/seal` and passes them as `info`/`aad` — the SDK stays proto-free.

### `crypto.go` — helpers
- `var ErrInvalidKey, ErrAADRequired, ErrEmptyPlaintext, ErrInfoRequired, ErrMalformedCiphertext error`.
- `func framePreimage(domain string, parts ...[]byte) []byte` — writes the domain
  tag **and** each part as `uvarint(len)‖bytes` (the domain is length-prefixed too,
  so a part can never be absorbed into the domain), so no two distinct
  `(domain, parts)` inputs collide ([SDK-13] "every hash/MAC preimage is
  length-prefixed and domain-separated, always"). This is the salt constructor for
  HKDF and the one framing chokepoint.
- `func constantTimeEqual(a, b []byte) bool` — `subtle.ConstantTimeCompare`==1;
  the only secret/MAC compare primitive (AC-17). (GCM tag verification is already
  constant-time inside `cipher.AEAD.Open`.)
- `var randReader io.Reader = rand.Reader` — the single RNG seam. Nonce reads use
  `io.ReadFull(randReader, …)`. **Keygen reads 32 bytes via `io.ReadFull(randReader,
  b[:])` then `ecdh.X25519().NewPrivateKey(b)`** — NOT `GenerateKey(randReader)`,
  which in Go 1.26 ignores its reader argument (internal FIPS DRBG, 0 bytes read,
  no error even on a failing reader; verified empirically), and so could not honor
  the seam or propagate an RNG failure. `NewPrivateKey` accepts any 32 random bytes
  (X25519 clamps internally). A read error is wrapped and returned (fail closed;
  never a predictable nonce/key) — AC-17 "crypto/rand read errors propagate".
  Tests override the seam with a failing reader.

## Guard activation (dormant → live)

- **G-3 (`TestGuard_Randomness`)** — re-point the matches-zero floor from
  `sdkGoFiles ≥ 1` to **≥1 crypto call site in `sdk/crypto`** now that the package
  exists (`randJitterAllow` stays empty; no `math/rand` in `sdk/crypto`).
- **G-5 (`TestGuard_PreimageFraming`)** — extend beyond the M1 import-ban:
  discover the hash/MAC preimage construction(s) in `sdk/crypto` and assert each
  routes through `framePreimage`. Keep the `fetch/fetch.go` sha256 allowlist entry
  (deferred fold above) so the orphan check still passes.
- **G-6 (`TestGuard_SealAADSurface`)** — auto-arms the moment `sdk/crypto/`
  exists. Every exported `*Seal*`/`*Open*` func has a parameter **named exactly
  `aad`** (`SealWithAAD`, `OpenWithAAD`, `SealToPublicKey`, `OpenWithPrivateKey`
  all comply), and ≥1 such export exists (floor met).

## Scenario matrix (AC-16, AC-17) — test-writer authors red first

AEAD:
- `SealWithAAD`/`OpenWithAAD` **round-trip** a non-empty plaintext under a 32-byte key + non-empty AAD.
- **Empty symmetry**: seal rejects empty plaintext, empty key, empty AAD; open rejects the same — *symmetrically* (a value seal rejects, open must reject; SDK-14).
- **Wrong AAD** at open → error, no plaintext (fail closed).
- **Wrong key** at open → error.
- **Malformed/truncated** ciphertext (`< 12+16`) → `ErrMalformedCiphertext`.
- **Tamper**: flip a ciphertext/tag byte → open errors.
- **Nonce freshness**: two seals of the same input yield different nonces/outputs.

Sealed transport:
- `SealToPublicKey`/`OpenWithPrivateKey` **round-trip** under X25519+HKDF+GCM with a mandated info string (`power-manage-lps-password:v1` used as a representative value — passed as a param, not imported).
- **Fail closed** on: wrong recipient private key; **AAD mismatch**; **wrong info string** (domain-separation → different HKDF key → open fails); tampered ephemeral pubkey or ciphertext.
- Empty `info`, empty `aad`, empty `plaintext` rejected at **both** seal and open.
- `ParseX25519PublicKey` rejects non-32-byte input.
- **Interop**: `Sealed.EphemeralPublicKey` is exactly 32 bytes; `Ciphertext` is `≥ 12+16+1`.

Helpers:
- `framePreimage` is **unambiguous**: `frame(d, ["a","bc"]) != frame(d, ["ab","c"])` and a different domain changes the output.
- `constantTimeEqual` matches `subtle` semantics (equal → true; any diff/length → false).
- **`crypto/rand` failure**: with `randReader` stubbed to a failing reader, `SealWithAAD` and `GenerateX25519`/`SealToPublicKey` return the wrapped error — never a zero/predictable nonce or key (AC-17).

## Verification
- Red first: test-writer authors `*_test.go`; each observed failing (package/stubs absent or accept-all) for the right reason before impl.
- `./scripts/verify.sh` (gofmt, vet, staticcheck, guards incl. G-3/G-5/G-6 live + bumped floor, all module tests) + `go test -C sdk ./... -race`.
- Ledger `00-index.md`: append the M5 row; line 23 status stays `In progress (M5 done)`.
