# SPEC-004 M4 — Validators (`sdk/validate`)

Milestone: SPEC-004 §3.4 **[SDK-10..12]**, AC-14/AC-15 (spec `docs/content/01-specs/004-sdk-core.md`).
Type: **mechanical** — the scenario matrix is authored here; row tests are written from it.
Builds-on: M1 (guards), M2 (Runner argv discipline), M3 (fsafe path grammar). New branch off merged main.

## Scope split (rollback-and-fail)

[SDK-11]/AC-14 says "a tool error naming the SDK-written file triggers rollback-and-fail."
The **file-restore machinery** (write candidate → validate → swap → restore-on-failure) is the
**M7 policy-file engine** ([SDK-18], §3.7, AC-21/22) — explicitly a later milestone. M4 ships the
two M4-appropriate pieces: (a) **pre-write rejection** so a bad value never reaches the file, and
(b) the **rollback trigger classifier** `ToolErrorNamesFile(stderr, path) bool` that detects a tool
error naming our file. The actual byte-restore is composed by callers / the M7 engine. This is the
spec's own milestone boundary, not a deviation.

## Package layout — new `sdk/validate` (package 9; bump the floor)

`sdk/validate` — "one grammar, shared server + agent" (§3.4 header). Files:
- `validate.go` — package doc, error sentinels, shared helpers (`hasControlChar`, `hasControlOrSpace`, leading-dash reject).
- `names.go` — [SDK-10] intent grammars.
- `structured.go` — [SDK-11] structured-file value + cross-field validators + `ToolErrorNamesFile`.
- `system.go` — [SDK-12] login shell (/etc/shells), LUKS path, flatpak app ID.
- `*_test.go` peers.

Guard: `sdk/guardtest/imports.go:35` `modulePackageFloors["sdk"]` **8 → 9** (self-discovering package
count gains `sdk/validate`). No new G-guard: M4 is grammars + red-first row tests, not a new archtest
(confirmed — no G-1..G-9 row demands validator coverage; the floor bump is the only guard delta).

## Error model

Sentinel `ErrInvalid` (`errors.Is`-matchable), wrapped `%w` with the field/reason
(house style: `sdk/fsafe/validate.go`). Every reject names what failed, never the raw secret. No
`(nil)`-swallow; empty-as-"unchanged" is explicit per function where the predecessor had it.

## Function surface + net-new decisions

### [SDK-10] `names.go`
| Fn | Grammar | Notes |
|---|---|---|
| `PackageName(s)` | `^[a-zA-Z0-9][a-zA-Z0-9._+:/@~-]{0,255}$` | port |
| `RpmPackageName(s)` | `^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,255}$` | port |
| `RepoName(s)` | `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$` | port (max 128) |
| `FlatpakRemoteName(s)` | `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$` | port |
| `GPGKeyRef(s)` | prefix switch https/file/abs, no `..` | port |
| `RepoBaseURL(s)` | `url.Parse`+https+host; **$releasever/$arch/$basearch survive** | port; AC-15 over-constraint accept |
| `Username(s)` | len 1..32, `[a-z][a-z0-9_-]*` | port (byte loop) |
| `SystemdUnitName(s)` | `^[a-zA-Z0-9][a-zA-Z0-9:_.@-]{0,254}\.(service\|socket\|device\|mount\|automount\|swap\|target\|path\|timer\|slice\|scope)$` | **NET-NEW** — no predecessor; leading alnum kills flag shape, `@` instance ok, known suffix set |
| `ULIDPathID(s)` | 26 chars, Crockford base32 `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I/L/O/U), case-insensitive | **NET-NEW** — hand-rolled (oklog/ulid is a banned dep) |

### [SDK-11] `structured.go`
| Fn | Rejects | Notes |
|---|---|---|
| `GECOSField(s)` | control chars, `:` (record sep). `,` allowed (GECOS subfields) | port |
| `GroupList(s)` | control chars, `:`, `,` | port (`,` is the `-G` separator) |
| `Deb822URIField(s)` | control, **space (2nd-URI inject)**, non-http(s) scheme, no hostname (`u.Hostname()`), embedded creds | port |
| `SSHDConfigValue(s)` / `SudoersValue(s)` / `AuthorizedKeysValue(s)` / `NMConnectionValue(s)` | the record separator only (`\n`/`\r`/NUL — all control chars). The other format delimiters (`: = [ ] ;`, spaces) are legitimate mid-value content read to end-of-line and are NOT rejected (rejecting them is an AC-15 over-constraint). `SudoersValue` additionally rejects a **trailing `\`** (sudoers line continuation). | shared `rejectControl`; see the delta note below |
| `Deb822Source(dist, comps)` | **cross-field**: empty dist + non-empty comps → reject | port [#302] |
| `ToolErrorNamesFile(stderr, path)` | `bool` — stderr references the written path | **rollback trigger**; exact-path substring match, ceiling documented |

### [SDK-12] `system.go`
| Fn | Rule | Notes |
|---|---|---|
| `LUKSDevicePath(s)` | `^/dev/[a-zA-Z0-9/_.\-]+$` + no `..` | port |
| `FlatpakAppID(s)` | reverse-DNS: ≥2 dot-separated segments, each `[A-Za-z_][A-Za-z0-9_-]*` (hyphen admitted in non-leading positions — see delta), total ≤255, no `/`/`..`/control | **NET-NEW** grammar (predecessor reused PackageName); the SDK-12 "before any path join" guard |
| `LoginShell(s)` | absolute + no control + **membership in `/etc/shells`** | **NET-NEW /etc/shells check** (predecessor only shape-checked). Host read behind `var readLoginShells = func() ([]string, error)` seam; **fail closed** (reject) if `/etc/shells` unreadable or shell absent from it |

## Scenario matrix (accept / reject rows → test names `Test<Fn>_<Case>`)

Every grammar gets: **accept** (canonical shapes), **reject-leading-dash** (flag injection), **reject-control**
(`\n`,`\x00`,`\t`,`0x7f`), **reject-delimiter** (format-specific), **reject-overlong** (cap+1), plus the
grammar-specific rows below. Reject cases must violate the *actual* constraint (tests.md).

- `PackageName`: accept `nginx`,`org.videolan.VLC/x86_64/stable`,`gcc-c++`,`lib32:i386`; reject `-y`,`--force`,`=evil`,`pkg;rm -rf /`,`pkg|cat`,`` `reboot` ``,`$(reboot)`,`pkg\nx`,`pkg\x00`,`pkg=1`,`pkg*`,257-char.
- `RepoBaseURL`: **accept** `https://dnf.example.com/fedora/$releasever`, `.../$arch`, `.../$basearch` (AC-15 over-constraint guard — a REQUIRED positive); reject `http://…`,`ftp://…`,`file:///etc`,`-o/tmp/x`,`https://a\nb`,`https://`,`https://[::1`,`not-a-url`.
- `GPGKeyRef`: accept `https://h/KEY`,`file:///etc/pki/KEY`,`/etc/pki/rpm-gpg/KEY`; reject `-`,`--import=/etc/shadow`,`http://evil/key`,`ext::sh -c id`,`relative/key`,`file://../../etc/passwd`,`/etc/../etc/shadow`,`https:///KEY`,`https://a\nhttps://b`.
- `Username`: accept `deploy`,`user_1`,`svc-acct`,32-char; reject ``,`Deploy`,`1user`,`-rf`,`_priv`,`user name`,`user:x`,`user\nroot`,33-char.
- `SystemdUnitName`: accept `nginx.service`,`sshd@1.socket`,`foo-bar.timer`; reject `nginx`(no type),`nginx.bogus`,`-x.service`,`a/b.service`,`unit\n.service`,`.service`,257-char.
- `ULIDPathID`: accept `01ARZ3NDEKTSV4RRFFQ69G5FAV` (and lowercase form); reject 25/27-char, `01ARZ3NDEKTSV4RRFFQ69G5FAI` (I), `…O`,`…L`,`…U`, `01arz…!`, embedded `/`.
- `GECOSField`: accept `Real Name`,`Real, Name, Room 5` (comma ok); reject `Real\nroot:x:0`,`a:b`,`x\x00y`,tab.
- `GroupList`: accept `wheel`,`wheel adm` (space-joined arg is caller's; value itself); reject `wheel,root`,`a:b`,control.
- `Deb822URIField`: accept `https://deb.example.com/ubuntu`,`http://…` (apt signed); reject `https://h/a https://evil/`(space),`https://user:pass@h/a`,`https://`,`ftp://…`,`a\nDeb-Src: x`,tab.
- `Deb822Source` cross-field: accept `(dist="stable", comps=["main"])`, `(dist="/", comps=[])`; reject `(dist="", comps=["main"])`.
- `ToolErrorNamesFile`: true for apt stderr naming `/etc/apt/sources.list.d/x.sources`; false for unrelated stderr / empty.
- `LUKSDevicePath`: accept `/dev/sda2`,`/dev/mapper/cryptroot`,`/dev/disk/by-uuid/…`; reject `/dev/../etc/shadow`,`-rf`,`sda2`(no /dev/),`/dev/sd a`,control.
- `FlatpakAppID`: accept `org.videolan.VLC`,`com.github.tchx84.Flatseal`; reject `VLC`(1 segment),`org.videolan.VLC/x86_64`(slash → path-join),`../org.x`,`org..x`,`org.videolan.VLC\n`,256-char.
- `LoginShell` (seam-stubbed `/etc/shells`): accept `/bin/bash` when in shells; reject `/bin/bash` when NOT in shells, `bash`(relative), `/bin/sh\nx`(control), and **reject-all when the seam errors** (fail closed).

## Implementation deltas (non-material, recorded)

- **`PasswdField` dropped.** Its rule (reject control + `:`) is byte-identical
  to `GECOSField`, and no M4 caller needs a second name (home/shell fields are
  covered by the fsafe path grammar and `LoginShell`). A duplicate exported
  function is the kind of redundancy YAGNI removes; if a generic passwd-field
  validator is ever needed, `GECOSField`'s rule already is it.
- **`FlatpakAppID` admits `-`** in non-leading element positions. The
  predecessor validated flatpak IDs through `PackageName` (which admits `-`),
  and real IDs carry it (`io.github.some-user.App`); rejecting it would be an
  AC-15 over-constraint. The NET-NEW grammar still tightens `PackageName` by
  dropping `/ @ ~ + :` — the path-join escape vectors [SDK-12] exists to stop.
  Implemented as a byte-checked element walk (no nested-quantifier regex → no
  ReDoS surface), not the `(\.…)+` form the plan sketched.
- **Line-oriented validators share `rejectControl`.** sshd_config, sudoers,
  authorized_keys, and NM-keyfile values reduce to the same check because their
  only smuggle-able structural delimiter is the record separator (a control
  char); the other format delimiters (`: = [ ] ;` space) are legitimate
  mid-value content and are deliberately NOT rejected. Kept as four named
  entry points (call sites read by format; each documents its own reasoning).

## Verification
- Red first: each row observed failing (scoped: stub the grammar to accept-all / comment the membership check), for the right reason, before impl.
- `./scripts/verify.sh` (gofmt, vet, staticcheck, guards incl. the bumped floor, all module tests) + `go test -C sdk ./... -race`.
- Ledger `00-index.md`: append the M4 row; line 23 status → `In progress (M4 done)`.
