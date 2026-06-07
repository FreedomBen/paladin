# symcrypt — Implementation plan 05: AES Crypt read support

**Status:** Proposed. Adds **decryption, verification, and inspection of foreign
[AES Crypt](https://www.aescrypt.com/) (`.aes`) files** to the existing core and
all three front-ends. Encryption to the AES Crypt format is **out of scope** —
symcrypt only ever *writes* its own container (DESIGN §5).
**Last updated:** 2026-06-07.

**Scope.** Teach `symcrypt-core` to recognize an AES Crypt container, derive its
key with the AES Crypt KDF, verify its HMACs, and stream out the plaintext, so
the four operations behave as follows on a `.aes` file:

| Operation              | Behavior on an AES Crypt file                                                |
| ---------------------- | --------------------------------------------------------------------------- |
| `decrypt` (`-d`)       | Detect, verify, and decrypt to the output.                                  |
| `verify` (`--verify`)  | Detect and verify the HMACs (decrypt-and-discard); write nothing.           |
| `inspect` (`-i`)       | Report unauthenticated AES Crypt metadata (version, extensions).            |
| `encrypt` (`-e`)       | **Unchanged** — always writes a symcrypt container; never AES Crypt.        |

Because the front-ends are thin (DESIGN §2.2), almost all of the work lands in
`symcrypt-core`; the front-ends only learn that `inspect` can now return a second
kind of metadata and that the default decrypt-output path can strip `.aes`.

**Depends on:** [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)
(core + common) and the implemented front-ends
([`02_CLI`](IMPLEMENTATION_PLAN_02_CLI.md),
[`03_TUI`](IMPLEMENTATION_PLAN_03_TUI.md),
[`04_GTK`](IMPLEMENTATION_PLAN_04_GTK.md)).

> **Security-affecting change — read [§4](#4-security-implications-confirm-before-implementing) first.**
> AES Crypt uses a deliberately weak-by-modern-standards KDF, an
> **unauthenticated** header/extensions/length byte, and CBC+HMAC rather than
> AEAD. Adding read support is an *interoperability* feature, not an endorsement;
> the implications and the tests that pin them are spelled out below and must be
> confirmed before implementation begins (repo policy, CLAUDE.md).

---

## Table of contents

1. [Goals & non-goals](#1-goals--non-goals)
2. [The AES Crypt file format (what we must read)](#2-the-aes-crypt-file-format-what-we-must-read)
3. [Design: where the work lives](#3-design-where-the-work-lives)
4. [Security implications (confirm before implementing)](#4-security-implications-confirm-before-implementing)
5. [Core changes (`symcrypt-core`)](#5-core-changes-symcrypt-core)
6. [CLI changes (`symcrypt`)](#6-cli-changes-symcrypt)
7. [TUI changes (`symcrypt-tui`)](#7-tui-changes-symcrypt-tui)
8. [GTK changes (`symcrypt-gtk`)](#8-gtk-changes-symcrypt-gtk)
9. [DESIGN.md updates required](#9-designmd-updates-required)
10. [Dependencies to add](#10-dependencies-to-add)
11. [Testing strategy & known-answer vectors](#11-testing-strategy--known-answer-vectors)
12. [Decisions](#12-decisions)
13. [Master checklist](#13-master-checklist)

---

## 1. Goals & non-goals

### Goals

- **Read interop.** Decrypt, verify, and inspect AES Crypt **version 2** files
  (the format the reference tool has written for years), and version 1 (same
  layout minus the extensions block). Version 0 is an optional stretch
  ([§12](#12-decisions)).
- **One core, thin front-ends — unchanged.** All format detection, KDF, and
  HMAC/CBC logic lives in `symcrypt-core`. Front-ends gain no crypto or format
  knowledge; `decrypt`/`verify` keep the *same signatures* and "just work" on a
  `.aes` file. Only `inspect`'s **return type** widens (it can now describe two
  formats), which the front-ends render.
- **Honest verification.** Verify HMAC-1 (key block) before producing any
  plaintext and HMAC-2 (body) before the output is finalized; map every failure
  to the single [`SymError::Auth`] condition, exactly as the symcrypt path does
  (DESIGN §4.4).
- **Same safety envelope.** Enforce the 64 GiB plaintext cap, bound every
  unauthenticated length before allocation, zeroize all key material.

### Non-goals

- **No AES Crypt encryption.** `encrypt` is untouched; symcrypt never emits a
  `.aes` file. (Re-encrypting a decrypted file with symcrypt's own format is the
  recommended migration — see [§4](#4-security-implications-confirm-before-implementing).)
- **No password compatibility shims** beyond the documented UTF-16LE encoding
  ([§2.3](#23-key-derivation-the-aes-crypt-kdf)); historical platform quirks of
  very old AES Crypt builds are a documented limitation, not a target.
- **No new front-end modes or flags.** Detection is automatic; there is no
  `--aescrypt` switch.

---

## 2. The AES Crypt file format (what we must read)

AES Crypt is **encrypt-then-MAC**: AES-256 in **CBC** mode for confidentiality,
**HMAC-SHA256** for integrity, with a two-level key hierarchy. All multi-byte
integers are big-endian. This section is the implementation reference; the
authoritative external spec is the AES Crypt "format" document.

### 2.1 Container layout (versions 1 & 2)

| Offset (v2)                | Size       | Field                | Notes                                                            |
| -------------------------- | ---------- | -------------------- | ---------------------------------------------------------------- |
| 0                          | 3          | `magic`              | ASCII `"AES"` (`0x41 0x45 0x53`).                                 |
| 3                          | 1          | `version`            | `0x00` / `0x01` / `0x02`.                                         |
| 4                          | 1          | `reserved`           | `0x00` for v1/v2. (For **v0** this byte is the `fsmod`, §2.4.)    |
| 5                          | varies     | `extensions`         | **v2 only.** Repeated `(u16 len, len bytes)`; a `len == 0x0000` terminates. Absent in v1. |
| …                          | 16         | `iv1`                | IV for the key-wrap layer; also seeds the KDF.                   |
| …                          | 48         | `enc_keys`           | `AES-256-CBC(key1, iv1, iv2 ‖ key2)` — 16-byte `iv2` + 32-byte `key2`. |
| …                          | 32         | `hmac1`              | `HMAC-SHA256(key1, enc_keys)`.                                   |
| …                          | `N`·16     | `ciphertext`         | `AES-256-CBC(key2, iv2, plaintext padded to a 16-byte boundary)`. `N` ≥ 0. |
| …                          | 1          | `fsmod`              | Original plaintext length **mod 16** (`0..=15`); how many bytes of the final block are real. |
| …                          | 32         | `hmac2`              | `HMAC-SHA256(key2, ciphertext)`.                                 |

The `ciphertext` length is not stored; it is *everything between `hmac1` and the
trailing 33 bytes* (`fsmod` + `hmac2`). The decryptor therefore buffers the last
33 bytes to find the boundary (§5.5).

### 2.2 Extensions (v2)

Each extension is a 2-byte big-endian length followed by that many content bytes;
content is conventionally `identifier ‖ 0x00 ‖ data`. Common ones: `CREATED_BY`
(e.g. `"AES Crypt 3.x"`) and a 128-byte zero-filled "container" extension used as
reserved padding. **Extensions are not authenticated** (§4). The reader bounds
the total extension bytes it will buffer and the count it will parse (§5.6); it
keeps `CREATED_BY` for `inspect` and ignores the rest.

### 2.3 Key derivation (the AES Crypt KDF)

`key1` is derived from the password and `iv1` with an iterated SHA-256 — **not**
Argon2/scrypt/PBKDF2:

```
pw16   = UTF-16LE(password)             # little-endian, no BOM
digest = iv1 (16 bytes) ‖ 0x00 * 16     # 32 bytes
repeat 8192 times:
    digest = SHA256(digest ‖ pw16)
key1   = digest                         # 32 bytes
```

`key1` then (a) keys `hmac1` over `enc_keys` and (b) AES-256-CBC-decrypts
`enc_keys` (IV = `iv1`) to recover `iv2 ‖ key2`. `key2` keys both the body CBC
decryption and `hmac2`.

> **Password encoding.** symcrypt front-ends capture the password as UTF-8 bytes
> (DESIGN §6.4). For AES Crypt we re-encode those bytes as **UTF-16LE** per the
> format spec. ASCII passwords interoperate cleanly; non-ASCII passwords depend
> on the writer having used the same Unicode encoding, which very old or
> non-standard AES Crypt builds did not always do — a documented limitation, not
> a bug.

### 2.4 Version 0 (optional, §12)

A single-key variant with **no extensions and no key wrap**: `"AES"`, `0x00`,
then `fsmod` (1 byte) at offset 4, `iv` (16), `ciphertext`, `hmac` (32). The key
is the §2.3 KDF output used *directly* for both the body CBC and the single HMAC;
there is no `hmac1`/`enc_keys` layer, so a wrong password is only caught by the
final HMAC. Supporting it is cheap but its test vectors are harder to source
(modern tools only write v2).

---

## 3. Design: where the work lives

### 3.1 Format detection & dispatch (the only public-API change)

After armor is stripped (an AES Crypt file is binary and passes
`armor::auto_dearmor` through untouched), the core peeks the leading bytes and
dispatches:

- `"SYMCRYPT"` → the existing symcrypt path (`header::parse` + `stream::*`).
- `"AES"` + a supported `version` → the new `aescrypt` path.
- anything else → [`SymError::BadMagic`] (exit 4), as today.

Detection reads a small fixed prefix (≤ 8 bytes) and re-attaches it with
`std::io::Read::chain` so the chosen parser sees the full stream. A new private
`format` module owns the peek-and-dispatch; `lib.rs::{decrypt, verify, inspect}`
call it instead of going straight to `stream`/`header`.

### 3.2 `inspect` returns a format-tagged enum

`inspect` currently returns a symcrypt-only [`Header`]. It must now describe
*either* format, so its return type becomes a small enum:

```rust
/// Unauthenticated metadata for whichever container `inspect` recognized.
pub enum Metadata {
    Symcrypt(Header),            // existing struct, unchanged
    AesCrypt(AesCryptHeader),    // new (version, extensions, …)
}

pub fn inspect<R: Read>(input: R) -> Result<Metadata>;
```

This is the **one breaking change** to the core API. Every `inspect` call site
renders the result by matching the enum (call sites enumerated in
[§6](#6-cli-changes-symcrypt)–[§8](#8-gtk-changes-symcrypt-gtk)). `decrypt` and
`verify` keep identical signatures — only their internals dispatch.

### 3.3 What stays identical

`Secret` assembly, the temp-file-then-rename finalization, progress/cancellation,
the 64 GiB cap, exit-code mapping, and the "wrong password vs. tampered file are
one condition" rule are all reused as-is. The AES Crypt decryptor plugs into the
*same* `Read`/`Write`/`OnProgress` contract the STREAM decryptor uses.

---

## 4. Security implications (confirm before implementing)

Per repo policy (CLAUDE.md), these are stated up front and each is pinned by a
test in [§11](#11-testing-strategy--known-answer-vectors). **Confirm before
implementing.**

| # | Implication | Mitigation / how it's handled |
| - | ----------- | ----------------------------- |
| 1 | **Weak KDF.** AES Crypt's 8192-iteration SHA-256 is far cheaper to brute-force than Argon2id/scrypt. We do not choose it — it is fixed by the file we are reading. | Read-only. Docs/help recommend **re-encrypting** decrypted data with symcrypt's own format. No symcrypt file is ever written with this KDF. |
| 2 | **Unauthenticated header.** `magic`, `version`, `reserved`, and all **extensions** are outside both HMACs. An attacker can flip the version byte or rewrite extensions undetected. This is a property of the foreign format, not fixable on read. | Treat all header/extension data as *unauthenticated even after a successful decrypt*. `inspect` labels it so. We bound and sanitize extensions; we never act on their contents. |
| 3 | **Unauthenticated `fsmod`.** The length-mod-16 byte sits outside `hmac2`, so the last block's *visible length* is malleable by up to 15 bytes (the bytes themselves are authentic). | Validate `fsmod ∈ 0..=15` and that it is consistent with the block count (e.g. `fsmod == 0` when there are zero body blocks). Document the residual malleability. |
| 4 | **CBC + late MAC.** `hmac2` covers the body and sits *after* it, so a pure verify-before-output design would need two passes (impossible for stdin). We stream-decrypt while computing `hmac2`, then verify at end. | Plaintext is written to the front-end's **temp file** and only renamed in on success; an `Auth` failure discards it (DESIGN §2.2). For `-o -` (stdout) partial plaintext may appear before the check — the *same* caveat symcrypt already documents (DESIGN §11). No padding oracle exists (AES Crypt uses `fsmod`, not PKCS#7), and we never deliver unverified plaintext to a file. |
| 5 | **`hmac1` first.** For v1/v2, a wrong password yields a wrong `key1`, so `hmac1` fails **before any body byte is processed** — wrong-password is caught early (exit 3) with no output. | Verify `hmac1` immediately after KDF, before touching the body. |
| 6 | **Constant-time tag checks.** A non-constant-time compare could leak. | Use the RustCrypto `Mac::verify_slice` (constant-time); never compare tags with `==`. |
| 7 | **Resource bounds on hostile input.** A crafted file could claim huge/streamed extensions or an enormous body. | Cap total extension bytes and count (§5.6); enforce the 64 GiB plaintext cap during streaming; the 8192-iteration KDF is a fixed, bounded cost. |
| 8 | **No keyfile concept.** AES Crypt has no keyfile. Silently ignoring a supplied `-k` would mislead the user. | If a `.aes` file is detected and the `Secret` carries keyfile material (or has no password, e.g. keyfile-only mode), reject with `InvalidOptions` (exit 2). |

---

## 5. Core changes (`symcrypt-core`)

All new code is library code with exhaustive unit + KAT tests (DESIGN §10). TDD:
write the failing test first, then the implementation.

### 5.1 New / changed modules

```
crates/symcrypt-core/src/
├── lib.rs        # CHANGED: decrypt/verify/inspect dispatch by format; export Metadata, AesCryptHeader
├── format.rs     # NEW: peek leading bytes, return Format + a re-chained Read; the dispatch point
├── aescrypt.rs   # NEW: AES Crypt header parse, KDF, CBC+HMAC verify/decrypt/inspect (the bulk)
├── secret.rs     # CHANGED: add pub(crate) password_bytes() accessor (UTF-16LE re-encode needs the raw password)
├── paths.rs      # CHANGED: default_decrypt_output strips .aes too; add default_aescrypt_output(input)
├── error.rs      # CHANGED: add UnsupportedAesCryptVersion(u8)
├── header.rs     # unchanged (symcrypt header)
├── cipher.rs     # unchanged (AEAD); AES Crypt CBC lives in aescrypt.rs
├── kdf.rs        # unchanged (symcrypt KDFs); AES Crypt KDF lives in aescrypt.rs
├── stream.rs     # unchanged
└── armor.rs      # unchanged
```

Keeping AES Crypt's CBC, HMAC, and bespoke KDF in a self-contained `aescrypt.rs`
mirrors the existing one-concern-per-module layout and avoids entangling the
audited symcrypt primitives with the legacy format.

### 5.2 Error surface (`error.rs` + `symcrypt-common`)

- Add one variant: `UnsupportedAesCryptVersion(u8)` →
  `#[error("unsupported AES Crypt version: {0:#04x}")]`, mapped to **exit 4** in
  `symcrypt-common::exit_code` (alongside the other format errors). The enum is
  already `#[non_exhaustive]`, so this is additive.
- Reuse existing variants everywhere else:
  - bad/short `"AES"` header, bad extension framing, out-of-range lengths,
    bad `fsmod` → `MalformedHeader(&'static str)` (exit 4);
  - any HMAC mismatch, a body too short to hold the trailer, or a ciphertext
    run not a multiple of 16 → `Auth` (exit 3) — never distinguished from a
    wrong password (DESIGN §4.4);
  - keyfile-present / password-absent against a `.aes` file → `InvalidOptions`
    (exit 2);
  - plaintext over 64 GiB → `InputTooLarge` (exit 1);
  - cancellation via `on_progress` → `Canceled` (exit 130);
  - caller `Read`/`Write` failures → `Io` (exit 1).
- **Test (common):** extend `core_errors_map_to_their_exit_codes` so
  `UnsupportedAesCryptVersion(3)` maps to 4.

### 5.3 `Secret` accessor (`secret.rs`)

The AES Crypt KDF needs the **raw password bytes** (to re-encode UTF-16LE) and
must reject keyfiles; the symcrypt `kdf_input()` blend is wrong here. Add:

```rust
impl Secret {
    /// Raw password bytes (for the AES Crypt KDF's UTF-16LE re-encoding).
    pub(crate) fn password_bytes(&self) -> &[u8] { &self.password }
    // has_keyfile() already exists.
}
```

The `aescrypt` decryptor rejects `secret.has_keyfile()` and an empty
`password_bytes()` with `InvalidOptions` before deriving (implication #8). A
`.aes` file written with a genuinely empty password is therefore unreadable by
symcrypt — a documented limitation; the reference tool does not produce such
files. **Test:** keyfile-bearing or password-less `Secret` against a fixture
`.aes` returns `InvalidOptions`.

### 5.4 Format detection (`format.rs`)

```rust
pub(crate) enum Format { Symcrypt, AesCrypt }

/// Peek the magic and return the format plus a reader that still yields the
/// peeked bytes. Fewer than the needed bytes, or an unrecognized magic, is
/// BadMagic / MalformedHeader as appropriate.
pub(crate) fn detect<R: Read>(input: R) -> Result<(Format, impl Read)>;
```

Reads up to 8 bytes, matches `"SYMCRYPT"` vs `"AES"`, and returns
`prefix.chain(input)`. **Tests:** symcrypt magic, AES magic, short input, and
foreign magic each classified correctly; the re-chained reader reproduces the
original bytes.

### 5.5 AES Crypt decrypt/verify (`aescrypt.rs`)

Single streaming routine shared by decrypt (writes plaintext) and verify
(discards it), parameterized like `stream::{decrypt, verify}`:

1. **Parse the unauthenticated header** (§2.1): `"AES"`, `version` (else
   `UnsupportedAesCryptVersion`), `reserved`, extensions (v2, §5.6), `iv1`,
   `enc_keys` (48), `hmac1` (32). Report `on_progress` once after the header.
2. **Reject incompatible secrets** (implication #8).
3. **Derive `key1`** with the §2.3 KDF (UTF-16LE password, 8192× SHA-256 over
   `digest ‖ pw16`), in `Zeroizing` buffers. Honor cancellation before/after.
4. **Verify `hmac1`** over `enc_keys` with `Mac::verify_slice` → `Auth` on
   mismatch (this is the early wrong-password gate, implication #5).
5. **Unwrap keys:** AES-256-CBC-decrypt `enc_keys` with (`key1`, `iv1`) → `iv2`,
   `key2` (zeroized). Build the body HMAC `HMAC-SHA256(key2, …)`.
6. **Stream the body with a 33-byte trailer buffer** (§5.7): maintain a rolling
   buffer and treat only the bytes *before* the trailing 33 as ciphertext,
   emitting them as complete 16-byte blocks — feeding each ciphertext block to
   `hmac2` and CBC-decrypting it with `key2`/chaining IV. **Defer each block's
   plaintext write by one block** (hold the most recently decrypted block back):
   the final ciphertext block needs `fsmod` truncation and which block is final
   isn't known until EOF. Enforce the 64 GiB plaintext cap from bytes actually
   produced. Report `on_progress` per block and observe cancellation.
7. **At EOF:** the retained 33 bytes are `fsmod ‖ hmac2`, and the held-back
   block is the final ciphertext block. Require the consumed body to be a
   multiple of 16; validate `fsmod` (§4, implication #3). Apply `fsmod` to that
   final block (keep `fsmod` bytes when non-zero; keep the whole block when zero;
   an empty body yields empty plaintext) and write it. Deferring the final block
   is **required** — the core's `Write` is not seekable, so `fsmod` truncation
   cannot be undone after the bytes are written (notably for `-o -`); deferring
   *all* plaintext until the MAC check is also sound but unnecessary given
   temp-file finalization. **Verify `hmac2` with `verify_slice` before returning
   `Ok`** regardless (implication #4).
8. **Verify `hmac2`** with `verify_slice` → `Auth` on mismatch.

`verify` runs the identical path with a sink that discards writes.

### 5.6 Extension parsing & bounds (`aescrypt.rs`)

- Read `(u16 len, len bytes)` repeatedly until `len == 0`.
- Bound **total** extension bytes (e.g. ≤ 256 KiB) and **count** (e.g. ≤ 1024);
  exceeding either is `MalformedHeader` (a hostile file cannot force unbounded
  buffering — implication #7).
- Retain a sanitized `CREATED_BY` value (printable, length-capped) for `inspect`;
  ignore the rest. Never interpret extension contents as paths or commands.

### 5.7 The 33-byte trailer-buffer technique (why)

The body is `ciphertext ‖ fsmod(1) ‖ hmac2(32)` with no stored length. To find
where ciphertext ends without a second pass, keep the most recent 33 bytes
buffered and only treat earlier bytes as ciphertext. When the stream ends, the
buffer holds exactly the trailer. Separately, hold the most recently *decrypted*
block's plaintext back by one block so `fsmod` can truncate the final block
before it is written (§5.5 step 6–7) — the core's `Write` is not seekable, so a
write cannot be taken back. Fewer than 33 trailing bytes total, or a ciphertext
run not divisible by 16, is `Auth` (truncation is indistinguishable
from tampering, DESIGN §5.5). Unit-test the boundary at body sizes
`0, 16, 16±(within a block), several blocks`.

### 5.8 `inspect` for AES Crypt (`aescrypt.rs` + `lib.rs`)

`AesCryptHeader { version: u8, extensions: Vec<AesExtension>, created_by: Option<String> }`
(no key material; unauthenticated). `inspect` parses through `hmac1` **without a
password** and returns `Metadata::AesCrypt(_)`. Stable `--info` field order
(rendered by the front-ends, §6):

```
format: aescrypt
version: <decimal>
cipher: aes-256-cbc
kdf: aescrypt-sha256
extensions: <count>
created_by: <sanitized value or empty>
authenticated: false
```

`authenticated: false` makes implication #2 explicit in the output. **Test:**
byte-exact block for a v2 fixture with and without `CREATED_BY`.

### 5.9 Path helpers (`paths.rs`)

- `default_aescrypt_output(input: &Path) -> PathBuf`: strip a trailing `.aes`
  (case-sensitive), else append `.dec`, with the same empty-basename fallback as
  the symcrypt helper (`.aes` → `.aes.dec`). AES Crypt v2 has no standard stored
  filename, so there is no name-from-header branch.
- Factor the suffix-stripping into a shared helper and **add `.aes`** to the set
  so a symcrypt file inadvertently named `*.aes` still strips sensibly.
- **Tests:** `secret.aes → secret`, `secret → secret.dec`, `.aes → .aes.dec`,
  non-UTF-8 input → `.dec` appended (mirrors existing `paths.rs` tests).

### 5.10 `lib.rs` wiring & ordered steps (TDD)

1. **Deps & module skeleton** — add `aes`, `cbc`, `hmac` ([§10](#10-dependencies-to-add));
   create `format.rs`/`aescrypt.rs`; export `Metadata`, `AesCryptHeader`.
2. **KDF** — implement and test the §2.3 derivation against a known vector
   (derive `key1` from a fixed password + `iv1`; lock the bytes).
3. **Header parse + extensions** — parse/validate; bounds tests (§5.6).
4. **`hmac1` + key unwrap** — verify-then-unwrap; wrong-password → `Auth`.
5. **Body stream + trailer buffer + `fsmod` + `hmac2`** — round-trip a real
   `.aes` fixture; tamper/truncate/append tests.
6. **`format::detect` + dispatch in `decrypt`/`verify`/`inspect`** — including
   the `inspect` enum migration and updating core's own `lib.rs` tests.
7. **`inspect` for AES Crypt + path helper** — `--info` block; `.aes` stripping.
8. **Size cap, cancellation, secret-rejection** — parity with the STREAM path.
9. `cargo fmt` + `cargo clippy --all-targets --all-features` clean; full KATs
   ([§11](#11-testing-strategy--known-answer-vectors)).

---

## 6. CLI changes (`symcrypt`)

The CLI gains **no new flags**; `-d`/`--verify`/`-i` transparently handle `.aes`
files once the core dispatches. The concrete edits:

| Area | File | Change |
| ---- | ---- | ------ |
| Decrypt default output | `src/run.rs` (`run_decrypt`, ~L109–116) | The no-`-o` branch already peeks `core::inspect`. Match the new `Metadata`: `Symcrypt(h)` → `default_decrypt_output(input, &h)` (today's call); `AesCrypt(_)` → `default_aescrypt_output(input)`. |
| Info rendering | `src/info.rs` (`format_info`) | Take `&Metadata` and branch: existing 12-line symcrypt block, or the §5.8 AES Crypt block. Keep both stable and test byte-exact. |
| Info dispatch | `src/run.rs` (`run_info`, ~L165) | `core::inspect` now returns `Metadata`; pass it to `info::format_info`. |
| Friendlier keyfile error | `src/run.rs` / `src/secret.rs` | On decrypt-without-`-o` we already know the format from the peek; if `AesCrypt` and `-k` was supplied, fail early with a clear "AES Crypt files don't use keyfiles" usage message *before prompting*. The core `InvalidOptions` backstop still covers the `-o`-supplied path. |
| Help / docs | `src/cli.rs` help text, man page, README | Note that `-d`/`--verify`/`-i` auto-detect AES Crypt (`.aes`) files, that encryption always uses symcrypt's format, and recommend re-encrypting decrypted data (implication #1). |

**Integration tests** (`tests/cli.rs`, `assert_cmd` + a committed `.aes`
fixture, §11):

- `-d sample.aes` with the right password → exit 0, plaintext matches; default
  output strips `.aes`.
- Wrong password → exit 3; truncated/tampered body → exit 3.
- `version` byte set to an unsupported value → exit 4.
- `-k key -d sample.aes` → exit 2 (keyfile rejected); `--no-password -k …` on a
  `.aes` file → exit 2.
- `--verify sample.aes` success/failure (0 vs 3).
- `-i sample.aes` → exact AES Crypt `--info` block (incl. `authenticated: false`).
- Quiet/verbose unaffected; `-o -` streams plaintext.

---

## 7. TUI changes (`symcrypt-tui`)

Decrypt and Verify run through the worker → `core::{decrypt, verify}`
(`src/worker.rs`, unchanged) and work automatically. Only the **Info** path and
the **decrypt-output prefill** touch the widened `inspect` return type.

| Area | File | Change |
| ---- | ---- | ------ |
| Info rendering | `src/info.rs` (`format_info(&Header) -> Vec<String>`) | Change to `format_info(&Metadata)` and branch to symcrypt vs AES Crypt rows (§5.8). |
| Inline inspect | `src/app.rs` (~L498–503) | `core::inspect(&mut r)` now yields `Metadata`; pass to `format_info`. |
| Decrypt prefill | `src/app.rs` (`sync_paths`, Decrypt branch ~L720–726) | The branch inspects to prefill the output name; match `Metadata`: `Symcrypt(h)` → `default_decrypt_output`; `AesCrypt(_)` → `default_aescrypt_output`. The current `Err(_)` → "not a symcrypt file" fallback now fires only for genuinely unrecognized inputs (a `.aes` file inspects successfully). |
| Keyfile field | (no code change) | A keyfile + a `.aes` file surfaces the core `InvalidOptions` as the existing error status; document it. Optionally disable the keyfile field once Info reveals an AES Crypt input — a nicety, not required. |

**Tests:** extend the existing `info.rs` unit test so `format_info` renders an
AES Crypt `Metadata` (build the fixture by inspecting committed `.aes` bytes);
keep the symcrypt assertions. The `info_mode_inline_inspect_populates_results`
app test gets an AES Crypt counterpart. Per DESIGN §10, headless TUI coverage
stays light and leans on the core tests.

---

## 8. GTK changes (`symcrypt-gtk`)

Same shape as the TUI: Decrypt/Verify run as relm4 commands calling
`core::{decrypt, verify}` and need no change; Info and the decrypt-output prefill
consume the new `Metadata`.

| Area | File | Change |
| ---- | ---- | ------ |
| Info rendering | `src/info.rs` (`header_rows`/`header_text`, take `&Header`) | Accept `&Metadata` (or add `aescrypt_rows`/`metadata_rows`) and render the §5.8 AES Crypt rows; keep `InfoRow`/order parity with the CLI. |
| Inspect helpers | `src/app.rs` (`inspect_path` ~L252, `open_and_inspect` ~L1034) | Return `Result<Metadata, …>` instead of `Result<Header, …>`; update the three call sites (decrypt prefill ~L238–240, info prefill ~L266–267, Run/Info ~L929–930). |
| Decrypt prefill | `src/app.rs` (~L238–240) | Match `Metadata`: `Symcrypt(h)` → `default_decrypt_output(&input, &h)`; `AesCrypt(_)` → `default_aescrypt_output(&input)`. |
| Info text | `src/app.rs` (~L267, ~L930) | `info::header_text` → `info::metadata_text(&meta)`. |
| Keyfile chooser | (no code change) | Core `InvalidOptions` is surfaced via the existing toast/error dialog; drag-and-drop of a `.aes` file decrypts normally. |

**Tests:** the `info.rs` unit tests (pure, no display) gain AES Crypt cases
(build `Metadata` by inspecting committed `.aes` bytes; assert rows/text). GTK UI
behavior stays on manual verification plus the shared core tests (DESIGN §10).

---

## 9. DESIGN.md updates required

`docs/DESIGN.md` is the source of truth (CLAUDE.md), so it changes alongside the
code:

- **New subsection (e.g. §5.8 "AES Crypt read interop")**: the §2 format summary,
  supported versions, the KDF, encrypt-then-MAC verification, and the
  unauthenticated-header caveat.
- **§2.3 API sketch:** `inspect` now returns `Metadata` (enum over
  `Header`/`AesCryptHeader`); note `default_aescrypt_output`.
- **§6.2 `--info`:** document `format: aescrypt` and its field block, including
  `authenticated: false`.
- **§6.5 output defaults:** decrypt strips `.aes`.
- **§6.6 errors:** add `UnsupportedAesCryptVersion` → exit 4; keyfile-with-`.aes`
  → exit 2.
- **§9 dependencies:** add `aes`, `cbc`, `hmac` (core).
- **§10 testing:** AES Crypt KATs, wrong-password, tamper, version handling.
- **§11 security:** the implication list from [§4](#4-security-implications-confirm-before-implementing).
- **§13 out of scope:** AES Crypt **encryption** stays out of scope (read-only).

---

## 10. Dependencies to add

Core-only, all from [RustCrypto](https://github.com/RustCrypto) (pure-Rust,
reviewed — DESIGN §4.1). Resolve exact versions via `cargo add` and pin in
`Cargo.lock`.

| Crate  | Why                                          | Compatibility note |
| ------ | -------------------------------------------- | ------------------ |
| `aes`  | Raw AES-256 block cipher for CBC.            | Use the version whose `cipher` traits match the `aes` already pulled by `aes-gcm 0.10` (currently `aes 0.8` / `cipher 0.4`) so no second `aes`/`cipher` generation is vendored. |
| `cbc`  | CBC block mode over `aes` (`BlockDecryptMut`). | Pairs with the same `cipher` generation as `aes` above. |
| `hmac` | HMAC-SHA256 over the key block and body; `verify_slice` for constant-time checks. | Must match the `digest` generation of the in-tree `sha2 0.11` (i.e. the `hmac` release built on `digest 0.11`). `sha2` is already a dependency; reuse it. |

UTF-16LE encoding uses `str::encode_utf16` (std) — no crate. No new dev-deps
beyond the existing `hex`/`tempfile` for KAT fixtures.

> **Watch the `digest`/`cipher` split.** `sha2 0.11` is the newer `digest 0.11`
> generation, while `aes-gcm 0.10` is the `cipher 0.4` generation. Pick `hmac`
> against `sha2`'s generation and `cbc`/`aes` against `aes-gcm`'s; they need not
> match each other. If `cargo add` surfaces a conflict, align versions rather
> than vendoring duplicate trait crates.

---

## 11. Testing strategy & known-answer vectors

Most coverage is in `symcrypt-core` (DESIGN §10). Commit small fixtures under
`crates/symcrypt-core/tests/` (or `data/`).

**Known-answer vectors (the anchor).** Generate `.aes` fixtures with the
**reference `aescrypt` tool** (v2) for a handful of plaintext sizes
(`0, 1, 15, 16, 17, a few KiB`) and passwords (ASCII; one non-ASCII as a
documented-limitation case). Commit ciphertext + expected plaintext + password.
Tests assert exact round-trip. Document the exact tool version/command used to
mint them so they can be regenerated. (v1 can be hand-derived from a v2 fixture
by dropping the extensions block and flipping the version byte — neither is under
a MAC; v0, if pursued, needs its own source.)

**KDF vector.** Lock `key1` for a fixed (`password`, `iv1`) so the §2.3
derivation can't drift silently.

**Round-trip.** Decrypt each committed fixture → byte-exact plaintext, across the
sizes above (exercises the trailer buffer, `fsmod`, empty body, multi-block).

**Negative / tamper (each → `Auth`, exit 3):**

- Wrong password (fails at `hmac1`, before any output).
- Flip a byte in the body; flip a byte in `enc_keys`.
- Truncate the last block; drop the trailer; append bytes.
- Body length not a multiple of 16.

**Format / malformed (→ exit 4):**

- `version` byte unsupported → `UnsupportedAesCryptVersion`.
- Extension framing overruns / exceeds the size or count bound →
  `MalformedHeader`.
- `fsmod ≥ 16`, or `fsmod ≠ 0` with zero body blocks → `MalformedHeader`.
- Header truncated mid-field → `MalformedHeader`.

**Usage (→ exit 2):** keyfile-bearing or password-less `Secret` against a `.aes`
file → `InvalidOptions`.

**Caps & control flow:** an authenticated body exceeding 64 GiB →
`InputTooLarge` (synthesize without a 64 GiB file, as the STREAM tests do);
`on_progress` → `Break` yields `Canceled` on the AES Crypt path too.

**Front-ends:** CLI `assert_cmd` cases (§6); TUI/GTK `info` rendering unit tests
(§7–§8). After changes: `cargo fmt`, `cargo clippy --all-targets --all-features`
(no warnings), `cargo test`.

---

## 12. Decisions

Resolved 2026-06-07.

- **Version 0 support — deferred.** v1/v2 cover essentially all real files; v0
  adds a separate single-key path and is hard to KAT (no modern writer). Ship
  v1/v2 first; add v0 only if a concrete need appears (§2.4).
- **`inspect` returns the `Metadata` enum.** Widening `inspect` to `Metadata` is
  the one breaking change; it touches the CLI/TUI/GTK info renderers and a few
  app call sites (all enumerated in §6–§8). The rejected alternative — a separate
  `inspect_aescrypt` plus a format probe — only moves the churn and forces
  front-ends to detect the format themselves, violating the thin-front-end rule.
  The enum keeps detection in core.
- **`--info` `cipher`/`kdf` labels — confirmed `aes-256-cbc` / `aescrypt-sha256`.**
  These are display-only strings (not the symcrypt `CipherId`/`KdfId` enums) and
  won't be accepted by `-c`/`--kdf`.
- **Friendlier pre-prompt keyfile rejection in the CLI (§6) — included.** When a
  decrypt peek detects an AES Crypt input and `-k` was supplied, fail early with a
  clear usage message before prompting; the core `InvalidOptions` backstop remains
  the contract for the `-o`-supplied path.

---

## 13. Master checklist

**Core (`symcrypt-core`)**
- [ ] Add `aes`, `cbc`, `hmac` deps; pin in `Cargo.lock` (mind the `digest`/`cipher` split, §10).
- [ ] `error.rs`: add `UnsupportedAesCryptVersion(u8)`; `common::exit_code` maps it to 4 (+ test).
- [ ] `secret.rs`: add `pub(crate) password_bytes()`; reject keyfile/empty-password for AES Crypt.
- [ ] `format.rs`: `detect` peeks magic and re-chains the reader (+ tests).
- [ ] `aescrypt.rs`: header + extension parse with bounds (§5.6).
- [ ] `aescrypt.rs`: §2.3 KDF (UTF-16LE, 8192× SHA-256) with a locked KDF vector.
- [ ] `aescrypt.rs`: verify `hmac1` (constant-time) → unwrap `iv2`/`key2`.
- [ ] `aescrypt.rs`: body stream w/ 33-byte trailer buffer, `fsmod`, `hmac2`, 64 GiB cap, cancellation.
- [ ] `aescrypt.rs`: `inspect` → `AesCryptHeader`; sanitized `CREATED_BY`.
- [ ] `lib.rs`: `decrypt`/`verify`/`inspect` dispatch by `Format`; export `Metadata`/`AesCryptHeader`; update core tests.
- [ ] `paths.rs`: `default_aescrypt_output` + `.aes` in the shared suffix set (+ tests).
- [ ] Full KAT + tamper + format + usage + cap tests (§11); `fmt`/`clippy` clean.

**CLI (`symcrypt`)**
- [ ] `info.rs`: `format_info(&Metadata)` renders both formats (byte-exact).
- [ ] `run.rs`: `run_info`/`run_decrypt` consume `Metadata`; AES Crypt default output.
- [ ] Pre-prompt keyfile rejection for detected `.aes` (§6).
- [ ] Help/man/README: auto-detect note + re-encrypt recommendation.
- [ ] `assert_cmd` suite over a committed `.aes` fixture (§6).

**TUI (`symcrypt-tui`)**
- [ ] `info.rs`: `format_info(&Metadata)`; AES Crypt rows.
- [ ] `app.rs`: inline-inspect (~L498) and decrypt prefill (~L720) consume `Metadata`.
- [ ] Info unit test + inline-inspect app test for an AES Crypt fixture.

**GTK (`symcrypt-gtk`)**
- [ ] `info.rs`: rows/text accept `&Metadata`; AES Crypt rows.
- [ ] `app.rs`: `inspect_path`/`open_and_inspect` return `Metadata`; update 3 call sites; decrypt prefill.
- [ ] `info.rs` unit tests for an AES Crypt fixture; manual UI spot-check.

**Docs**
- [ ] DESIGN.md updated per [§9](#9-designmd-updates-required).
- [x] Security implications ([§4](#4-security-implications-confirm-before-implementing)) confirmed with the user (2026-06-07).
