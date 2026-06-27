# paladin — Implementation plan 05: AES Crypt read support

**Status:** **Implemented for Stream Format 1 and 2** across the core and all
three front-ends; **Stream Format 3 is deferred** (see [§12](#12-decisions)).
Adds **decryption, verification, and inspection of foreign
[AES Crypt](https://www.aescrypt.com/) (`.aes`) files**. Encryption to the AES
Crypt format is **out of scope** — paladin only ever *writes* its own container
(DESIGN §5).
**Last updated:** 2026-06-08.

**Scope.** Teach `paladin-core` to recognize an AES Crypt container, derive its
key with the AES Crypt KDFs, verify its HMACs, and stream out the plaintext, so
the four operations behave as follows on a `.aes` file:

| Operation              | Behavior on an AES Crypt file                                                |
| ---------------------- | --------------------------------------------------------------------------- |
| `decrypt` (`-d`)       | Detect, verify, and decrypt to the output.                                  |
| `verify` (`--verify`)  | Detect and verify the HMACs (decrypt-and-discard); write nothing.           |
| `inspect` (`-i`)       | Report unauthenticated AES Crypt metadata (version, KDF, extensions).       |
| `encrypt` (`-e`)       | **Unchanged** — always writes a paladin container; never AES Crypt.        |

Because the front-ends are thin (DESIGN §2.2), almost all of the work lands in
`paladin-core`; the front-ends only learn that `inspect` can now return a second
kind of metadata and that the default decrypt-output path can strip `.aes`.

**Depends on:** [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)
(core + common) and the implemented front-ends
([`02_CLI`](IMPLEMENTATION_PLAN_02_CLI.md),
[`03_TUI`](IMPLEMENTATION_PLAN_03_TUI.md),
[`04_GTK`](IMPLEMENTATION_PLAN_04_GTK.md)).

> **Security-affecting change — read [§4](#4-security-implications-confirm-before-implementing) first.**
> AES Crypt uses legacy KDFs, an **unauthenticated**
> header/extensions/legacy length byte, and CBC+HMAC rather than
> AEAD. Adding read support is an *interoperability* feature, not an endorsement;
> the implications and the tests that pin them are spelled out below and must be
> confirmed before implementation begins (repo policy, CLAUDE.md).

---

## Table of contents

1. [Goals & non-goals](#1-goals--non-goals)
2. [The AES Crypt file format (what we must read)](#2-the-aes-crypt-file-format-what-we-must-read)
3. [Design: where the work lives](#3-design-where-the-work-lives)
4. [Security implications (confirm before implementing)](#4-security-implications-confirm-before-implementing)
5. [Core changes (`paladin-core`)](#5-core-changes-paladin-core)
6. [CLI changes (`paladin`)](#6-cli-changes-paladin)
7. [TUI changes (`paladin-tui`)](#7-tui-changes-paladin-tui)
8. [GTK changes (`paladin-gtk`)](#8-gtk-changes-paladin-gtk)
9. [DESIGN.md updates required](#9-designmd-updates-required)
10. [Dependencies to add](#10-dependencies-to-add)
11. [Testing strategy & known-answer vectors](#11-testing-strategy--known-answer-vectors)
12. [Decisions](#12-decisions)
13. [Master checklist](#13-master-checklist)

---

## 1. Goals & non-goals

### Goals

- **Read interop.** Decrypt, verify, and inspect AES Crypt **Stream Format 1 and
  2** files (**implemented**). **Stream Format 3** (current AES Crypt 4.x output)
  is **deferred** until its KDF salt can be pinned from a real v3 fixture
  ([§12](#12-decisions)); a v3 file is rejected as `UnsupportedAesCryptVersion`.
  Version 0 is an optional stretch ([§12](#12-decisions)).
- **One core, thin front-ends — unchanged.** All format detection, KDF, and
  HMAC/CBC logic lives in `paladin-core`. Front-ends gain no crypto or format
  knowledge; `decrypt`/`verify` keep the *same signatures* and "just work" on a
  `.aes` file. Only `inspect`'s **return type** widens (it can now describe two
  formats), which the front-ends render.
- **Honest verification.** Verify HMAC-1 (key block) before producing any
  plaintext and HMAC-2 (body) before the output is finalized; map every failure
  to the single [`SymError::Auth`] condition, exactly as the paladin path does
  (DESIGN §4.4).
- **Same safety envelope.** Enforce the 64 GiB plaintext cap, bound every
  unauthenticated length before allocation, zeroize all key material.

### Non-goals

- **No AES Crypt encryption.** `encrypt` is untouched; paladin never emits a
  `.aes` file. (Re-encrypting a decrypted file with paladin's own format is the
  recommended migration — see [§4](#4-security-implications-confirm-before-implementing).)
- **No password compatibility shims** beyond the documented v1/v2 UTF-16LE
  encoding and v3 UTF-8 password text ([§2.4](#24-key-derivation-the-aes-crypt-kdfs));
  historical platform quirks of very old AES Crypt builds are a documented
  limitation, not a target.
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
| 3                          | 1          | `version`            | `0x01` / `0x02`.                                                   |
| 4                          | 1          | `reserved`           | `0x00` for v1/v2. (For **v0** this byte is the `fsmod`, §2.5.)    |
| 5                          | varies     | `extensions`         | **v2 only.** Repeated `(u16 len, len bytes)`; a `len == 0x0000` terminates. Absent in v1. |
| …                          | 16         | `iv1`                | IV for the key-wrap layer; also seeds the KDF.                   |
| …                          | 48         | `enc_keys`           | `AES-256-CBC(key1, iv1, iv2 ‖ key2)` — 16-byte `iv2` + 32-byte `key2`. |
| …                          | 32         | `hmac1`              | `HMAC-SHA256(key1, enc_keys)`.                                   |
| …                          | `N`·16     | `ciphertext`         | `AES-256-CBC(key2, iv2, plaintext padded to a 16-byte boundary)`. `N` ≥ 0; padding bytes are ignored on read. |
| …                          | 1          | `fsmod`              | Original plaintext length **mod 16** (`0..=15`); `0` means a full final block when ciphertext exists. |
| …                          | 32         | `hmac2`              | `HMAC-SHA256(key2, ciphertext)`.                                 |

The `ciphertext` length is not stored; it is *everything between `hmac1` and the
trailing 33 bytes* (`fsmod` + `hmac2`). The decryptor therefore buffers the last
33 bytes to find the boundary (§5.5).

### 2.2 Container layout (version 3)

| Offset (v3)                | Size       | Field                | Notes                                                            |
| -------------------------- | ---------- | -------------------- | ---------------------------------------------------------------- |
| 0                          | 3          | `magic`              | ASCII `"AES"` (`0x41 0x45 0x53`).                                 |
| 3                          | 1          | `version`            | `0x03`.                                                           |
| 4                          | 1          | `reserved`           | `0x00`.                                                           |
| 5                          | varies     | `extensions`         | Same extension block framing as v2 (§2.3).                       |
| …                          | 4          | `kdf_iterations`     | Big-endian PBKDF2-HMAC-SHA512 iteration count.                   |
| …                          | 16         | `iv1`                | IV for the key-wrap layer.                                        |
| …                          | 48         | `enc_keys`           | `AES-256-CBC(key1, iv1, iv2 ‖ key2)` — 16-byte `iv2` + 32-byte `key2`. |
| …                          | 32         | `hmac1`              | `HMAC-SHA256(key1, enc_keys ‖ 0x03)`.                             |
| …                          | `N`·16     | `ciphertext`         | `AES-256-CBC(key2, iv2, PKCS#7-padded plaintext)`. `N` ≥ 1.      |
| …                          | 32         | `hmac2`              | `HMAC-SHA256(key2, ciphertext)`.                                 |

The v3 body has no `fsmod` byte. The ciphertext is everything after `hmac1`
except the trailing 32-byte `hmac2`, so the decryptor uses a 32-byte trailer
buffer for v3 and removes PKCS#7 padding from the final decrypted block after
`hmac2` verifies.

### 2.3 Extensions (v2/v3)

Each extension is a 2-byte big-endian length followed by that many content bytes;
content is conventionally `identifier ‖ 0x00 ‖ data`. Common ones: `CREATED_BY`
(e.g. `"AES Crypt 3.x"`) and a 128-byte zero-filled "container" extension used as
reserved padding. **Extensions are not authenticated** (§4). The reader bounds
the total extension bytes it will buffer and the count it will parse (§5.6); it
keeps a sanitized `CREATED_BY` value for `inspect` and ignores the rest.

### 2.4 Key derivation (the AES Crypt KDFs)

For v1/v2, `key1` is derived from the password and `iv1` with an iterated
SHA-256 — **not** Argon2/scrypt/PBKDF2:

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

For v3, `key1` is derived with PBKDF2-HMAC-SHA512 using the 4-byte iteration
count stored in the header and `iv1` as the salt:

```
pw8    = UTF-8(password)
key1   = PBKDF2-HMAC-SHA512(pw8, salt = iv1, iterations = kdf_iterations, dkLen = 32)
```

> **Provisional — confirm from a fixture.** The public AES Crypt stream-format
> page documents PBKDF2-HMAC-SHA512, the `‖ 0x03` HMAC input, and PKCS#7 padding,
> but it does **not** state the PBKDF2 *salt*. `salt = iv1` (and `dkLen = 32`, and
> `key1` keying both `hmac1` and the `enc_keys` unwrap) is unverified against the
> spec and must be pinned from a real v3 fixture in the §5.10 step-2 KDF-vector
> test *before* any v3 body code is written — a wrong salt means nothing decrypts.

The v3 `kdf_iterations` value is unauthenticated until `hmac1` verifies; accept
only `1..=10_000_000` before use so hostile inputs cannot force unbounded CPU
work (≈33× the reference tool's 300,000 default, so any realistic file is accepted
while CPU-DoS stays bounded). Out-of-range values are `MalformedHeader` in
`decrypt`/`verify`; `inspect` reports the raw value without enforcing the bound
(it derives no key — §5.8).

> **Password encoding.** paladin front-ends capture the password as UTF-8 bytes
> (DESIGN §6.4). For AES Crypt v1/v2 we validate those bytes as UTF-8 text and
> re-encode the text as **UTF-16LE** per the legacy format. For v3 we use the
> UTF-8 bytes directly. ASCII passwords interoperate cleanly; non-ASCII passwords
> depend on the writer having used the same Unicode encoding, which very old or
> non-standard AES Crypt builds did not always do — a documented limitation, not
> a bug. On the AES Crypt path, a `--password-file` that is not valid UTF-8 is
> rejected with `InvalidOptions`; UTF-16/BOM AES Crypt key files are out of
> scope for this implementation. CLI `--password-file` keeps the existing
> paladin behavior: exactly one trailing LF or CRLF is stripped before the core
> sees the password bytes, and AES Crypt UTF-8 validation applies after that
> trim. Byte-exact AES Crypt password files whose intended password ends with a
> newline are out of scope.

### 2.5 Version 0 (optional, §12)

A single-key variant with **no extensions and no key wrap**: `"AES"`, `0x00`,
then `fsmod` (1 byte) at offset 4, `iv` (16), `ciphertext`, `hmac` (32). The key
is the v1/v2 KDF output used *directly* for both the body CBC and the single HMAC;
there is no `hmac1`/`enc_keys` layer, so a wrong password is only caught by the
final HMAC. Supporting it is cheap but its test vectors are harder to source
(current AES Crypt 4.x writes Stream Format 3).

---

## 3. Design: where the work lives

### 3.1 Format detection & dispatch

After armor is stripped (an AES Crypt file is binary and passes
`armor::auto_dearmor` through untouched), the core peeks the leading bytes and
dispatches:

- `"PALADIN"` → the existing paladin path (`header::parse` + `stream::*`).
- `"AES"` → the new `aescrypt` path; that parser reports
  `UnsupportedAesCryptVersion(version)` when the version byte is not supported.
- anything else → [`SymError::BadMagic`] (exit 4), with the user-facing message
  updated to say the input is neither a paladin nor AES Crypt file.

Detection reads a small fixed prefix (≤ 8 bytes) and re-attaches it with
`std::io::Read::chain` so the chosen parser sees the full stream. A new private
`format` module owns the peek-and-dispatch; `lib.rs::{decrypt, verify, inspect}`
call it instead of going straight to `stream`/`header`.

### 3.2 `inspect` returns a format-tagged enum

`inspect` currently returns a paladin-only [`Header`]. It must now describe
*either* format, so its return type becomes a small enum:

```rust
/// Unauthenticated metadata for whichever container `inspect` recognized.
pub enum Metadata {
    Paladin(Header),            // existing struct, unchanged
    AesCrypt(AesCryptHeader),    // new (version, KDF, extension count, …)
}

pub fn inspect<R: Read>(input: R) -> Result<Metadata>;
```

This is the **one breaking change** to the core API. Every `inspect` call site
renders the result by matching the enum (call sites enumerated in
[§6](#6-cli-changes-paladin)–[§8](#8-gtk-changes-paladin-gtk)). `decrypt` and
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
| 1 | **Legacy KDFs.** v1/v2 use 8192-iteration SHA-256, and v3 uses PBKDF2-HMAC-SHA512 with an unauthenticated iteration count. These are fixed by the file we are reading and are not paladin's chosen KDFs. | Read-only. Bound v3 iterations before deriving (§2.4). Docs/help recommend **re-encrypting** decrypted data with paladin's own format. No paladin file is ever written with these KDFs. |
| 2 | **Unauthenticated header.** `magic`, `version`, `reserved`, v3 `kdf_iterations`, and all **extensions** are outside both HMACs. An attacker can flip the version byte, rewrite extensions, or alter the v3 KDF work factor before authentication. This is a property of the foreign format, not fixable on read. | Treat all header/extension data as *unauthenticated even after a successful decrypt*. `inspect` labels it so. We bound and sanitize extensions, bound v3 iterations, and never act on extension contents. |
| 3 | **Unauthenticated v1/v2 `fsmod`.** The length-mod-16 byte sits outside `hmac2`, so the last block's *visible length* is malleable by up to 15 bytes (the bytes themselves are authentic). | Validate `fsmod < 16` and that it is consistent with the block count (`fsmod == 0` when there are zero body blocks; `fsmod == 0` means 16 final bytes when blocks exist). Document the residual malleability. v3 has no `fsmod`; it uses authenticated ciphertext plus PKCS#7 padding checked after `hmac2`. |
| 4 | **CBC + late MAC.** `hmac2` covers the body and sits *after* it, so a pure verify-before-output design would need two passes (impossible for stdin). We stream-decrypt while computing `hmac2`, then verify at end. | Plaintext is written to the front-end's **temp file** and only renamed on success; an `Auth` failure discards it (DESIGN §2.2). For `-o -` (stdout) partial plaintext may appear before the check — the *same* caveat paladin already documents (DESIGN §11). Verify `hmac2` before applying v3 PKCS#7 padding so there is no padding oracle; never deliver unverified plaintext to a file. |
| 5 | **`hmac1` first.** For v1/v2/v3, a wrong password yields a wrong `key1`, so `hmac1` fails **before any body byte is processed** — wrong-password is caught early (exit 3) with no output. | Verify `hmac1` immediately after KDF, before touching the body. For v3 the `hmac1` input is `enc_keys ‖ 0x03` (§2.2). |
| 6 | **Constant-time tag checks.** A non-constant-time compare could leak. | Use the RustCrypto `Mac::verify_slice` (constant-time); never compare tags with `==`. |
| 7 | **Resource bounds on hostile input.** A crafted file could claim huge/streamed extensions, a huge v3 KDF iteration count, or an enormous body. | Cap total extension bytes and count (§5.6); cap v3 iterations (§2.4); enforce the 64 GiB plaintext cap during streaming. |
| 8 | **No paladin-style keyfile component.** AES Crypt key-file workflows are password-source workflows, not a separate format-bound secret like paladin's `-k`. Silently ignoring or blending a supplied `-k` would mislead the user. | If a `.aes` file is detected and the `Secret` carries keyfile material (or has no password, e.g. keyfile-only mode), reject with `InvalidOptions` (exit 2). Users who have an AES Crypt key file may pass it as `--password-file` only when it is UTF-8 text; UTF-16/BOM key files are out of scope. |

---

## 5. Core changes (`paladin-core`)

All new code is library code with exhaustive unit + KAT tests (DESIGN §10). TDD:
write the failing test first, then the implementation.

### 5.1 New / changed modules

```
crates/paladin-core/src/
├── lib.rs        # CHANGED: decrypt/verify/inspect dispatch by format; export Metadata, AesCryptHeader
├── format.rs     # NEW: peek leading bytes, return Format + a re-chained Read; the dispatch point
├── aescrypt.rs   # NEW: AES Crypt header parse, KDFs, CBC+HMAC verify/decrypt/inspect (the bulk)
├── secret.rs     # CHANGED: add pub(crate) password_bytes() accessor (AES Crypt password text validation/encoding)
├── paths.rs      # CHANGED: default_decrypt_output strips .aes too; add default_aescrypt_output(input)
├── error.rs      # CHANGED: add UnsupportedAesCryptVersion(u8)
├── header.rs     # unchanged (paladin header)
├── cipher.rs     # unchanged (AEAD); AES Crypt CBC lives in aescrypt.rs
├── kdf.rs        # unchanged (paladin KDFs); AES Crypt KDF lives in aescrypt.rs
├── stream.rs     # unchanged
└── armor.rs      # unchanged
```

Keeping AES Crypt's CBC, HMAC, and bespoke KDF in a self-contained `aescrypt.rs`
mirrors the existing one-concern-per-module layout and avoids entangling the
audited paladin primitives with the legacy format.

### 5.2 Error surface (`error.rs` + `paladin-common`)

- Add one variant: `UnsupportedAesCryptVersion(u8)` →
  `#[error("unsupported AES Crypt version: {0:#04x}")]`, mapped to **exit 4** in
  `paladin-common::exit_code` (alongside the other format errors). The enum is
  already `#[non_exhaustive]`, so this is additive.
- Update the existing `BadMagic` display/docs from "not a paladin file" to a
  format-neutral message such as "not a recognized paladin or AES Crypt file",
  because foreign inputs are now classified after checking both magics.
- Reuse existing variants everywhere else:
  - bad/short `"AES"` header, nonzero v1/v2/v3 `reserved`, bad extension
    framing, out-of-range lengths, bad `fsmod`, or out-of-range v3
    `kdf_iterations` → `MalformedHeader(&'static str)` (exit 4);
  - any HMAC mismatch, a body too short to hold the trailer, a ciphertext run
    not a multiple of 16, or invalid v3 PKCS#7 padding after `hmac2` verifies →
    `Auth` (exit 3) — never distinguished from a wrong password (DESIGN §4.4);
  - keyfile-present / password-absent / non-UTF-8 password bytes against a `.aes`
    file → `InvalidOptions` (exit 2);
  - plaintext over 64 GiB → `InputTooLarge` (exit 1);
  - cancellation via `on_progress` → `Canceled` (exit 130);
  - caller `Read`/`Write` failures → `Io` (exit 1).
- **Test (common):** extend `core_errors_map_to_their_exit_codes` so
  `UnsupportedAesCryptVersion(4)` maps to 4.

### 5.3 `Secret` accessor (`secret.rs`)

The AES Crypt KDFs need the **raw password bytes** so the AES path can validate
them as UTF-8 text, re-encode v1/v2 as UTF-16LE, and feed v3 as UTF-8. They must
also reject keyfiles; the paladin `kdf_input()` blend is wrong here. Add:

```rust
impl Secret {
    /// Raw password bytes (for AES Crypt password-text validation and encoding).
    pub(crate) fn password_bytes(&self) -> &[u8] { &self.password }
    // has_keyfile() already exists.
}
```

The `aescrypt` decryptor rejects `secret.has_keyfile()` and an empty
`password_bytes()` with `InvalidOptions` before deriving (implication #8). It
also rejects `password_bytes()` that are not valid UTF-8, which matters for
CLI `--password-file` because paladin password files are otherwise raw bytes. A
`.aes` file written with a genuinely empty password is therefore unreadable by
paladin — a documented limitation. **Test:** keyfile-bearing, password-less, or
non-UTF-8 password-file `Secret` against a fixture `.aes` returns
`InvalidOptions`.

### 5.4 Format detection (`format.rs`)

```rust
pub(crate) enum Format { Paladin, AesCrypt }

/// Peek the magic and return the format plus a reader that still yields the
/// peeked bytes. A complete non-matching prefix is BadMagic; a short input that
/// is a prefix of a supported magic is MalformedHeader.
pub(crate) fn detect<R: Read>(input: R) -> Result<(Format, impl Read)>;
```

Reads up to 8 bytes, matches `"PALADIN"` vs `"AES"`, and returns
`prefix.chain(input)`. **Tests:** paladin magic, AES magic (including an
unsupported AES version routed to the AES parser), short recognized-prefix input,
and foreign magic each classified correctly; the re-chained reader reproduces
the original bytes.

### 5.5 AES Crypt decrypt/verify (`aescrypt.rs`)

Single streaming routine shared by decrypt (writes plaintext) and verify
(discards it), parameterized like `stream::{decrypt, verify}`:

1. **Parse the unauthenticated header** (§2.1): `"AES"`, `version` (else
   `UnsupportedAesCryptVersion`), `reserved == 0x00`, extensions (v2/v3, §5.6),
   optional v3 `kdf_iterations`, `iv1`, `enc_keys` (48), `hmac1` (32). Report
   `on_progress` once after the header.
2. **Reject incompatible secrets** (implication #8).
3. **Validate and encode the password text** (§2.4): reject non-UTF-8 password
   bytes with `InvalidOptions` (empty and keyfile-bearing secrets are already
   rejected in step 2); encode UTF-16LE for v1/v2 and UTF-8 for v3.
4. **Derive `key1`** with the version-specific §2.4 KDF, in `Zeroizing` buffers.
   Honor cancellation before/after. For v3, validate the unauthenticated
   `kdf_iterations` bound before running PBKDF2.
5. **Verify `hmac1`** with `Mac::verify_slice` → `Auth` on mismatch (this is the
   early wrong-password gate, implication #5). The input is `enc_keys` for v1/v2
   and `enc_keys ‖ 0x03` for v3.
6. **Unwrap keys:** AES-256-CBC-decrypt `enc_keys` with (`key1`, `iv1`) → `iv2`,
   `key2` (zeroized). Build the body HMAC `HMAC-SHA256(key2, …)`.
7. **Stream the body with a version-specific trailer buffer** (§5.7): v1/v2 keep
   the last 33 bytes (`fsmod ‖ hmac2`), while v3 keeps the last 32 bytes
   (`hmac2`). Treat only bytes before that trailer as ciphertext, feeding each
   complete 16-byte ciphertext block to `hmac2` and CBC-decrypting it with
   `key2`/chaining IV. Reads may split blocks arbitrarily, so keep a small
   ciphertext-block buffer between reads; leftover non-trailer ciphertext bytes
   at EOF mean the ciphertext run is not a multiple of 16 and return `Auth`.
   **Defer each block's plaintext write by one block** (hold the most recently
   decrypted block back): the final block needs `fsmod` truncation (v1/v2) or
   PKCS#7 unpadding (v3), and which block is final is not known until EOF.
   Enforce the 64 GiB plaintext cap from bytes actually produced. Report
   `on_progress` and observe cancellation per read buffer (the STREAM path's
   granularity), not per 16-byte block, so progress callbacks don't dominate
   runtime on large files.
8. **At EOF:** require the consumed ciphertext to be a multiple of 16; for v3
   require at least one ciphertext block (PKCS#7 always emits a full block, even
   for empty plaintext). Verify `hmac2` with `verify_slice` before processing the
   final plaintext block. On mismatch return `Auth`.
9. **Finalize the held-back block:** for v1/v2, validate `fsmod` (§4,
   implication #3), then write `fsmod` bytes from the final block when
   `fsmod != 0`, or all 16 bytes when `fsmod == 0` and at least one ciphertext
   block was present. If there were no ciphertext blocks, require `fsmod == 0`
   and write nothing. Do not validate v1/v2 padding byte values; the legacy
   format only stores `fsmod`, and non-PKCS#7 final-block filler must not become
   a compatibility failure. For v3, remove PKCS#7 padding from the final block
   after `hmac2` verification; invalid padding returns `Auth`. Deferring the
   final block is **required** — the core's `Write` is not seekable, so
   final-block truncation/unpadding cannot be undone after the bytes are written
   (notably for `-o -`); deferring *all* plaintext until the MAC check is also
   sound but unnecessary given temp-file finalization.

`verify` runs the identical path with a sink that discards writes.

### 5.6 Extension parsing & bounds (`aescrypt.rs`)

- Read `(u16 len, len bytes)` repeatedly until `len == 0`.
- Bound **total extension content bytes** to 256 KiB and **extension count** to
  1024; exceeding either is `MalformedHeader` (a hostile file cannot force
  unbounded buffering — implication #7).
- Retain a sanitized `CREATED_BY` value for `inspect`; ignore the rest. Parse
  extension content as `identifier ‖ 0x00 ‖ data`, use the first extension whose
  identifier is exactly `CREATED_BY`, and treat absent, malformed, or non-UTF-8
  `data` as no value (`created_by: ` renders empty). For valid UTF-8 `data`,
  replace Unicode control characters with `?` and cap the display value at 256
  `char`s. Never interpret extension contents as paths or commands.

### 5.7 The trailer-buffer technique (why)

The v1/v2 body is `ciphertext ‖ fsmod(1) ‖ hmac2(32)`; the v3 body is
`ciphertext ‖ hmac2(32)`. Neither stores the ciphertext length. To find where
ciphertext ends without a second pass, keep the most recent 33 bytes buffered
for v1/v2 and 32 bytes for v3, and only treat earlier bytes as ciphertext. When
the stream ends, the buffer holds exactly the trailer. Feed released ciphertext
through a separate 16-byte block buffer before HMAC/CBC processing so arbitrary
`Read` chunking cannot create partial-block decrypt calls. Separately, hold the
most recently *decrypted* block's plaintext back by one block so the final block
can be truncated by `fsmod` (v1/v2; `0` means a full final block when at least
one ciphertext block exists) or PKCS#7-unpadded (v3) before it is written
(§5.5 step 7–9) — the core's `Write` is not seekable, so a write cannot be
taken back. Too few trailing bytes total, a ciphertext run not divisible by 16,
or a v3 body with no ciphertext block is `Auth` (truncation is indistinguishable
from tampering, DESIGN §5.5). Unit-test the boundary at plaintext sizes
`0, 1, 15, 16, 17, 31, 32, and several blocks` for both v1/v2 `fsmod` and v3
PKCS#7 padding.

### 5.8 `inspect` for AES Crypt (`aescrypt.rs` + `lib.rs`)

`AesCryptHeader { version: u8, kdf: AesCryptKdf, extension_count: usize, created_by: Option<String> }`
(no key material; unauthenticated). `AesCryptKdf` records `Sha256 { iterations: 8192 }`
for v1/v2 and `Pbkdf2HmacSha512 { iterations }` for v3. `inspect` parses through
`hmac1` **without a password** and returns `Metadata::AesCrypt(_)`. For v3 it
reports the raw header `kdf_iterations` **without** enforcing the `1..=10_000_000`
bound (it derives no key, so a hostile work factor is surfaced rather than
rejected); only `decrypt`/`verify` enforce the bound before deriving `key1`. Stable
`--info` field order (rendered by the front-ends, §6):

```
format: aescrypt
version: <decimal>
cipher: aes-256-cbc
kdf: aescrypt-sha256 | pbkdf2-hmac-sha512
kdf_iterations: <8192 or v3 header value>
extensions: <count>
created_by: <sanitized value or empty>
authenticated: false
```

`authenticated: false` makes implication #2 explicit in the output. **Test:**
byte-exact block for v2 and v3 fixtures with and without `CREATED_BY`.

### 5.9 Path helpers (`paths.rs`)

- `default_aescrypt_output(input: &Path) -> PathBuf`: strip a trailing `.aes`
  (case-sensitive), else append `.dec`, with the same empty-basename fallback as
  the paladin helper (`.aes` → `.aes.dec`). Supported AES Crypt stream formats
  have no authenticated stored filename, so there is no name-from-header branch.
- **Add `.aes`** to the existing shared `strip_encrypt_suffix` helper (today:
  `.paladin.asc`, `.paladin`, `.asc`) so a paladin file inadvertently named
  `*.aes` also strips sensibly.
- **Tests:** `secret.aes → secret`, `secret → secret.dec`, `.aes → .aes.dec`,
  non-UTF-8 input → `.dec` appended (mirrors existing `paths.rs` tests).

### 5.10 `lib.rs` wiring & ordered steps (TDD)

1. **Deps & module skeleton** — add `aes`, `cbc`, `hmac` ([§10](#10-dependencies-to-add));
   create `format.rs`/`aescrypt.rs`; export `Metadata`, `AesCryptHeader`.
2. **KDFs** — implement and test the §2.4 v1/v2 SHA-256 derivation and v3
   PBKDF2-HMAC-SHA512 derivation against known vectors (derive `key1` from a
   fixed password + `iv1`; lock the bytes). **Confirm the provisional v3
   `salt = iv1` here** (§2.4): derive the vector from a real v3 fixture's `iv1`
   and require its `hmac1` to verify. The salt is not in the public spec, so this
   step gates all later v3 work.
3. **Header parse + extensions + v3 iterations** — parse/validate; bounds tests
   (§5.6).
4. **`hmac1` + key unwrap** — verify-then-unwrap for v1/v2 (`enc_keys`) and v3
   (`enc_keys ‖ 0x03`); wrong-password → `Auth`.
5. **Body stream + trailer buffer + `fsmod`/PKCS#7 + `hmac2`** — round-trip real
   `.aes` fixtures; tamper/truncate/append tests.
6. **`format::detect` + dispatch in `decrypt`/`verify`/`inspect`** — including
   the `inspect` enum migration and updating core's own `lib.rs` tests.
7. **`inspect` for AES Crypt + path helper** — `--info` block; `.aes` stripping.
8. **Size cap, cancellation, secret-rejection** — parity with the STREAM path.
9. `cargo fmt` + `cargo clippy --all-targets --all-features` clean; full KATs
   ([§11](#11-testing-strategy--known-answer-vectors)).

---

## 6. CLI changes (`paladin`)

The CLI gains **no new flags**; `-d`/`--verify`/`-i` transparently handle `.aes`
files once the core dispatches. The concrete edits:

| Area | File | Change |
| ---- | ---- | ------ |
| Decrypt default output | `crates/paladin-cli/src/run.rs` (`run_decrypt`, ~L109–116) | The no-`-o` branch already peeks `core::inspect`. Match the new `Metadata`: `Paladin(h)` → `default_decrypt_output(input, &h)` (today's call); `AesCrypt(_)` → `default_aescrypt_output(input)`. |
| Info rendering | `crates/paladin-cli/src/info.rs` (`format_info`) | Take `&Metadata` and branch: existing 12-line paladin block, or the §5.8 AES Crypt block. Keep both stable and test byte-exact for v1/v2/v3. |
| Info dispatch | `crates/paladin-cli/src/run.rs` (`run_info`, ~L165) | `core::inspect` now returns `Metadata`; pass it to `info::format_info`. |
| Friendlier keyfile error | `crates/paladin-cli/src/run.rs` / `crates/paladin-cli/src/secret.rs` | For non-stdin `decrypt` and `verify`, if `-k` or `--no-password` was supplied, inspect the input before reading the keyfile or prompting; if it is `AesCrypt`, fail early with a clear "AES Crypt files don't use paladin keyfiles; use a UTF-8 --password-file for compatible AES Crypt key files" usage message. The decrypt-without-`-o` path reuses the existing metadata peek; decrypt-with-`-o` and verify open/inspect/reopen before secret resolution. Stdin inputs keep the core `InvalidOptions` backstop because pre-inspection would require buffering the stream. |
| Help / docs | `crates/paladin-cli/src/cli.rs` help text, man page, README | Note that `-d`/`--verify`/`-i` auto-detect AES Crypt (`.aes`) files, that encryption always uses paladin's format, that AES Crypt key files may be passed as `--password-file` only when they are UTF-8 text, and recommend re-encrypting decrypted data (implication #1). |

**Integration tests** (`tests/cli.rs`, `assert_cmd` + a committed `.aes`
fixture, §11):

- `-d sample.aes` with the right password → exit 0, plaintext matches; default
  output strips `.aes`.
- Wrong password → exit 3; truncated/tampered body → exit 3.
- `version` byte set to an unsupported value → exit 4.
- `-k key -d sample.aes`, `-k key -d sample.aes -o out`, and
  `-k key --verify sample.aes` → exit 2 before prompting; `--no-password -k …`
  on a `.aes` file → exit 2.
- `--password-file` containing non-UTF-8 bytes on a `.aes` file → exit 2.
- `--verify sample.aes` success/failure (0 vs 3).
- `-i sample.aes` → exact AES Crypt `--info` block (incl. `authenticated: false`).
- Quiet/verbose unaffected; `-o -` streams plaintext.

---

## 7. TUI changes (`paladin-tui`)

Decrypt and Verify run through the worker → `core::{decrypt, verify}`
(`crates/paladin-tui/src/worker.rs`, unchanged) and work automatically. Only
the **Info** path and the **decrypt-output prefill** touch the widened `inspect`
return type.

| Area | File | Change |
| ---- | ---- | ------ |
| Info rendering | `crates/paladin-tui/src/info.rs` (`format_info(&Header) -> Vec<String>`) | Change to `format_info(&Metadata)` and branch to paladin vs AES Crypt rows (§5.8). |
| Inline inspect | `crates/paladin-tui/src/app.rs` (~L498–503) | `core::inspect(&mut r)` now yields `Metadata`; pass to `format_info`. |
| Decrypt prefill | `crates/paladin-tui/src/app.rs` (`sync_paths`, Decrypt branch ~L720–726) | The branch inspects to prefill the output name; match `Metadata`: `Paladin(h)` → `default_decrypt_output`; `AesCrypt(_)` → `default_aescrypt_output`. Update the current `Err(_)` fallback to format-neutral wording such as "not a recognized paladin or AES Crypt file; enter the output path"; it now fires only for genuinely unrecognized inputs (a `.aes` file inspects successfully). |
| Keyfile field | (no code change) | A keyfile + a `.aes` file surfaces the core `InvalidOptions` as the existing error status; document it. Optionally disable the keyfile field once Info reveals an AES Crypt input — a nicety, not required. |

**Tests:** extend the existing `info.rs` unit test so `format_info` renders an
AES Crypt `Metadata` (build the fixture by inspecting committed `.aes` bytes);
keep the paladin assertions. The `info_mode_inline_inspect_populates_results`
app test gets an AES Crypt counterpart. Per DESIGN §10, headless TUI coverage
stays light and leans on the core tests.

---

## 8. GTK changes (`paladin-gtk`)

Same shape as the TUI: Decrypt/Verify run as relm4 commands calling
`core::{decrypt, verify}` and need no change; Info and the decrypt-output prefill
consume the new `Metadata`.

| Area | File | Change |
| ---- | ---- | ------ |
| Info rendering | `crates/paladin-gtk/src/info.rs` (`header_rows`/`header_text`, take `&Header`) | Accept `&Metadata` (or add `aescrypt_rows`/`metadata_rows`) and render the §5.8 AES Crypt rows; keep `InfoRow`/order parity with the CLI. |
| Inspect helpers | `crates/paladin-gtk/src/app.rs` (`inspect_path` ~L252, `open_and_inspect` ~L1034) | Return `Result<Metadata, …>` instead of `Result<Header, …>`; update the three call sites (decrypt prefill ~L238–240, info prefill ~L266–267, Run/Info ~L929–930). |
| Decrypt prefill | `crates/paladin-gtk/src/app.rs` (`refresh_output`, ~L238–240) | Match `Metadata`: `Paladin(h)` → `default_decrypt_output(&input, &h)`; `AesCrypt(_)` → `default_aescrypt_output(&input)`. |
| Info text | `crates/paladin-gtk/src/app.rs` (~L267, ~L930) | `info::header_text` → `info::metadata_text(&meta)`. |
| Error messages | `crates/paladin-gtk/src/message.rs` | GTK renders `SymError` through its own message mapper, so update `BadMagic` to the format-neutral wording and add an explicit `UnsupportedAesCryptVersion` message/test instead of letting it fall through to the generic future-variant text. |
| Keyfile chooser | (no code change) | Core `InvalidOptions` is surfaced via the existing toast/error dialog; drag-and-drop of a `.aes` file decrypts normally. |

**Tests:** the `info.rs` unit tests (pure, no display) gain AES Crypt cases
(build `Metadata` by inspecting committed `.aes` bytes; assert rows/text), and
`message.rs` covers the new/updated AES Crypt error messages. GTK UI behavior
stays on manual verification plus the shared core tests (DESIGN §10).

---

## 9. DESIGN.md updates required

`docs/DESIGN.md` is the source of truth (CLAUDE.md), so it changes alongside the
code:

- **New subsection (e.g. §5.8 "AES Crypt read interop")**: the §2 format summary,
  supported versions, the v1/v2 and v3 KDFs, encrypt-then-MAC verification, and
  the unauthenticated-header caveat.
- **§2.3 API sketch:** `inspect` now returns `Metadata` (enum over
  `Header`/`AesCryptHeader`); note `default_aescrypt_output`.
- **§6.2 `--info`:** document `format: aescrypt` and its field block, including
  version-specific `kdf`, `kdf_iterations`, and `authenticated: false`.
- **§6.5 output defaults:** decrypt strips `.aes`.
- **§6.4 password sources:** document that AES Crypt `--password-file` input must
  be valid UTF-8 text after the existing one-trailing-newline trim; UTF-16/BOM
  AES Crypt key files and byte-exact password files that intentionally end with
  a newline are not supported.
- **§6.6 errors:** add `UnsupportedAesCryptVersion` → exit 4; keyfile-with-`.aes`,
  password-less `.aes`, and non-UTF-8 AES Crypt password file → exit 2.
- **§9 dependencies:** add `aes`, `cbc`, `hmac` (core).
- **§10 testing:** AES Crypt v1/v2/v3 KATs, wrong-password, tamper, version handling.
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
| `hmac` | HMAC-SHA256 over the key block and body; `verify_slice` for constant-time checks. | Must match the `digest` generation of the in-tree `sha2 0.11` (i.e. the `hmac` release built on `digest 0.11`). `sha2` is already a dependency; reuse it for SHA-256 and SHA-512. |

The existing `pbkdf2` dependency handles v3 PBKDF2-HMAC-SHA512. UTF-16LE
encoding uses `str::encode_utf16` (std), and v3 PKCS#7 unpadding comes from the
`cipher` traits re-exported by `cbc`; no extra crates are needed for either. No
new dev-deps beyond the existing `hex`/`tempfile` for KAT fixtures.

> **Watch the `digest`/`cipher` split.** `sha2 0.11` is the newer `digest 0.11`
> generation, while `aes-gcm 0.10` is the `cipher 0.4` generation. Pick `hmac`
> against `sha2`'s generation and `cbc`/`aes` against `aes-gcm`'s; they need not
> match each other. If `cargo add` surfaces a conflict, align versions rather
> than vendoring duplicate trait crates.

---

## 11. Testing strategy & known-answer vectors

Most coverage is in `paladin-core` (DESIGN §10). Commit small fixtures under
`crates/paladin-core/tests/` (or `data/`).

**Known-answer vectors (the anchor).** Generate v3 `.aes` fixtures with the
current reference AES Crypt tool, and generate v2 fixtures with an AES Crypt
version/tool that can still emit Stream Format 2. Cover plaintext sizes
`0, 1, 15, 16, 17, a few KiB` and passwords (ASCII; one non-ASCII
documented-limitation case). Commit ciphertext + expected plaintext + password.
Tests assert exact round-trip. Document the exact tool version/command used to
mint them so they can be regenerated. (v1 can be hand-derived from a v2 fixture
by dropping the extensions block and flipping the version byte — neither is under
a MAC; v0, if pursued, needs its own source.)

**KDF vectors.** Lock `key1` for fixed (`password`, `iv1`) inputs for both the
v1/v2 SHA-256 KDF and the v3 PBKDF2-HMAC-SHA512 KDF so neither derivation can
drift silently. The v3 vector also pins the provisional `salt = iv1` assumption
(§2.4): mint it from a real v3 fixture and require `hmac1` to verify, so a wrong
salt fails immediately rather than after the body code is written.

**Round-trip.** Decrypt each committed fixture → byte-exact plaintext, across the
sizes above (exercises the trailer buffer, `fsmod`, empty body, multi-block).

**Negative / tamper (each → `Auth`, exit 3):**

- Wrong password for v1/v2 and v3 (fails at `hmac1`, before any output).
- Flip a byte in the body; flip a byte in `enc_keys`.
- Truncate the last block; drop the trailer; append bytes.
- Body length not a multiple of 16.
- v3 invalid PKCS#7 padding in an otherwise authenticated fixture → `Auth`.

**Format / malformed (→ exit 4):**

- `version` byte unsupported → `UnsupportedAesCryptVersion`.
- Nonzero v1/v2/v3 `reserved` byte → `MalformedHeader`.
- v3 `kdf_iterations` outside the accepted bound → `MalformedHeader`.
- Extension framing overruns / exceeds the size or count bound →
  `MalformedHeader`.
- `fsmod ≥ 16`, or `fsmod ≠ 0` with zero body blocks → `MalformedHeader`.
- Header truncated mid-field → `MalformedHeader`.

**Usage (→ exit 2):** keyfile-bearing, password-less, or non-UTF-8-password
`Secret` against a `.aes` file → `InvalidOptions`.

**Caps & control flow:** an authenticated body exceeding 64 GiB →
`InputTooLarge` (synthesize without a 64 GiB file, as the STREAM tests do);
`on_progress` → `Break` yields `Canceled` on the AES Crypt path too.

**Front-ends:** CLI `assert_cmd` cases (§6); TUI/GTK `info` rendering unit tests
(§7–§8). After changes: `cargo fmt`, `cargo clippy --all-targets --all-features`
(no warnings), `cargo test`.

---

## 12. Decisions

Resolved 2026-06-07; v3 KDF-salt, `inspect`-bound, and iteration-ceiling
clarifications added 2026-06-08.

- **Version 3 support — deferred (revised 2026-06-08).** v3 was planned as
  required (current AES Crypt 4.x writes Stream Format 3), but the only AES Crypt
  tool available to mint fixtures (`aescrypt 3.16.1`) writes Stream Format 2, and
  the v3 PBKDF2 salt is not stated in the public spec — so v3 body code cannot be
  written until its salt is pinned from a real v3 fixture (the gate below). v1/v2
  ship now with genuine fixtures; v3 (PBKDF2-HMAC-SHA512, a bounded unauthenticated
  iteration count, `hmac1` over `enc_keys ‖ 0x03`, PKCS#7 body padding) is rejected
  as `UnsupportedAesCryptVersion` until a v3 fixture or v3-capable tool is
  available. The v1/v2 design below is structured so v3 slots in without rework.
- **Version 0 support — deferred.** v1/v2/v3 cover the targeted real-world
  interoperability set; v0 adds a separate single-key path and is hard to KAT
  (no modern writer). Add v0 only if a concrete need appears (§2.5).
- **`inspect` returns the `Metadata` enum.** Widening `inspect` to `Metadata` is
  the one breaking change; it touches the CLI/TUI/GTK info renderers and a few
  app call sites (all enumerated in §6–§8). The rejected alternative — a separate
  `inspect_aescrypt` plus a format probe — only moves the churn and forces
  front-ends to detect the format themselves, violating the thin-front-end rule.
  The enum keeps detection in core.
- **`--info` `cipher`/`kdf` labels — confirmed.** AES Crypt always displays
  `cipher: aes-256-cbc`; `kdf` is `aescrypt-sha256` for v1/v2 and
  `pbkdf2-hmac-sha512` for v3, with a separate `kdf_iterations` line. These are
  display-only strings (not the paladin `CipherId`/`KdfId` enums) and won't be
  accepted by `-c`/`--kdf`.
- **Friendlier pre-prompt keyfile rejection in the CLI (§6) — included.** For
  non-stdin `decrypt` and `verify`, if `-k` or `--no-password` was supplied,
  inspect before reading keyfile material or prompting and fail early with a
  clear usage message when the input is AES Crypt. Stdin inputs keep the core
  `InvalidOptions` backstop.
- **AES Crypt password files — UTF-8 only.** AES Crypt key files may be supplied
  as `--password-file` only when they are UTF-8 text after the existing
  one-trailing-newline trim. UTF-16/BOM AES Crypt key files and byte-exact
  password files whose intended password ends with a newline are out of scope;
  non-UTF-8 password bytes on the AES Crypt path are `InvalidOptions`.
- **v3 PBKDF2 salt — provisional, gated by a fixture.** The public stream-format
  page omits the PBKDF2 salt, so `salt = iv1` (§2.4) is unverified and must be
  pinned from a real v3 fixture in the §5.10 step-2 KDF-vector test before any v3
  body code is written.
- **`inspect` does not enforce the v3 iteration bound.** It reports the raw
  `kdf_iterations` (no derivation, so a hostile work factor is surfaced, not
  rejected); only `decrypt`/`verify` enforce `1..=10_000_000` (§2.4, §5.8).
- **v3 iteration ceiling — `10_000_000`.** ≈33× the reference tool's 300,000
  default: accepts any realistic file while bounding CPU-DoS on hostile input.

---

## 13. Master checklist

Checked items are done for **Stream Format 1 and 2**; sub-parts marked
*(v3 deferred)* land with Stream Format 3 ([§12](#12-decisions)).

**Core (`paladin-core`)**
- [x] Add `aes`, `cbc`, `hmac` deps (`aes 0.8` / `cbc 0.1` / `hmac 0.13`, no new `digest`/`cipher` generation); pinned in `Cargo.lock`.
- [x] `error.rs`: add `UnsupportedAesCryptVersion(u8)`; update `BadMagic` display/docs; `common::exit_code` maps the AES version variant to 4 (+ test).
- [x] `secret.rs`: add `pub(crate) password_bytes()`; reject keyfile/empty-password for AES Crypt.
- [x] `format.rs`: `detect` peeks magic and re-chains the reader (+ tests).
- [x] `aescrypt.rs`: header + extension parse with bounds. *(v3 iteration bound deferred.)*
- [x] `aescrypt.rs`: v1/v2 SHA-256 KDF with an independently-derived locked vector. *(v3 PBKDF2-HMAC-SHA512 deferred.)*
- [x] `aescrypt.rs`: verify `hmac1` (constant-time) → unwrap `iv2`/`key2`. *(v3 `enc_keys ‖ 0x03` input deferred.)*
- [x] `aescrypt.rs`: body stream w/ 33-byte trailer buffer, `fsmod`, `hmac2`, 64 GiB cap, cancellation. *(v3 32-byte trailer + PKCS#7 deferred.)*
- [x] `aescrypt.rs`: `inspect` → `AesCryptHeader`; sanitized `CREATED_BY`. *(v3 `kdf_iterations` deferred.)*
- [x] `lib.rs`: `decrypt`/`verify`/`inspect` dispatch by `Format`; export `Metadata`/`AesCryptHeader`; update core tests.
- [x] `paths.rs`: `default_aescrypt_output` + `.aes` in the shared suffix set (+ tests).
- [x] Full KAT + tamper + format + usage + cap tests (§11); `fmt`/`clippy` clean.

**CLI (`paladin`)**
- [x] `info.rs`: `format_info(&Metadata)` renders both formats (byte-exact).
- [x] `run.rs`: `run_info`/`run_decrypt` consume `Metadata`; AES Crypt default output.
- [x] Pre-prompt keyfile / `--no-password` rejection for non-stdin AES Crypt decrypt/verify (§6).
- [x] Help/man/README: auto-detect note + UTF-8 AES password-file note + re-encrypt recommendation.
- [x] `assert_cmd` suite over committed v1/v2 `.aes` fixtures (§6). *(v3 fixtures deferred.)*

**TUI (`paladin-tui`)**
- [x] `info.rs`: `format_info(&Metadata)`; AES Crypt rows.
- [x] `app.rs`: inline-inspect and decrypt prefill consume `Metadata`; decrypt-prefill fallback is format-neutral.
- [x] Info unit test + inline-inspect app test for AES Crypt v2 fixtures.

**GTK (`paladin-gtk`)**
- [x] `info.rs`: rows/text accept `&Metadata`; AES Crypt rows.
- [x] `app.rs`: `inspect_path`/`open_and_inspect` return `Metadata`; update 3 call sites; decrypt prefill.
- [x] `message.rs`: format-neutral `BadMagic`; explicit `UnsupportedAesCryptVersion` message (+ tests).
- [x] `info.rs` unit tests for AES Crypt v2 fixtures; manual UI spot-check still pending.

**Docs**
- [x] DESIGN.md updated per [§9](#9-designmd-updates-required).
- [x] Security implications ([§4](#4-security-implications-confirm-before-implementing)) confirmed with the user before implementation (v3 deferred as part of that discussion).
