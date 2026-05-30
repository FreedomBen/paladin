# Implementation Plan 01 — Core & Common

> Scope: the Cargo workspace scaffold, the `symcrypt-core` library (all crypto,
> file format, streaming, armor, pure helpers), and the `symcrypt-common`
> terminal glue shared by the CLI and TUI. This is the foundation the three
> front-end plans (`02`–`04`) all depend on, so it is built first.

`DESIGN.md` is the source of truth; this plan only sequences *how* and *in what
order* to build it. Section references below (e.g. §4.3) point into `DESIGN.md`.
If implementation reveals a needed change, update `DESIGN.md` first, then this
plan, then the code.

> **Status (2026-05-30): Plan 01 is essentially complete.** Per `README.md`
> ("the shared libraries … are implemented and tested") and the git history
> (`Add ASCII armor and the public encrypt/decrypt/inspect/verify API`, `Add
> known-answer vectors and public-API integration tests`, `Add default
> output-path helpers`, `Implement symcrypt-common terminal glue`), the
> workspace, `symcrypt-core`, and `symcrypt-common` are already built. The
> checklists below are ticked to reflect that committed state — they now serve as
> an as-built spec and a re-verification checklist. Re-run `cargo test` +
> `cargo clippy --all-targets --all-features` to confirm green.
> **Caveat:** the project `CLAUDE.md` still says "design phase — there is no Rust
> code yet"; that line is now stale and should be updated.

---

## How to use this plan

- **TDD throughout.** Each phase lists *Tests first*, then *Implementation*.
  Write the failing tests, watch them fail, then implement until green. This is
  mandatory for the security-critical core (per `CLAUDE.md`).
- **Build order is dependency order.** Phases 0→12 compile and test cleanly at
  each step; later phases only depend on earlier ones.
- **After every phase:** `cargo fmt`, then `cargo clippy --all-targets
  --all-features` with zero warnings, then `cargo test -p <crate>`. Commit the
  phase (serialize via the `commit.lock` protocol in `CLAUDE.md`; never push).
- **Checklists** under each phase track progress — tick items as they land.

## Guiding constraints (the core's hard boundary)

These come straight from §2.2 and must hold for every line in `symcrypt-core`:

- Never reads argv, never prompts, never touches the filesystem, never decides
  whether to overwrite, never exits the process.
- Operates on generic `Read`/`Write`; reports progress through an `on_progress`
  callback that returns `ControlFlow::Break` to cancel (→ `SymError::Canceled`).
- **RustCrypto crates only** — no hand-rolled crypto (§4.1).
- All key material and derived buffers wrapped in `zeroize` (§4.1, §11).
- All multi-byte integers **big-endian** on the wire (§5.1).
- Unauthenticated header lengths/KDF costs are range-checked **before** any
  allocation or key derivation (§5.4, §11).
- `SymError` → exit-code classification lives in `symcrypt-common`, **not** in
  the core and **not** in the front-ends (§6.6).

## Crates to scaffold & dependency direction

Workspace members: `symcrypt-core`, `symcrypt-common`, `symcrypt-cli`,
`symcrypt-tui`, `symcrypt-gtk`. Direction: `common`/`cli`/`tui`/`gtk` → `core`;
`cli`/`tui` → `common`; `gtk` deliberately skips `common` (§2).

This plan implements **`symcrypt-core`** and **`symcrypt-common`** fully. The
three front-end crates are scaffolded as compiling placeholders only (a `main`
that prints "not implemented") so the workspace stays green; their real work and
dependencies arrive in plans `02`–`04`. Do **not** add front-end deps
(`clap`, `ratatui`, `relm4`, …) here.

---

## Phase 0 — Workspace scaffold

**Goal:** an empty but compiling five-crate workspace.

**Tasks**

- Root `Cargo.toml`: `[workspace]` with `resolver = "3"`, `members` listing all
  five crates under `crates/`, and a shared `[workspace.package]` (edition
  `2024`, rust-version `1.94`, license, repository) + `[workspace.dependencies]`
  table so versions are pinned once.
- Create the directory tree from §2.1 (`crates/symcrypt-core/src/{lib,error,
  secret,header,kdf,cipher,stream,armor,paths}.rs` as empty modules wired into
  `lib.rs`; `crates/symcrypt-common/src/lib.rs`; placeholder `main.rs` for the
  three front-ends).
- Add core deps via `cargo add` (pins land in `Cargo.lock`, §9): `aes-gcm`,
  `chacha20poly1305`, `argon2`, `scrypt`, `pbkdf2`, `sha2`, `rand`, `getrandom`,
  `rand_core`, `zeroize` (with `derive`), `base64`, `thiserror`; dev-dep
  `tempfile` and `hex` (KAT fixtures).
- `symcrypt-common` deps: path `symcrypt-core`, `thiserror`; dev-dep `tempfile`.
- Confirm `cargo build` + `cargo test` succeed on the empty workspace.

**Checklist**

- [x] Root workspace manifest with resolver, members, shared package + deps.
- [x] `symcrypt-core` crate with all module files stubbed and re-exported.
- [x] `symcrypt-common` crate stub.
- [x] `symcrypt-cli` (bin `symcrypt`), `symcrypt-tui`, `symcrypt-gtk` placeholders.
- [x] Core + common dependencies added and pinned.
- [x] `cargo build`, `cargo fmt --check`, `cargo clippy`, `cargo test` all clean.

---

## Phase 1 — Errors (`error.rs`)

**Goal:** the single error type every other module returns. Defined first so all
later phases use it. Variants align 1:1 with the §6.6 exit-code mapping.

**API sketch**

```rust
#[derive(Debug, thiserror::Error)]
pub enum SymError {
    Auth,                       // wrong password OR corrupt/tampered (indistinguishable) → 3
    BadMagic,                   // not a symcrypt file                                    → 4
    UnsupportedVersion(u8),     //                                                        → 4
    UnknownCipher(u8),          //                                                        → 4
    UnknownKdf(u8),             //                                                        → 4
    ReservedFlags,              // reserved flag bit set                                  → 4
    MalformedHeader(&'static str), // structural: bad lengths/costs, non-UTF-8 name, armor → 4
    InvalidOptions(&'static str),  // empty Secret, bad keyfile size, KDF mismatch, etc.   → 2
    InputTooLarge,              // > 64 GiB plaintext or > 2^32 chunks                     → 1
    Canceled,                   // on_progress returned Break                             → 130
    Io(#[from] std::io::Error), //                                                        → 1
}
pub type Result<T> = std::result::Result<T, SymError>;
```

**Tests first**

- `Display` strings are stable and non-leaking (the `Auth` message names *both*
  "wrong password or corrupted/tampered file", never which — §4.4).
- `From<std::io::Error>` yields `Io`.

**Checklist**

- [x] `SymError` with all variants from §6.6 + `Result<T>` alias.
- [x] `Auth` message conflates wrong-password and tamper (§4.4).
- [x] `From<io::Error>` impl + tests.

---

## Phase 2 — Secret (`secret.rs`)

**Goal:** assemble password + optional keyfile into the domain-separated,
length-prefixed secret input (§4.2), zeroized on drop.

**API sketch**

```rust
pub struct Secret { input: Zeroizing<Vec<u8>>, has_keyfile: bool }
impl Secret {
    /// password may be empty iff keyfile is Some(1..=1 MiB). Both empty → InvalidOptions.
    pub fn new(password: &[u8], keyfile: Option<&[u8]>) -> Result<Self>;
    pub(crate) fn input(&self) -> &[u8];     // fed to the KDF
    pub(crate) fn has_keyfile(&self) -> bool; // drives header flag bit1 (§4.2)
}
```

Encoding (exact, §4.2):
`b"symcrypt secret v1\0" || u64be(pw_len) || pw || u64be(kf_len) || kf`.

**Tests first**

- Exact byte layout for a known (password, keyfile) pair, including the literal
  domain tag and both `u64be` length prefixes.
- **Ambiguity guard:** `(pw="ab", kf="c")` and `(pw="a", kf="bc")` produce
  *different* encodings (length-prefixing prevents concatenation collisions).
- Empty password + `None` keyfile → `InvalidOptions`.
- Empty password + non-empty keyfile → ok (keyfile-only, §4.2).
- Password + `None` keyfile → ok.
- Keyfile `Some(&[])` (0 bytes) → `InvalidOptions`; keyfile > 1 MiB →
  `InvalidOptions` (§4.2 bound 1 byte..=1 MiB).
- `has_keyfile` reflects whether a keyfile was supplied.
- Type is `ZeroizeOnDrop` (compile-time assertion / drop-zeroize check).

**Checklist**

- [x] `Secret::new` with domain-separated length-prefixed encoding.
- [x] Empty-both rejection and keyfile size bounds enforced.
- [x] `Zeroizing` wrapper; zeroize-on-drop verified.
- [x] All encoding/ambiguity/bounds tests green.

---

## Phase 3 — Cipher dispatch (`cipher.rs`)

**Goal:** AEAD selection + single-chunk seal/open over AES-256-GCM and
ChaCha20-Poly1305 (§4.1, §5.3). 256-bit key, 96-bit nonce, 128-bit tag.

**API sketch**

```rust
pub enum CipherId { Aes256Gcm, ChaCha20Poly1305 } // FromStr/Display (§6.3), id byte (§5.3)
impl CipherId {
    pub(crate) fn id_byte(self) -> u8;                 // 0x01 / 0x02
    pub(crate) fn from_id_byte(b: u8) -> Result<Self>; // else UnknownCipher
}
// nonce is the 12 bytes built by stream.rs; aad is the serialized header (chunk 0) or empty.
pub(crate) fn seal(c: CipherId, key: &[u8;32], nonce: &[u8;12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>>;
pub(crate) fn open(c: CipherId, key: &[u8;32], nonce: &[u8;12], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>>; // tag fail → Auth
```

**Tests first**

- `FromStr`/`Display` exact-lowercase round-trip: `aes-256-gcm`,
  `chacha20-poly1305`; reject aliases, uppercase, and unknown names (§6.3).
- `id_byte` ↔ `from_id_byte` round-trip; `0x00`/`0x03`/`0xff` → `UnknownCipher`.
- `seal` then `open` round-trips (incl. empty plaintext) for both ciphers.
- `open` fails with `Auth` on any single-bit change to ciphertext, tag, nonce,
  key, or AAD.
- Output length == `pt.len() + 16` (tag appended).
- (Optional) one published RFC test vector per cipher to confirm the wiring.

**Checklist**

- [x] `CipherId` enum, id bytes, `FromStr`/`Display` (exact, no aliases).
- [x] `seal`/`open` for both ciphers with `Auth` on tag failure.
- [x] Round-trip, tamper, length, and name-parsing tests green.

---

## Phase 4 — KDF dispatch (`kdf.rs`)

**Goal:** derive the 32-byte key via Argon2id / scrypt / PBKDF2-HMAC-SHA256,
with the §5.4 parameter encoding, range validation, and §12 defaults.

**API sketch**

```rust
pub enum KdfId { Argon2id, Scrypt, Pbkdf2 }  // FromStr/Display, id byte 0x01/0x02/0x03
pub enum KdfParams {
    Argon2id { memory_kib: u32, time_cost: u32, parallelism: u32 },
    Scrypt   { log_n: u32, r: u32, p: u32 },
    Pbkdf2   { iterations: u32 },
}
impl KdfId  { pub fn default_params(self) -> KdfParams; /* §12 */ }
impl KdfParams {
    pub(crate) fn matches(&self, kdf: KdfId) -> bool;
    /// pure range check (§5.4); caller maps false → MalformedHeader (read) or InvalidOptions (user).
    pub(crate) fn ranges_ok(&self) -> bool;
    pub(crate) fn to_wire(&self) -> (u32, u32, u32);
    pub(crate) fn from_wire(kdf: KdfId, p1: u32, p2: u32, p3: u32) -> Result<Self>; // MalformedHeader on bad range
}
pub(crate) fn derive_key(kdf: KdfId, p: &KdfParams, secret_input: &[u8], salt: &[u8])
    -> Result<Zeroizing<[u8; 32]>>;
```

Range rules (§5.4) — validate **before** deriving:

| KDF      | `kdf_p1`               | `kdf_p2`     | `kdf_p3`        | Extra rule                   |
| -------- | ---------------------- | ------------ | --------------- | ---------------------------- |
| Argon2id | memory 8192..=1048576  | time 1..=10  | parallel 1..=16 | Argon2 version `0x13`        |
| scrypt   | log₂N 10..=20          | r 1..=32     | p 1..=16        | `128 * 2^log₂N * r <= 1 GiB` |
| PBKDF2   | iters 10000..=10000000 | `== 0`       | `== 0`          | PRF fixed HMAC-SHA256        |

Defaults (§12): Argon2id `{65536, 3, 1}`; scrypt `{15, 8, 1}`; PBKDF2 `{600000}`.

**Tests first**

- Determinism: same `(secret_input, salt, params)` → identical key; any change to
  secret, salt, or a param → different key (§10).
- Each KDF yields exactly 32 bytes.
- `ranges_ok` accepts both boundary values and rejects each just-out-of-range
  value (low and high) for every parameter.
- scrypt `128*N*r <= 1 GiB` cap rejects an in-individual-range-but-too-big combo
  (e.g. `log_n=20, r=32`).
- PBKDF2 reserved: `from_wire` rejects non-zero `p2`/`p3`.
- `to_wire`/`from_wire` round-trip for all three; `matches` correctness.
- `default_params` returns the §12 values.
- **KAT (locks behavior):** for one fixed `(secret_input, salt)` per KDF at
  fixed params, assert the derived key equals a committed hex constant.

**Checklist**

- [x] `KdfId`/`KdfParams`, id bytes, exact `FromStr`/`Display`.
- [x] `ranges_ok` + `from_wire` enforcing every §5.4 bound incl. scrypt mem cap.
- [x] `derive_key` for all three KDFs returning a zeroized 32-byte key.
- [x] `default_params` matches §12.
- [x] Determinism, boundary, reserved-field, and committed-KAT tests green.

---

## Phase 5 — Header (`header.rs`)

**Goal:** serialize/parse the §5.2 header, decode flags & name, and range-check
everything on read. The serialized header is the AAD for chunk 0, so parse must
hand back the **exact bytes consumed**.

**API sketch**

```rust
pub enum NameStatus { Absent, Present, IgnoredUnsafe } // drives --info name_status (§6.2)
pub struct Header {
    pub version: u8, pub cipher: CipherId, pub kdf: KdfId, pub kdf_params: KdfParams,
    pub flags: u8, pub keyfile_hint: bool,
    pub(crate) salt: Vec<u8>, pub salt_len: u8,
    pub(crate) nonce_prefix: [u8; 7], pub nonce_prefix_len: u8,
    pub chunk_size: u32,
    pub name: Option<String>, pub name_status: NameStatus,
}
impl Header {
    pub(crate) fn serialize(&self) -> Vec<u8>;                 // encrypt path; this is the AAD
    pub(crate) fn parse<R: Read>(r: &mut R) -> Result<(Header, Vec<u8>)>; // (header, raw AAD bytes)
}
/// Shared basename safety check (§5.2), reused by EncryptOptions validation in lib.rs.
pub(crate) fn is_safe_basename(name: &str) -> bool;
```

`is_safe_basename`: single UTF-8 component, 1..=255 bytes, contains none of
`/ \ : NUL`, no Unicode control (U+0000–U+001F, U+007F, U+0080–U+009F), and is
neither `.` nor `..` (interior dots allowed).

Parse order & validation (reject **before** allocating large buffers or
deriving keys, §5.7 / §11):

1. `magic == "SYMCRYPT"` else `BadMagic`.
2. `version == 0x01` else `UnsupportedVersion`.
3. `cipher_id` known else `UnknownCipher`; `kdf_id` known else `UnknownKdf`.
4. `flags` bits 2–7 must be 0 else `ReservedFlags`; decode bit0 (name present),
   bit1 (`keyfile_hint`).
5. `kdf_params = from_wire(...)` → range-checked (`MalformedHeader`).
6. `salt_len ∈ 16..=64`, `nonce_prefix_len == 7`, `chunk_size ∈ 4096..=16777216`
   — else `MalformedHeader`.
7. If name flag: `name_len ∈ 1..=255`; read bytes; non-UTF-8 → `MalformedHeader`;
   then `is_safe_basename` → `Present` or (valid but unsafe) `IgnoredUnsafe`.
8. EOF before the header is complete → `MalformedHeader`.

**Tests first**

- `serialize` → `parse` round-trip for **every** cipher × kdf × {no-name,
  safe-name} × {keyfile bit 0/1} combination; the returned raw bytes equal the
  serialized input (AAD fidelity).
- Byte-offset assertions against the §5.2 table on a hand-built header (magic at
  0, version at 8, …).
- Each rejection: bad magic, bad version, unknown cipher, unknown kdf, reserved
  flag set, every out-of-range length/cost, non-UTF-8 name, truncated/partial
  header.
- Valid-but-unsafe name (e.g. `../etc`, `a/b`, `.`, name with control char) →
  parse succeeds with `IgnoredUnsafe`; safe `report.pdf` → `Present`.
- `is_safe_basename` table-driven accept/reject cases.

**Checklist**

- [x] `Header`, `NameStatus`, `serialize`, `parse` returning raw AAD bytes.
- [x] `is_safe_basename` per §5.2 (shared with lib option validation).
- [x] Parse validates magic→version→ids→flags→params→lengths→name in order.
- [x] Round-trip (all combos), offset, every-rejection, and name-status tests green.

---

## Phase 6 — STREAM body (`stream.rs`)

**Goal:** the STREAM construction (§4.3, §5.5): chunked seal/open with per-chunk
nonce, look-ahead finality, counter/size caps, progress, and cancellation.

**API sketch**

```rust
pub(crate) fn nonce(prefix: &[u8; 7], counter: u32, final_flag: bool) -> [u8; 12];
// prefix‖u32be(counter)‖final_flag(0x00|0x01)

pub(crate) fn encrypt_body<R: Read, W: Write>(
    c: CipherId, key: &[u8;32], prefix: &[u8;7], chunk_size: u32, header_aad: &[u8],
    input: R, output: W, size_cap: u64, on_progress: &mut OnProgress, plaintext_done: &mut u64,
) -> Result<()>;

pub(crate) enum BodyMode { Decrypt, Verify }
pub(crate) fn decrypt_body<R: Read, W: Write>(
    c: CipherId, key: &[u8;32], prefix: &[u8;7], chunk_size: u32, header_aad: &[u8],
    input: R, output: W, size_cap: u64, mode: BodyMode, on_progress: &mut OnProgress,
) -> Result<()>;
```

Rules to implement:

- **Nonce:** `nonce[0..7]=prefix`, `nonce[7..11]=counter.to_be_bytes()`,
  `nonce[11]=final_flag` (§4.3).
- **AAD:** chunk 0 → `header_aad`; chunks > 0 → empty (§4.3).
- **Encrypt finality via look-ahead:** buffer one chunk ahead; a chunk is final
  iff no further input follows. Empty plaintext → exactly **one** final empty
  chunk (16-byte tag only). Never emit a trailing empty final chunk after full
  chunks (§5.5). Fill each chunk with a read-until-full helper (a short `read`
  is not EOF).
- **Decrypt finality:** read up to `chunk_size + 16` bytes, buffer one ahead;
  final iff nothing follows. A trailing fragment < 16 bytes, no body after the
  header, or an empty final chunk after a previous chunk → **`Auth`** (exit 3),
  indistinguishable from tampering (§4.4, §5.5).
- **Counter cap:** checked `+1` per chunk; exceeding 2³² chunks → encrypt
  `InputTooLarge`, decrypt `Auth` (§4.3).
- **Size cap:** accumulate *plaintext* bytes; exceeding `size_cap` → encrypt
  `InputTooLarge` before finalizing; decrypt/verify `InputTooLarge` on
  authenticated plaintext (stdout may already hold partial output) (§4.3).
  `size_cap` is a parameter (lib passes the 64 GiB const; tests pass a small cap
  to exercise the limit honestly without 64 GiB of data).
- **Progress/cancel:** call `on_progress` per chunk; `Break` → `Canceled`. (For
  encrypt, progress counts plaintext consumed; the raw-input counter for
  decrypt/verify lives in lib.rs, Phase 9.)

**Tests first**

- `nonce` byte layout: prefix placement, `u32be` counter increment, final flag
  0x00/0x01.
- Single-chunk and multi-chunk encrypt→decrypt round-trip at sizes 0, 1,
  `chunk-1`, `chunk`, `chunk+1`, several chunks (use a small `chunk_size` to make
  multi-chunk cheap).
- Exactly one final chunk; final flag set only on the last chunk; empty
  plaintext → one 16-byte chunk.
- Look-ahead correctness when `Read` returns short reads (wrap a reader that
  yields 1 byte at a time).
- Decrypt rejects (all `Auth`): flipped body byte, truncated last chunk, appended
  chunk, swapped chunks, sub-tag fragment, empty body.
- Size cap: with a tiny `size_cap`, encrypt of `cap+1` bytes → `InputTooLarge`;
  a crafted over-cap authenticated stream → decrypt/verify `InputTooLarge`.
- Cancellation: an `on_progress` returning `Break` after N chunks →
  `SymError::Canceled`.

**Checklist**

- [x] `nonce` builder + tests.
- [x] `encrypt_body` with look-ahead finality, counter & size caps, progress.
- [x] `decrypt_body` (Decrypt + Verify) with AAD binding and structural→`Auth`.
- [x] Round-trip across sizes, tamper/truncate/reorder, caps, cancel tests green.

---

## Phase 7 — ASCII armor (`armor.rs`)

**Goal:** the optional outer base64 layer (§5.6) — wrap on encrypt, detect +
strip on decrypt/verify/info.

**API sketch**

```rust
pub(crate) const BEGIN: &str = "-----BEGIN SYMCRYPT MESSAGE-----";
pub(crate) const END:   &str = "-----END SYMCRYPT MESSAGE-----";

/// Writer adapter: base64 (RFC 4648 +/=), LF, lines wrapped at exactly 64 cols,
/// BEGIN before body, END + single trailing LF on finish. Requires explicit finish().
pub(crate) struct ArmorWriter<W: Write> { /* … */ }
impl<W: Write> ArmorWriter<W> { pub(crate) fn new(w: W) -> Self; pub(crate) fn finish(self) -> Result<W>; }

/// Peek the input; if armored, return a Read that strips markers + decodes base64.
pub(crate) fn dearmor_if_armored<R: Read>(input: R) -> Result<Box<dyn Read>>;
```

Detection (§5.6): buffer the leading bytes, skip surrounding whitespace, and test
for the exact `BEGIN` line; if absent, treat input as binary and replay the
buffered bytes. Accept LF or CRLF; require the exact begin/end marker lines once
armored. Reject extra non-whitespace outside the markers, non-base64 body, or a
missing end marker → `MalformedHeader`.

**Tests first**

- Round-trip: `ArmorWriter` output → `dearmor` reproduces the original bytes for
  several lengths (incl. empty and non-multiple-of-3).
- Output shape: starts with `BEGIN`, body lines exactly 64 cols (last may be
  shorter), ends with `END` + exactly one LF, nothing outside the markers.
- Detection: armored input is recognized; plain binary is passed through
  untouched (leading bytes not lost).
- Acceptance: CRLF line endings and surrounding whitespace accepted.
- Rejection (`MalformedHeader`): junk before BEGIN / after END, invalid base64,
  missing END marker.
- **KAT:** a committed armored blob dearmors to a known binary container.

**Checklist**

- [x] `ArmorWriter` (64-col wrap, LF, markers, explicit `finish`).
- [x] `dearmor_if_armored` with peek-based detection and binary pass-through.
- [x] Round-trip, shape, accept (LF/CRLF/whitespace), reject, KAT tests green.

---

## Phase 8 — Path helpers (`paths.rs`)

**Goal:** the pure, no-I/O default output-path helpers all front-ends share
(§2.3, §6.5).

**API sketch**

```rust
pub fn default_encrypt_output(input: &Path, armor: bool) -> PathBuf;
pub fn default_decrypt_output(input: &Path, header: &Header) -> PathBuf;
```

- Encrypt: append `.symcrypt` (or `.symcrypt.asc` when `armor`).
- Decrypt: if `header.name_status == Present`, place that basename beside the
  input; else strip `.symcrypt.asc`, then `.symcrypt`, then `.asc`; else append
  `.dec`. Empty-basename fallback: input named exactly `.symcrypt` / `.asc` /
  `.symcrypt.asc` → append `.dec` to the original (e.g. `.symcrypt` →
  `.symcrypt.dec`).

**Tests first**

- `report.pdf` → `report.pdf.symcrypt`; armored → `report.pdf.symcrypt.asc`.
- Decrypt with stored `Present` name → that name beside the input dir.
- Strip each recognized extension: `x.symcrypt.asc`→`x`, `x.symcrypt`→`x`,
  `x.asc`→`x`; unknown → `x.dec`.
- Empty-basename fallback: `.symcrypt`→`.symcrypt.dec`, `.asc`→`.asc.dec`,
  `.symcrypt.asc`→`.symcrypt.asc.dec`.
- `IgnoredUnsafe`/`Absent` names fall through to extension stripping.

**Checklist**

- [x] `default_encrypt_output` + `default_decrypt_output` per §6.5.
- [x] Stored-name, extension-strip, and empty-basename-fallback tests green.

---

## Phase 9 — Public API (`lib.rs`)

**Goal:** wire the modules into the four operations from §2.3, plus the
`EncryptOptions`/`Progress` types and the constants. This is the only surface the
front-ends touch.

**API sketch (§2.3)**

```rust
pub struct EncryptOptions {
    pub cipher: CipherId, pub kdf: KdfId, pub kdf_params: KdfParams,
    pub chunk_size: u32, pub filename: Option<String>, pub armor: bool,
}
impl Default for EncryptOptions { /* §12 defaults */ }

pub struct Progress { pub done: u64, pub total: Option<u64> }
pub type OnProgress = dyn FnMut(Progress) -> std::ops::ControlFlow<()>;

pub fn encrypt<R: Read, W: Write>(input: R, output: W, secret: &Secret,
    opts: &EncryptOptions, input_len: Option<u64>, on_progress: &mut OnProgress) -> Result<()>;
pub fn decrypt<R: Read, W: Write>(input: R, output: W, secret: &Secret,
    input_len: Option<u64>, on_progress: &mut OnProgress) -> Result<()>;
pub fn inspect<R: Read>(input: R) -> Result<Header>;
pub fn verify<R: Read>(input: R, secret: &Secret, input_len: Option<u64>,
    on_progress: &mut OnProgress) -> Result<()>;
```

Constants: `PLAINTEXT_CAP: u64 = 64 * 1024 * 1024 * 1024`, `DEFAULT_CHUNK_SIZE:
u32 = 65536`, `SALT_LEN: usize = 16`, `NONCE_PREFIX_LEN: usize = 7`.

**`encrypt` flow** (§2.4, §4.2, §4.3, §5.4):

1. Validate `EncryptOptions` → `InvalidOptions`: `kdf_params.matches(kdf)`,
   `ranges_ok()`, `chunk_size` in range, and `filename` (if any)
   `is_safe_basename`. (Guarantees a programmatic header can't fail its own read
   validation, §5.4.)
2. Cancellation check; generate `salt` (16) + `nonce_prefix` (7) from `OsRng`.
3. Build `Header` (flags from `filename.is_some()` and
   `secret.has_keyfile()`); `serialize()` → `aad`.
4. `derive_key`; cancellation check after KDF.
5. Wrap `output` in `ArmorWriter` when `opts.armor`; write the header bytes,
   then `stream::encrypt_body(..., PLAINTEXT_CAP, ...)`; `finish()` the armor.

**`decrypt`/`verify` flow:**

1. Wrap raw `input` in a `CountingReader` (so progress `done` counts
   caller-provided bytes — armored bytes for armored input, §2.3).
2. `dearmor_if_armored`; `Header::parse` → `(header, aad)`.
3. Cancellation check; `derive_key`; cancellation check after KDF.
4. `stream::decrypt_body` to `output` (decrypt) or `io::sink()` (verify), mode
   set accordingly; progress reads the counting reader's position.

**`inspect`:** dearmor + `Header::parse`, return the `Header`; no secret, no
body read, unauthenticated (powers `--info`, §6.2).

**Progress note:** encrypt reports plaintext-consumed; decrypt/verify report
raw-input-consumed via `CountingReader`. The size cap is always enforced from
plaintext bytes, never from `input_len` (advisory only, §2.3, §4.3).

**Deterministic seam for KAT:** add `pub(crate) fn encrypt_with_entropy(...)`
taking explicit `salt: &[u8]` + `nonce_prefix: &[u8;7]`; public `encrypt` calls
it with `OsRng` output. In-crate KAT unit tests call it with fixed entropy so
re-encryption reproduces committed fixtures byte-for-byte (§10); production
always uses `OsRng`.

**Tests first** (smoke-level here; exhaustive coverage is Phase 10)

- `EncryptOptions::default()` equals §12.
- Option validation rejects mismatched `kdf_params`, out-of-range `chunk_size`,
  unsafe `filename` (`InvalidOptions`).
- A tiny end-to-end `encrypt`→`decrypt` round-trip and an `encrypt`→`inspect`
  metadata check.
- `verify` returns `Ok` on a good file and `Auth` on a tampered one.
- Cancellation before/after KDF returns `Canceled`.

**Checklist**

- [x] `EncryptOptions` (+ `Default` = §12), `Progress`, `OnProgress`, constants.
- [x] `encrypt` with option validation, OsRng entropy, armor wrap, AAD binding.
- [x] `decrypt`/`verify` with `CountingReader`, dearmor, sink-for-verify.
- [x] `inspect` returning unauthenticated `Header`.
- [x] `encrypt_with_entropy` seam for deterministic KAT.
- [x] Smoke round-trip / option-validation / cancel tests green.

---

## Phase 10 — Core integration tests (`crates/symcrypt-core/tests/`)

**Goal:** the exhaustive suite from §10. Use **minimal KDF cost params**
(Argon2id `{8192,1,1}`, scrypt `{10,1,1}`, PBKDF2 `{10000}`) so the suite stays
fast; cost-correctness is already covered in Phase 4.

**`round_trip.rs`** — parameterized over sizes {0, 1, `chunk-1`, `chunk`,
`chunk+1`, several MiB} × {both ciphers} × {all three KDFs} × {armored, binary}:
`encrypt` then `decrypt` reproduces the input exactly.

**`tamper.rs`** (each → `Auth` unless noted):

- Flip a byte in the body.
- Change a header byte to another *valid* value (`cipher_id 0x01→0x02`) → `Auth`
  (AAD mismatch); change it to an *unknown* id → `UnknownCipher`/`UnknownKdf`
  (exit 4).
- Wrong password; wrong keyfile; missing keyfile.
- Truncate the last chunk; append a chunk; swap two chunks.
- Truncate body to a sub-tag fragment; drop the body entirely.

**`kat.rs`** — committed fixtures under `tests/vectors/`:

- Decrypt direction: each fixture (per cipher × KDF, fixed password/salt/
  nonce-prefix/plaintext) decrypts to the expected plaintext via the public API.
- (Re-encryption byte-equality lives in-crate using the `encrypt_with_entropy`
  seam, per Phase 9.)
- Include at least one armored fixture.

**Checklist**

- [x] `round_trip.rs` across all size × cipher × KDF × armor combinations.
- [x] `tamper.rs` covering every §10 negative case with correct error variant.
- [x] `kat.rs` + committed `tests/vectors/` (binary + armored).
- [x] Suite runs fast with minimal KDF params.

---

## Phase 11 — `symcrypt-common` (terminal glue)

**Goal:** the shared CLI+TUI glue (§2.2, §6.4–§6.6). Depends only on
`symcrypt-core` + std + `thiserror` + `tempfile`. No crypto, no format logic.

**Responsibilities & API sketch**

```rust
// Exit-code mapping — the ONLY place SymError is classified (§6.6).
pub fn exit_code(err: &SymError) -> i32; // Auth→3, BadMagic/Version/Cipher/Kdf/ReservedFlags/Malformed→4,
                                         // InvalidOptions→2, Canceled→130, Io/InputTooLarge→1

// Password-source resolution (§6.4): at most one of inline/file/env/no-password.
pub enum PasswordSource<'a> { Inline(&'a [u8]), File(&'a Path), Env(&'a OsStr), NoPassword }
pub fn resolve_secret(src: PasswordSource, keyfile: Option<&Path>) -> Result<Secret, UsageError>;

// Path-or-stdin I/O + finalization (§6.5).
pub fn open_input(path: &OsStr) -> ...;        // "-"=stdin; else existing regular file (+ len for progress)
pub fn finalize_output(dst: &Path, force: bool, write: impl FnOnce(&mut File)->Result<()>) -> ...;
                                               // sibling temp, 0600 on Unix, rename on success, remove on error
pub fn same_file(input: &Path, output: &Path) -> bool;  // symlink-resolved; hardlink identity where available
pub fn best_effort_remove(path: &Path) -> RemoveOutcome; // --remove: warn-but-Ok on failure
```

Rules to enforce (from §6.4/§6.5):

- Password-source exclusivity; empty source rejected **except** `--no-password`
  (so `-p ''`, empty/newline-only password-file, set-but-empty env all error).
- `--password-file`/`-k` reject `-`, require an existing **regular** file, cap
  reads at 1 MiB; password-file trims exactly one trailing LF/CRLF; keyfile must
  be 1..=1 MiB (0 bytes rejected).
- Clobber: refuse an existing output unless `force`; existing directories/special
  files rejected even with `force`.
- Same-file refusal (resolve symlinks; use hardlink identity where the platform
  exposes it; else compare canonical paths).
- Temp-file finalization: sibling temp, Unix mode `0600`, rename only on success,
  remove on any error/cancel; failed rename → `Io` (exit 1), `--remove` skipped.

**Tests first** (unit, with `tempfile`)

- `exit_code` for every `SymError` variant → §6.6 table.
- Source exclusivity (two sources → error); empty-source rejection per source;
  `--no-password` empty accepted only with a keyfile.
- password-file: trailing LF/CRLF trim, >1 MiB rejected, `-` rejected,
  non-regular rejected.
- keyfile: 1..=1 MiB ok, 0 bytes rejected, >1 MiB rejected, `-`/non-regular
  rejected.
- Clobber refuse vs `force`; directory/special-file output rejected even with
  `force`.
- Same-file: symlink-resolved match; hardlink match where supported.
- Finalization: Unix `0600` on the result; rename on success; temp removed on a
  simulated write error.
- `best_effort_remove`: success path and warn-but-Ok failure path.

**Checklist**

- [x] `exit_code` mapping (sole classifier) + tests.
- [x] Password-source resolution with exclusivity & empty-source rules.
- [x] Password-file / keyfile readers with size caps, `-`/non-regular rejection.
- [x] Clobber, same-file (symlink/hardlink), and temp-file `0600` finalization.
- [x] `best_effort_remove` warn-but-success behavior.
- [x] All `symcrypt-common` unit tests green.

---

## Phase 12 — Workspace-wide verification

- [x] `cargo fmt --check` clean across the workspace.
- [x] `cargo clippy --all-targets --all-features` — **zero** warnings.
- [x] `cargo test` green for `symcrypt-core` and `symcrypt-common`.
- [x] `cargo build --release` succeeds (front-end placeholders included).
- [x] `README.md` "Development commands" still match reality; update if drifted.
- [x] Confirm the core honors its boundary: a quick grep shows no argv/stdin/
      `std::process::exit`/filesystem access inside `symcrypt-core`.

---

## Test coverage map (`DESIGN.md` §10 → this plan)

| §10 requirement                                             | Phase |
| ---------------------------------------------------------- | ----- |
| KDF determinism (same in→same key; diff params→diff key)   | 4     |
| Secret assembly: domain separation, length prefix, bounds  | 2     |
| Header serialize↔parse for every cipher/KDF/flag combo     | 5     |
| Header validation rejects out-of-range / non-UTF-8 / unsafe| 5     |
| Encrypt-option validation (`InvalidOptions`/`InputTooLarge`)| 9, 6  |
| Decrypt/verify size-cap enforcement (`InputTooLarge`)      | 6     |
| ASCII armor accept LF/CRLF/ws; reject junk/base64/no-end   | 7     |
| STREAM nonce derivation: counter, final flag               | 6     |
| Pure helpers: default output paths (+ empty-basename)      | 8     |
| Cipher/KDF `FromStr`/`Display` exact, alias/case rejection | 3, 4  |
| Round-trip across sizes × ciphers × KDFs                   | 10    |
| Negative/tamper (flip, downgrade, truncate, append, swap…) | 10    |
| Known-answer vectors (committed, deterministic generation) | 9, 10 |
| `symcrypt-common` glue (I/O, clobber, remove, mapping)     | 11    |

## Definition of done

- All Phase 0–12 checklists ticked.
- `symcrypt-core` exposes exactly the §2.3 surface and never crosses its §2.2
  boundary.
- `symcrypt-common` is the sole place `SymError` is mapped to exit codes.
- Every §10 test exists and passes; `fmt`/`clippy` clean.
- The CLI plan (`IMPLEMENTATION_PLAN_02_CLI.md`) can build entirely on the public
  core API + common glue with no further core changes.

See `DESIGN.md` §2, §4, §5, §10, §11, and §12 for authoritative details.
