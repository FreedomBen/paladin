# symcrypt — Design

**Status:** Design phase. No implementation yet.
**Target stack:** Rust 1.94+, [relm4](https://relm4.org/) (gtk4-rs + libadwaita), [ratatui](https://ratatui.rs/).
**Last updated:** 2026-05-29

`symcrypt` is a simple, safe symmetric file encryption tool. It ships as three
**thin front-ends over one shared core library** — a scriptable CLI
(`symcrypt`), an interactive terminal UI (`symcrypt-tui`), and a GTK desktop app
(`symcrypt-gtk`, built with relm4) — all built on `symcrypt-core`, which does all
the work. The default cipher is AES-256-GCM. Encrypted files begin with a
self-describing, authenticated header so they can be identified and decrypted
without out-of-band parameters (other than the password/keyfile).

---

## Table of contents

1. [Goals & non-goals](#1-goals--non-goals)
2. [Architecture](#2-architecture)
3. [Threat model](#3-threat-model)
4. [Cryptographic design](#4-cryptographic-design)
5. [File format specification](#5-file-format-specification)
6. [CLI specification](#6-cli-specification)
7. [TUI application design](#7-tui-application-design)
8. [GTK application design](#8-gtk-application-design)
9. [Dependencies](#9-dependencies)
10. [Testing strategy](#10-testing-strategy)
11. [Security considerations](#11-security-considerations)
12. [Defaults summary](#12-defaults-summary)
13. [Out of scope for v1](#13-out-of-scope-for-v1)
14. [Resolved decisions](#14-resolved-decisions)
15. [Implementation plan](#15-implementation-plan)

---

## 1. Goals & non-goals

### Goals

- **Confidentiality + integrity** of file contents at rest, using authenticated
  encryption (AEAD). Any tampering or corruption is detected on decrypt.
- **Self-describing files**: a magic marker and a versioned, authenticated
  header carry everything needed to decrypt (cipher, KDF, KDF params, salt,
  nonce prefix, chunk size) — only the secret (password/keyfile) is external.
- **Streaming**: encrypt/decrypt large files with bounded memory, within the v1
  plaintext size cap (§4.3).
- **Three thin front-ends, one core**: a scriptable CLI, an interactive TUI, and
  a GTK desktop app, all calling the same library so behavior never diverges and
  nothing is reimplemented per front-end.
- **Strong, modern defaults** that a non-expert gets for free, with knobs for
  experts.

### Non-goals (v1)

- Public-key / asymmetric encryption, signing, or key exchange.
- Hiding *that* a file is a symcrypt file (the magic is intentionally
  identifiable) or hiding the approximate plaintext size.
- Deniable encryption, hidden volumes, or secure erasure guarantees on modern
  storage (see [§11](#11-security-considerations)).
- Compression (can be added later; compressing before encrypting has known
  side-channel caveats, so it stays off by default and out of v1).

---

## 2. Architecture

A Cargo **workspace** of five crates: the pure-logic `symcrypt-core`, the three
thin front-ends (`symcrypt`, `symcrypt-tui`, `symcrypt-gtk`), and
`symcrypt-common` — a small support crate of terminal glue shared by the CLI and
TUI. **`symcrypt-core` does all the work**; the front-ends are just views that
gather input, hand it to the core, and render the result. This keeps the
security-critical code small, front-end-agnostic, and unit-testable, and
guarantees the CLI, TUI, and GTK app behave identically because they share the
same code path.

### 2.1 Workspace layout

```
symcrypt/
├── Cargo.toml                 # workspace manifest
├── DESIGN.md
├── IMPLEMENTATION_PLAN_01_CORE.md   # per-component implementation plans (stubs)
├── IMPLEMENTATION_PLAN_02_CLI.md
├── IMPLEMENTATION_PLAN_03_TUI.md
├── IMPLEMENTATION_PLAN_04_GTK.md
├── README.md                  # (later)
└── crates/
    ├── symcrypt-core/         # library — ALL crypto, format, streaming, pure helpers
    │   ├── src/
    │   │   ├── lib.rs          # public API: encrypt / decrypt / inspect / verify
    │   │   ├── error.rs        # SymError, Result
    │   │   ├── secret.rs       # Secret (password + optional keyfile), zeroized
    │   │   ├── header.rs       # serialize / parse, IDs, flags, params
    │   │   ├── kdf.rs          # Argon2id / scrypt / PBKDF2 dispatch + defaults
    │   │   ├── cipher.rs       # AEAD dispatch (AES-256-GCM, ChaCha20-Poly1305)
    │   │   ├── stream.rs       # STREAM chunked encrypt / decrypt
    │   │   ├── armor.rs        # base64 ASCII-armor wrap / unwrap + detect
    │   │   └── paths.rs        # default output-path helpers (pure, no I/O)
    │   └── tests/              # round-trip, tamper, KAT vectors
    ├── symcrypt-common/        # library — terminal glue shared by CLI + TUI
    │   └── src/lib.rs          # path-or-stdin I/O, clobber check, temp-file finalization,
    │                           #   best-effort remove, password-source resolution, exit-code mapping
    ├── symcrypt-cli/           # binary `symcrypt`      (thin front-end)
    │   └── src/main.rs
    ├── symcrypt-tui/           # binary `symcrypt-tui`  (thin front-end, ratatui)
    │   └── src/main.rs
    └── symcrypt-gtk/           # binary `symcrypt-gtk`  (thin front-end, relm4 + libadwaita)
        └── src/main.rs
```

### 2.2 Design principle: thin front-ends

Front-ends own only *medium-specific* concerns — capturing input and rendering
output. Everything else lives in the core, including pure helpers (output-path
derivation, cipher/KDF name parsing, defaults) so even those are written once.

| Concern                                                   | `symcrypt-core` | Front-ends |
|-----------------------------------------------------------|:---------------:|:----------:|
| AEAD, KDF, RNG, key derivation                            | ✓               |            |
| File format: header, chunk framing, armor                 | ✓               |            |
| Streaming loop, nonce derivation, tamper/auth checks      | ✓               |            |
| `Secret` assembly (password + keyfile) and zeroization    | ✓               |            |
| Default output-path / extension logic                     | ✓ (pure helper) | call it    |
| Cipher/KDF name parsing, display, and default params      | ✓               | call it    |
| Unauthenticated header inspection for `--info`            | ✓               | call it    |
| Parsing args / drawing widgets / reading keypresses       |                 | ✓          |
| Acquiring the password (prompt / file / env / entry)      |                 | ✓          |
| Opening files or stdin/stdout, the clobber *decision*, `--remove` |         | ✓          |
| Rendering progress, formatting errors, exit codes         |                 | ✓          |

The core never reads argv, never prompts, never touches the filesystem on its
own, never decides whether to overwrite, and never exits the process. It takes
generic `Read`/`Write` and reports progress through a callback. The terminal glue
shared by `symcrypt` and `symcrypt-tui` (open-path-or-stdin, clobber check,
temp-file finalization, best-effort remove, password-source resolution,
exit-code mapping) lives in the
`symcrypt-common` crate so it is written once. `symcrypt-gtk` does not use it —
it relies on the core plus GTK-native file handling.

For file outputs, front-ends write to a sibling temporary file and rename it to
the requested output path only after the core call succeeds. Any error,
authentication failure, or cancellation removes the temporary output. When the
output is stdout, rollback is impossible; callers may receive partial plaintext
or ciphertext before an error is detected.

### 2.3 Core public API (sketch)

```rust
// ---- Inputs the front-ends assemble and hand to the core ----

/// Password and/or keyfile material; zeroized on drop. If `keyfile` is Some,
/// it must be 1 byte..=1 MiB. Empty password + no keyfile is rejected.
pub struct Secret { /* … */ }
impl Secret {
    pub fn new(password: &[u8], keyfile: Option<&[u8]>) -> Result<Self>;
}

pub enum CipherId { Aes256Gcm, ChaCha20Poly1305 }   // FromStr / Display
pub enum KdfId    { Argon2id, Scrypt, Pbkdf2 }       // FromStr / Display
pub enum KdfParams {
    Argon2id { memory_kib: u32, time_cost: u32, parallelism: u32 },
    Scrypt { log_n: u32, r: u32, p: u32 },
    Pbkdf2 { iterations: u32 },
}

pub struct EncryptOptions {
    pub cipher: CipherId,
    pub kdf: KdfId,
    pub kdf_params: KdfParams,     // variant must match `kdf`
    pub chunk_size: u32,           // default-only in v1 (§5.4)
    pub filename: Option<String>,  // Some(name) ⇒ store in header (--name)
    pub armor: bool,
}
impl Default for EncryptOptions { /* secure defaults from §12 */ }

/// Progress callback payload. `done` is the running count of input bytes
/// consumed so far; `total` echoes the caller's `input_len` — the input length
/// when known (e.g. a regular file), or None when unknown (e.g. stdin).
/// For armored decrypt/verify input, both `done` and `total` count the
/// caller-provided armored bytes, before base64 decoding.
/// `input_len` is advisory for progress only; the §4.3 size cap is enforced
/// from the bytes actually streamed (input plaintext on encrypt, authenticated
/// plaintext on decrypt/verify), so a wrong hint never affects safety.
/// Returning Break aborts with SymError::Canceled.
pub struct Progress { pub done: u64, pub total: Option<u64> }
type OnProgress = dyn FnMut(Progress) -> std::ops::ControlFlow<()>;

// ---- The four operations every front-end calls ----

pub fn encrypt<R: Read, W: Write>(
    input: R, output: W, secret: &Secret,
    opts: &EncryptOptions, input_len: Option<u64>, on_progress: &mut OnProgress,
) -> Result<()>;

pub fn decrypt<R: Read, W: Write>(
    input: R, output: W, secret: &Secret,
    input_len: Option<u64>, on_progress: &mut OnProgress,
) -> Result<()>;

pub fn inspect<R: Read>(input: R) -> Result<Header>;       // powers --info (unauthenticated metadata)
pub fn verify<R: Read>(input: R, secret: &Secret, input_len: Option<u64>,
                       on_progress: &mut OnProgress) -> Result<()>;  // powers --verify

// ---- Pure helpers shared by all front-ends (no I/O) ----

pub fn default_encrypt_output(input: &Path, armor: bool) -> PathBuf;
pub fn default_decrypt_output(input: &Path, header: &Header) -> PathBuf;
```

### 2.4 Data flow

**Encrypt.** A front-end gathers options (args / keys / widgets), acquires the
password in its own way, builds a `Secret` and `EncryptOptions`, opens the input
as a `Read` and the output as a `Write`, determines `input_len` (the input's
byte length from file metadata, or `None` for stdin), then calls
`core::encrypt(input, output, &secret, &opts, input_len, on_progress)`. The core derives the
key, writes the authenticated header, and STREAM-encrypts the body, invoking
`on_progress` per chunk. The front-end only renders progress and the result.

**Decrypt.** Same shape: the front-end opens streams and calls `core::decrypt`;
the core parses/validates the header, re-derives the key, and STREAM-decrypts,
verifying every tag.

**Info / verify.** `core::inspect(input)` returns unauthenticated header
metadata for display; `core::verify(input, &secret, input_len, on_progress)`
decrypts-and-discards to confirm integrity. Front-ends never parse the format
themselves.

---

## 3. Threat model

**In scope.** An attacker who obtains the encrypted file (at rest, in transit,
in backups) must not learn the contents and must not be able to alter them
undetected. Offline password guessing must be made expensive via a deliberately
costly KDF (memory-hard by default; PBKDF2 is an iteration-hard compatibility
option). Truncation, reordering, and bit-flips of the ciphertext must be detected.

**Out of scope.** A compromised host while the tool runs (malware, keyloggers,
swap/coredump capture), an attacker who knows the password or keyfile, coercion,
traffic analysis of file size, and the fact that the file *is* a symcrypt file.
Secure deletion of the original plaintext is best-effort only.

---

## 4. Cryptographic design

### 4.1 Primitives

| Role            | Choice (default first)                                  |
|-----------------|---------------------------------------------------------|
| AEAD cipher     | **AES-256-GCM**, or ChaCha20-Poly1305                   |
| Key size        | 256-bit (32 bytes) for both ciphers                     |
| Auth tag        | 128-bit (16 bytes)                                      |
| Nonce           | 96-bit (12 bytes), constructed per chunk (see §4.3)     |
| KDF             | **Argon2id**, or scrypt, or PBKDF2-HMAC-SHA256          |
| CSPRNG          | OS RNG (`getrandom` / `OsRng`) for salt + nonce prefix  |
| Secret wiping   | `zeroize` on all key material and derived buffers       |

AEAD, KDF, and hash primitives come from the
[RustCrypto](https://github.com/RustCrypto) project (pure-Rust, widely
reviewed). Randomness comes from the operating system RNG. We do not roll our
own crypto.

### 4.2 Key derivation

```
key (32 bytes) = KDF(secret_input, salt, params)
```

- `salt` is 16 random bytes, fresh per file, stored in the header.
- `secret_input` is a domain-separated, length-prefixed encoding:
  `b"symcrypt secret v1\0" || u64be(password_len) || password_bytes ||
  u64be(keyfile_len) || keyfile_bytes`, where `u64be` is an unsigned 64-bit
  big-endian length. This avoids ambiguity between passwords and keyfile
  contents. Each part may be empty, but not both; creating a `Secret` with no
  password bytes and no keyfile bytes is an error.
- `params` are stored in the header so decrypt re-derives the identical key.
- Because the salt is random per file, encrypting two files with the same
  password yields different keys with overwhelming probability — so AEAD keys
  are not reused across files unless the RNG fails or repeats a salt.

**Keyfiles (v1).** A keyfile is read in full as raw bytes (must be 1 byte..=1 MiB
to bound memory; an empty or larger keyfile is a usage error, exit 2), combined
with the password as shown above, and zeroized after key derivation. With a
nonempty password it is a second factor — an attacker needs *both* the password
and the keyfile. In explicit keyfile-only mode (`--no-password -k`), the keyfile
is the only secret. Advisory flag bit1 is set when a keyfile was used, so on
decrypt a front-end can say "this file needs a keyfile" rather than only
reporting an auth failure when `-k` is missing. This bit is unauthenticated until
decrypt/verify succeeds, so it is only a hint for diagnostics; it never bypasses
tag verification, changes the exit code, or proves that a keyfile was required.
Keyfile contents are never stored; losing the keyfile means the file cannot be
decrypted.

### 4.3 Streaming AEAD (the STREAM construction)

Large files are encrypted as a sequence of fixed-size chunks using the
**STREAM** construction (Hoang–Reyhanitabar–Rogaway–Vizár; the same scheme used
by Tink and `age`). The plaintext is split into chunks of `chunk_size` bytes
(default 64 KiB); the final chunk may be full-sized or shorter, and is empty
only for empty plaintext.

For each chunk `i` (0-indexed) the 12-byte nonce is:

```
nonce[0..7]   = prefix        # 7 random bytes, stored in the header
nonce[7..11]  = counter        # u32 big-endian, starts at 0, +1 per chunk
nonce[11]     = final_flag     # 0x00 for normal chunks, 0x01 for the last chunk
```

- **Associated data (AAD):** chunk 0 is encrypted with the *entire serialized
  header* (everything before the body) as AAD; chunks `i > 0` use empty AAD.
  This binds the header — cipher/KDF/params/filename — to the ciphertext, so it
  cannot be altered (e.g. a cipher-downgrade) without breaking authentication.
- **Reordering** is prevented by the per-chunk counter.
- **Truncation / appending** is prevented by `final_flag`: the decryptor
  determines finality by reading one chunk ahead, and the only chunk encrypted
  with `final_flag = 1` is the genuine last one. Removing or adding a chunk
  flips an expected flag and fails authentication.
- **Counter overflow:** refuse to encrypt a stream needing more than 2³² chunks
  (≈ 256 TiB at 64 KiB), which is far beyond practical inputs. On decrypt the
  counter is advanced with checked arithmetic; a stream that would exceed 2³²
  chunks is rejected as an authentication failure (`SymError::Auth`, exit 3)
  rather than wrapping the counter.
- **v1 file-size cap:** refuse to encrypt, decrypt, or verify plaintext larger
  than 64 GiB. This is comfortably below the nonce counter limit and keeps
  AES-GCM usage within a conservative per-key data bound. The cap is enforced
  from streamed plaintext bytes, not from the caller's advisory `input_len`.
  Exceeding either the chunk-count or file-size limit while encrypting is
  reported as `SymError::InputTooLarge` (exit 1), detected during streaming and
  before any file output is finalized. During decrypt/verify, an authenticated
  plaintext stream that would exceed 64 GiB is also rejected as
  `SymError::InputTooLarge`; file outputs are removed, while stdout may already
  contain plaintext written before the cap was reached. Larger-file support can
  later use explicit segment keys or another reviewed construction.

### 4.4 Verification semantics

A failed tag check is reported as a single condition: *"wrong password or
corrupted/tampered file."* These are cryptographically indistinguishable with
AEAD, and conflating them avoids leaking which one occurred.

---

## 5. File format specification

### 5.1 Container layout

```
+----------------------------------+
| Header (plaintext, authenticated)|  ← also used as AAD for chunk 0
+----------------------------------+
| Body: chunk 0, chunk 1, ...      |  ← each chunk = ciphertext ‖ 16-byte tag
+----------------------------------+
```

All multi-byte integers are **big-endian**. The header is *not* encrypted (it
carries no secret key material, and any optional filename is visible) but *is*
authenticated via AAD during decrypt/verify.
`--info` can parse the header without a password, but cannot authenticate it.

### 5.2 Header fields

| Offset            | Size               | Field              | Notes                                             |
|-------------------|--------------------|--------------------|---------------------------------------------------|
| 0                 | 8                  | `magic`            | ASCII `"SYMCRYPT"`                                |
| 8                 | 1                  | `version`          | `0x01`                                            |
| 9                 | 1                  | `cipher_id`        | `0x01` AES-256-GCM · `0x02` ChaCha20-Poly1305     |
| 10                | 1                  | `kdf_id`           | `0x01` Argon2id · `0x02` scrypt · `0x03` PBKDF2   |
| 11                | 1                  | `flags`            | bit0 filename-present · bit1 keyfile-used (hint)  |
| 12                | 4                  | `kdf_p1`           | u32, meaning per KDF (§5.4)                       |
| 16                | 4                  | `kdf_p2`           | u32                                               |
| 20                | 4                  | `kdf_p3`           | u32                                               |
| 24                | 1                  | `salt_len`         | bytes (default 16)                                |
| 25                | `salt_len`         | `salt`             | random                                            |
| 25+`salt_len`     | 1                  | `nonce_prefix_len` | bytes (exactly 7 in v1)                           |
| 26+`salt_len`     | `nonce_prefix_len` | `nonce_prefix`     | random                                            |
| …                 | 4                  | `chunk_size`       | u32, plaintext bytes per chunk (default 65536)    |
| … (if flags bit0) | 2                  | `name_len`         | u16, 1..=255                                      |
| …                 | `name_len`         | `name`             | UTF-8 **basename only** (path components stripped) |

The "serialized header" used as AAD spans `magic` through the end of the
optional `name` field, i.e. everything before the body. `name_len` is a `u16`
even though v1 caps names at 255 bytes; the wider field reserves headroom to
raise the limit in a future version without changing the layout.

When the filename flag is present, `name` is a display/output hint only — never
trusted as a path. A well-formed `name` is a single UTF-8 basename of 1..=255
bytes that contains no `/`, `\`, `:`, or NUL, no Unicode control character
(U+0000–U+001F, U+007F, or U+0080–U+009F), and is neither `.` nor `..`
(interior dots, as in `report.pdf`, are
allowed). On encryption, front-ends derive it from the input path basename when
`--name` is set, reject `--name` when the input is stdin, reject any non-UTF-8,
unsafe, or over-long (>255-byte) basename as a usage error (exit 2) rather than
sanitizing or truncating it, and never store directory components.
On decryption, a stored `name` whose bytes are not valid UTF-8 is a malformed
header (exit 4); a `name` that is valid UTF-8 but fails the basename rules above
is ignored, and the output path is derived from the input path instead. A
well-formed stored name is used only as a relative filename. With file input and
no `-o`, that relative filename is placed beside the input file; with stdin
input, decrypt requires `-o` (§6.5).

### 5.3 Identifiers & flags

- **cipher_id:** `0x01` = AES-256-GCM, `0x02` = ChaCha20-Poly1305.
  (`0x03` reserved for XChaCha20-Poly1305.)
- **kdf_id:** `0x01` = Argon2id, `0x02` = scrypt, `0x03` = PBKDF2-HMAC-SHA256.
- **flags:** bit0 (`0x01`) = original filename field present; bit1 (`0x02`) =
  keyfile was used (advisory, so decrypt can give a clearer error if the keyfile
  is missing). Bit1 is unauthenticated until decrypt/verify succeeds and is
  never used as an authorization or format decision. Bits 2–7 reserved, must be
  0.

### 5.4 KDF parameter encoding

The three `kdf_p*` u32 fields are interpreted per `kdf_id`:

| KDF      | `kdf_p1`         | `kdf_p2`           | `kdf_p3`                                |
|----------|------------------|--------------------|-----------------------------------------|
| Argon2id | memory cost, KiB | time cost (passes) | parallelism (lanes)                     |
| scrypt   | log₂(N)          | r                  | p                                       |
| PBKDF2   | iterations       | 0 (reserved)       | 0 (reserved) — PRF fixed at HMAC-SHA256 |

All KDFs produce the 32-byte AEAD key from §4.1. Argon2id uses Argon2
version `0x13` (v1.3).

Header values are unauthenticated until decrypt/verify succeeds, so parsers
validate sizes and KDF costs before allocation or key derivation. Values outside
these ranges are malformed-header errors (exit 4) when read from a file, and
usage errors (exit 2) when supplied by the user as cipher/KDF knobs for a new
encryption (§6.3). `chunk_size` is not user-settable in v1 — every new file is
written with the 64 KiB default — but it is still range-checked on read so older
or hand-crafted files are validated, and the `EncryptOptions.chunk_size` field is
retained for forward compatibility and for tests that exercise multi-chunk
streams on small inputs. `core::encrypt` validates `EncryptOptions` before
writing any output: `kdf_params` must match `kdf`, `chunk_size` must be in
range, and any `filename` must satisfy the basename rules from §5.2. Invalid
programmatic options return `SymError::InvalidOptions` (exit 2), so a
programmatically constructed `EncryptOptions` (for example in tests) cannot
produce a file that fails its own read validation.

| Parameter            | Valid range / rule                                      |
|----------------------|---------------------------------------------------------|
| `salt_len`           | 16..=64 bytes; v1 encryption writes 16.                 |
| `nonce_prefix_len`   | Exactly 7 bytes in v1.                                  |
| `chunk_size`         | 4096..=16777216 bytes (4 KiB..=16 MiB).                 |
| `name_len`           | 1..=255 bytes when the filename flag is set.            |
| Argon2id memory      | 8192..=1048576 KiB (8 MiB..=1 GiB).                     |
| Argon2id time        | 1..=10 passes.                                          |
| Argon2id parallelism | 1..=16 lanes.                                           |
| scrypt `log₂(N)`     | 10..=20, and `N = 2^log₂(N)`.                           |
| scrypt `r`           | 1..=32.                                                 |
| scrypt `p`           | 1..=16.                                                 |
| scrypt memory cap    | `128 * N * r` must be <= 1 GiB.                         |
| PBKDF2 iterations    | 10000..=10000000.                                       |
| PBKDF2 reserved      | `kdf_p2 == 0` and `kdf_p3 == 0`.                        |

### 5.5 Body / chunk layout

The body is a sequence of chunks. Each on-disk chunk is the AEAD output
`ciphertext ‖ tag` (16-byte tag appended). Non-final chunks carry exactly
`chunk_size` plaintext bytes (so `chunk_size + 16` on disk); the final chunk
carries 0..=`chunk_size` plaintext bytes.

The encryptor fills each chunk by reading up to `chunk_size` plaintext bytes,
marking a chunk final (`final_flag = 1`) when no further input follows. A
compliant encryptor never emits an extra empty final chunk after one or more
full non-final chunks; the only empty final chunk is the sole chunk for empty
plaintext. The decryptor reads `chunk_size + 16` bytes at a time and buffers one
chunk ahead so it can set `final_flag` correctly: a chunk is final iff no bytes
follow it. The body must contain at least one chunk; an empty file produces
exactly one final chunk of 16 bytes (tag only). A structurally malformed body —
a trailing fragment shorter than the 16-byte tag, no body after a complete
header, or an empty final chunk after a previous chunk — is reported as an
authentication failure (exit 3), exactly like a wrong password or a flipped bit;
truncation and tampering are deliberately indistinguishable (§4.4).

**Size accounting.** `num_chunks = max(1, ceil(plaintext_len / chunk_size))`;
`body_len = plaintext_len + 16 * num_chunks`. Example: a 200 000-byte file at 64
KiB → 4 chunks → body 200 064 bytes; with a ~53-byte header, total ≈ 200 117
bytes (~117 bytes overhead).

### 5.6 ASCII armor (optional outer layer)

With `--armor`, the binary container is base64-encoded and wrapped:

```
-----BEGIN SYMCRYPT MESSAGE-----
<base64, wrapped at 64 columns>
-----END SYMCRYPT MESSAGE-----
```

Encryption uses standard base64 (RFC 4648 `+`/`/` alphabet, with `=` padding),
writes LF line endings, wraps complete base64 lines at exactly 64 columns (with
the final line shorter when needed), and emits no extra text before the begin
marker or after the end marker. Decrypt,
verify, and info auto-detect armor by the `-----BEGIN SYMCRYPT MESSAGE-----`
line and strip it before parsing the binary header. They accept LF or CRLF line
endings and surrounding whitespace, but require the exact begin/end marker
lines once armor is detected. Extra non-whitespace outside the markers,
non-base64 body content, or a missing end marker is malformed armor
(`MalformedHeader`, exit 4). Armor is purely an outer transport encoding; it is
not represented in the binary header.

### 5.7 Versioning & forward compatibility

The magic is checked first, then the `version` byte. An unknown `version`,
`cipher_id`, or `kdf_id`, or any reserved `flags` bit set, is rejected with a
clear error (exit code 4) — symcrypt never guesses at an unrecognized format.
New ciphers or KDFs take new IDs (with a version bump if the layout changes).
Because every file stores its own KDF parameters, files remain decryptable as
the *defaults* for new files evolve over time.

---

## 6. CLI specification

`symcrypt` is the command-line front-end: a thin wrapper that parses arguments,
resolves the password, opens streams, calls `symcrypt-core`, and maps results to
exit codes. It contains no crypto or format logic. The flags below are also the
shared vocabulary the TUI and GTK app expose through their own controls where
applicable — cipher and KDF names, defaults, and output-path rules all come from
core helpers, so shared behavior stays identical across front-ends. CLI-only
behavior includes stdin/stdout streaming (`-`), password files, and password
environment variables.

### 6.1 Synopsis

```
symcrypt (-e|--encrypt | -d|--decrypt | -i|--info | --verify) <FILE> [options]
```

Except for `-h/--help` and `-V/--version`, exactly one mode and one `<FILE>` are
required. `<FILE>` of `-` means **stdin**.

### 6.2 Modes

| Mode             | Action                                                            |
|------------------|-------------------------------------------------------------------|
| `-e, --encrypt`  | Encrypt `<FILE>` → output.                                         |
| `-d, --decrypt`  | Decrypt `<FILE>` → output.                                         |
| `-i, --info`     | Print unauthenticated header metadata (cipher, KDF + params, version, flags, chunk size, and the stored filename when present and well-formed) without decrypting. No password needed. |
| `--verify`       | Stream-decrypt and discard the output (nothing written) to verify integrity + password. Exit 0 if valid. |

`--info` writes stable UTF-8 `key: value` lines to stdout in this exact order:
`format`, `version`, `cipher`, `kdf`, `kdf_params`, `flags`, `keyfile_hint`,
`chunk_size`, `salt_len`, `nonce_prefix_len`, `name_status`, and `name`. Values
are display forms from the shared core helpers: `format: symcrypt`, decimal
numeric values, lowercase cipher/KDF names, `flags` as two-digit lowercase hex
(`0x00`), and `keyfile_hint: true|false`. `kdf_params` is
`memory=<KiB>,time=<N>,parallelism=<N>` for Argon2id, `log_n=<N>,r=<N>,p=<N>`
for scrypt, and `iterations=<N>` for PBKDF2. `name_status` is `absent`,
`present`, or `ignored_unsafe`; `name` is the stored basename only when
`name_status: present`, and is otherwise empty. A non-UTF-8 stored name is a
malformed header and does not produce normal `--info` output.

### 6.3 Options

| Flag                       | Applies to     | Description                                                           |
|----------------------------|----------------|-----------------------------------------------------------------------|
| `-o, --output <FILE>`      | enc/dec        | Output path; `-` = stdout. Defaults in §6.5.                          |
| `-p, --password <PW>`      | enc/dec/verify | Password inline (**discouraged**, see §11).                           |
| `--password-file <FILE>`   | enc/dec/verify | Read password from a file (trailing newline trimmed).                 |
| `--password-env <VAR>`     | enc/dec/verify | Read password from an environment variable.                           |
| `--no-password`            | enc/dec/verify | Use an empty password; valid only with `-k`.                          |
| `-k, --keyfile <FILE>`     | enc/dec/verify | Keyfile material combined with the password source.                   |
| `-c, --cipher <NAME>`      | encrypt        | `aes-256-gcm` (default) or `chacha20-poly1305`.                       |
| `--kdf <NAME>`             | encrypt        | `argon2id` (default), `scrypt`, or `pbkdf2`.                          |
| `--argon2-memory <KiB>`    | encrypt        | Argon2id memory cost.                                                 |
| `--argon2-time <N>`        | encrypt        | Argon2id passes.                                                      |
| `--argon2-parallelism <N>` | encrypt        | Argon2id lanes.                                                       |
| `--scrypt-log-n <N>`       | encrypt        | scrypt log₂(N).                                                       |
| `--scrypt-r <N>`           | encrypt        | scrypt block-size parameter `r`.                                      |
| `--scrypt-p <N>`           | encrypt        | scrypt parallelization parameter `p`.                                 |
| `--pbkdf2-iterations <N>`  | encrypt        | PBKDF2-HMAC-SHA256 iteration count.                                   |
| `-a, --armor`              | encrypt        | ASCII-armored (base64) output. (Decrypt/verify/info auto-detect.)     |
| `--name`                   | encrypt        | Store the input's basename; boolean switch, off by default (sensitive). |
| `-f, --force`              | enc/dec        | Overwrite an existing output file (default: refuse).                  |
| `--remove`                 | enc/dec        | Best-effort delete the input after success (default: keep).           |
| `--progress/--no-progress` | enc/dec/verify | Progress bar. Default: auto (on when stderr is a TTY).                |
| `-v, --verbose`            | all            | More diagnostics on stderr.                                           |
| `-q, --quiet`              | all            | Suppress progress and status output.                                  |
| `-V, --version`            | —              | Print version.                                                        |
| `-h, --help`               | —              | Print help.                                                           |

Cipher and KDF names are parsed as exact, lowercase strings shown in the table;
there are no aliases and no case folding in v1.

Flags supplied for a mode they do not apply to (per the **Applies to** column)
are usage errors (exit 2), not silently ignored — e.g. `-c/--cipher` or any KDF
cost knob with `--decrypt`/`--info`/`--verify`, `-o/--output` with
`--info`/`--verify`, or `-p/--password` with `--info`.
KDF-specific cost knobs are also usage errors unless their matching `--kdf` is
selected: Argon2id knobs require `--kdf argon2id` or the default KDF, scrypt
knobs require `--kdf scrypt`, and PBKDF2 knobs require `--kdf pbkdf2`. Supplying
`--scrypt-*` or `--pbkdf2-iterations` never implicitly changes the KDF.
Unspecified cost knobs use the selected KDF's defaults from §12.
`-q/--quiet` and `-v/--verbose` are mutually exclusive. `--progress` with
`--quiet` is a usage error; `--no-progress` with `--quiet` is allowed but
redundant. Quiet mode does not suppress primary stdout output such as `--info`,
nor does it suppress warnings or errors on stderr.

### 6.4 Password input rules

For modes that require a secret (Encrypt / Decrypt / Verify), at most one of
`-p`, `--password-file`, `--password-env`, or `--no-password` may be supplied;
supplying more than one is a usage error. If none is supplied, the CLI uses an
**interactive prompt** (no echo). On **encrypt**, an interactive prompt asks
twice and must match.
`--no-password` is valid only with `-k` and is the explicit keyfile-only mode.
A keyfile (`-k`), if given, is always combined with whatever password source is
used. The resolved secret must contain at least one byte of password or keyfile
material; if both are empty, this is a usage error before the core is called.
An empty password is accepted **only** via `--no-password`: a `-p ''` argument,
an empty or newline-only `--password-file`, a `--password-env` variable that is
set but empty, or an empty interactive entry is a usage error (the encrypt
prompt re-asks rather than accepting an empty passphrase). This keeps a
misconfigured password source from silently downgrading a password-plus-keyfile
setup to keyfile-only.
`-k/--keyfile` requires an existing regular file path; `-` is rejected so stdin
remains reserved for the main input stream. Directories, special files, and
symlinks that resolve to non-regular files are usage errors.

Password bytes are used exactly as provided; symcrypt does no Unicode
normalization. Password text obtained from CLI argv, environment-variable
values, TUI fields, and GTK entries is encoded as UTF-8 bytes; non-UTF-8
password argv or environment values are usage errors. Path arguments are
OS-native paths and may be non-UTF-8; only a basename stored with `--name` must
be valid UTF-8 (§5.2). If `--password-env <VAR>` names an unset variable, that
is a usage error.
`--password-file` requires an existing regular file path; `-` is rejected so
stdin remains reserved for the main input stream. Directories, special files,
and symlinks that resolve to non-regular files are usage errors. It reads at
most 1 MiB of raw bytes; a larger file is a usage error. It removes exactly one
trailing LF or CRLF if present; no other whitespace is trimmed.

### 6.5 Output defaults

- **Encrypt, no `-o`:** `<input>.symcrypt` (`.symcrypt.asc` if `--armor`).
- **Decrypt, no `-o`:** use the stored filename if present and well-formed
  (§5.2); otherwise — no stored name, or one that fails the basename rules —
  strip `.symcrypt.asc`, then `.symcrypt`, then `.asc`; else append `.dec`. If
  stripping a recognized extension would leave an empty basename (an input named
  exactly `.symcrypt`, `.asc`, or `.symcrypt.asc`), treat it as having no
  recognizable extension and append `.dec` to the original basename instead
  (e.g. `.symcrypt` → `.symcrypt.dec`).
  Stored names are written beside the input file. Refuse to overwrite unless
  `-f`.
- **Filesystem path inputs/outputs:** when `<FILE>` is not `-`, it must be an
  existing regular file. Directories, special files, and symlinks that resolve
  to non-regular files are usage errors. Output paths may name a new file or an
  existing regular file; existing directories or special files are usage errors
  even with `-f`.
- **Output must differ from input:** if the resolved output path refers to the
  same file as the input, the operation is a usage error (exit 2), refused
  before any work begins — preventing the temp-file rename from clobbering the
  source and, with `--remove`, preventing deletion of the freshly written output.
  Resolve symlinks and compare filesystem identity (including hardlinks) using
  platform metadata where available; where identity metadata is unavailable,
  compare canonical absolute paths and still reject obvious self-overwrites.
- **Stdin input (`<FILE>` is `-`):** encrypt/decrypt require `-o`; `--remove` is
  rejected. `--info` and `--verify` accept stdin and write no output file, so they
  need no `-o`.
- **File outputs:** write to a sibling temporary file, then rename it into place
  only after success. On Unix, create the temporary output with mode `0600`
  (`rw-------`) and do not preserve source-file permissions in v1. Remove the
  temporary file on error, authentication failure, cancellation, or output
  finalization failure. A failed rename/finalization is a general I/O error
  (exit 1), and `--remove` is not attempted.
- **`--remove`:** after a successful encrypt/decrypt and successful output
  finalization, attempt to delete the input path. If deletion fails, keep the
  successful output, print a warning on stderr, and still exit 0.
- `-o -` writes to stdout. Progress is independent of stdout (it renders on
  stderr), so it still follows the normal rule — on when stderr is a TTY; armor
  is recommended when stdout is a terminal. If stdout is used, partial output
  may already have been written before an error is detected.

### 6.6 Exit codes

| Code | Meaning                                          |
|------|--------------------------------------------------|
| 0    | Success                                          |
| 1    | General error (I/O, etc.)                        |
| 2    | Usage / argument error                           |
| 3    | Authentication failure (wrong password or tampered file) |
| 4    | Unsupported, unknown, or malformed format/header |
| 130  | Canceled by the user                             |

Errors returned by `symcrypt-core` map directly from its `SymError` variants —
the front-end does not reclassify them: `Auth` → 3; `BadMagic` /
`UnsupportedVersion` / `UnknownCipher` / `UnknownKdf` / `ReservedFlags` /
`MalformedHeader` → 4; `InvalidOptions` (including an empty `Secret`, an empty
or over-large keyfile buffer, mismatched KDF params, an unsafe stored filename,
or an out-of-range programmatic `chunk_size`) → 2; `Canceled` → 130; `Io`,
`InputTooLarge`, and the like → 1; argument/usage problems caught before the
core is called → 2. The mapping lives in `symcrypt-common` and is shared by the
CLI and TUI.

`MalformedHeader` covers a header that is structurally invalid rather than merely
unrecognized: an out-of-range `salt_len`, `nonce_prefix_len`, `chunk_size`,
`name_len`, or KDF cost (§5.4); a stored `name` whose bytes are not valid UTF-8;
corrupt ASCII armor; or end-of-input reached before the header is complete. A
body too short to form a chunk (a trailing fragment under 16 bytes, or no body
after a complete header) is reported as `Auth` (exit 3), not distinguished from
tampering (§4.4, §5.5).

On SIGINT (Ctrl-C), the CLI installs a handler that flips the same cancellation
flag the worker-thread front-ends use. Cancellation is cooperative: the core
checks before and after key derivation and between chunks, but a KDF call already
running may finish before cancellation is observed. When cancellation is
observed, the core's `on_progress` returns `ControlFlow::Break`, the operation
returns `SymError::Canceled`, any temporary output is removed (§6.5), and the
process exits 130.

### 6.7 Examples

```sh
symcrypt -e report.pdf                      # → report.pdf.symcrypt (prompts for password)
symcrypt -e report.pdf -o - --armor > out   # armored to stdout
symcrypt -d report.pdf.symcrypt             # → report.pdf (or prompts/derives name)
symcrypt -i report.pdf.symcrypt             # show unauthenticated header metadata
printf 'secret' | PW='passphrase' symcrypt -e - -o s.symcrypt --password-env PW
symcrypt -e vault.tar -k usb.key --no-password
symcrypt -e big.iso -c chacha20-poly1305 --remove
```

---

## 7. TUI application design

**Binary:** `symcrypt-tui`. **Toolkit:** [ratatui](https://ratatui.rs/) for
widgets/layout + [crossterm](https://docs.rs/crossterm) for the terminal backend
(raw mode, key and resize events). Like the other front-ends it is a thin view
over `symcrypt-core` (reusing `symcrypt-common` for the terminal glue) and holds
no crypto or format logic — it builds the same `Secret`/`EncryptOptions` and
calls the same four core functions.

### 7.1 Layout & flow

A single full-screen form, navigable entirely by keyboard:

All TUI path fields accept filesystem paths only; a literal `-` is rejected
because the terminal UI owns stdin/stdout. Input and keyfile paths must be
existing regular files; directories, special files, and symlinks that resolve to
non-regular files are rejected. Output paths may name a new file or an existing
regular file, with the same overwrite and same-file checks as the CLI (§6.5).
CLI remains the only v1 front-end with stdin/stdout streaming.

- **Mode tabs:** Encrypt / Decrypt / Info / Verify.
- **Input path** field (plain text entry for v1; a built-in file-browser popup
  is a post-v1 enhancement).
- **Output path** field, shown for Encrypt / Decrypt, prefilled from
  `core::default_*_output` (§6.5), and editable.
- **Password** field, shown for Encrypt / Decrypt / Verify (masked, captured
  inside the event loop), plus a **confirm** field shown only in Encrypt mode,
  a show/hide toggle, and a keyfile-only toggle equivalent to `--no-password`.
  Password-file and password-env sources are CLI-only.
- **Advanced** (collapsible): Encrypt-only cipher and KDF selectors, `--name`
  and armor toggles, KDF-specific cost knobs, and (Encrypt / Decrypt)
  remove-input-after-success and overwrite-existing toggles mirroring the CLI's
  `--remove` and `-f`; keyfile path is available in Encrypt / Decrypt / Verify.
- **Progress gauge** + status line during an operation.
- **Footer** key hints (Tab/Shift-Tab to move, Enter to run, Esc to cancel/quit,
  `?` for help).

Optionally launch with a path (`symcrypt-tui <file>`) to prefill the input
field.

### 7.2 Concurrency & cancellation

The ratatui event loop stays on the main thread; the crypto call runs on a
worker thread. `Progress` updates are sent over an `mpsc` channel that the UI
drains each tick to redraw the gauge. Esc requests cancellation — the worker's
`on_progress` callback returns `ControlFlow::Break` once the core observes the
cancel flag before/after KDF work or between chunks, the core returns
`SymError::Canceled`, and the front-end removes any temporary output it created
and shows a non-error canceled state. A KDF call already running may finish
before cancellation takes effect. The password lives in a zeroizing buffer moved
into the worker.

Note: password capture happens in the TUI's own masked field (under crossterm
raw mode), not `rpassword`, which would conflict with raw mode.

---

## 8. GTK application design

**Binary:** `symcrypt-gtk`. **Framework:** [relm4](https://relm4.org/) — an
Elm-architecture layer over gtk4-rs — with
[libadwaita](https://gnome.pages.gitlab.gnome.org/libadwaita/) for modern GNOME
styling and `relm4-components` for ready-made helpers. Like the CLI and TUI it
is a thin front-end and links the same `symcrypt-core`; it holds no crypto or
format logic.

### 8.1 Component model

relm4 structures the app as the Elm triad: a `Model` (UI state), `Input`
messages (user/UI events), and a declarative `view!`. `AppModel` holds the
selected mode, input/output paths, password + confirm, keyfile-only choice,
advanced options (cipher, KDF, KDF-specific cost knobs, keyfile, `--name`,
armor, remove-input-after-success, and overwrite approval for the selected
output path), and run status/progress. UI events become `Input` messages —
`SetInputFile`, `PickOutput`, `SetPassword`, `SetKeyfile`, `ToggleAdvanced`,
`Run`, `Cancel` — handled in `update`, which mutates the model and re-renders.
The model never calls crypto directly; it builds a `Secret` + `EncryptOptions`
and invokes the core.

### 8.2 Widgets (libadwaita)

- `adw::ApplicationWindow` + `adw::ToolbarView` / `adw::HeaderBar`.
- `adw::ViewStack` + `ViewSwitcher` for the Encrypt / Decrypt / Info / Verify modes.
- `adw::EntryRow` for paths, each with a "browse" button opening
  `gtk::FileDialog`; the output row is shown only for Encrypt / Decrypt and is
  prefilled from `core::default_*_output` (§6.5). The save dialog's native
  overwrite confirmation is the GTK equivalent of the CLI's `-f`; if a path is
  typed or prefilled and already exists, Run shows the same confirmation before
  finalization. Without overwrite approval, the GTK app refuses to overwrite.
  Input and keyfile selections must be existing regular files, and output paths
  use the same regular-file, overwrite, and same-file checks as the CLI (§6.5).
- `adw::PasswordEntryRow` for the password in Encrypt / Decrypt / Verify modes
  (+ a confirm row in Encrypt mode), a keyfile-only toggle equivalent to
  `--no-password`, and a keyfile chooser row (`-k`). Password-file and
  password-env sources are CLI-only.
- `adw::PreferencesGroup` + `adw::ExpanderRow` for the collapsible Advanced
  section.
- `gtk::ProgressBar` + `adw::ToastOverlay` for progress and status/errors.
- `gtk::DropTarget` on the window for drag-and-drop of an input file.

### 8.3 Concurrency & cancellation

The crypto call must not block the GTK main loop, so it runs as a relm4
**`Command`** (background task via `spawn_blocking`) or a `Worker` on its own
thread. It streams `Progress` back as `CommandOutput` messages that `update_cmd`
applies to the progress bar; success or failure arrives as a final message shown
via an `adw::Toast` or error dialog. Cancellation uses the command's shutdown
handle (a shared `AtomicBool`) — the core observes it before/after KDF work or
between chunks, the `on_progress` callback returns `ControlFlow::Break`, the
core returns `SymError::Canceled`, and the GTK worker removes any temporary
output it created and shows a non-error canceled state. A KDF call already
running may finish before cancellation takes effect. The password is moved into
the worker in a zeroizing buffer.

---

## 9. Dependencies

| Crate                          | Used in            | Purpose                                  |
|--------------------------------|--------------------|------------------------------------------|
| `aes-gcm`                      | core               | AES-256-GCM AEAD                         |
| `chacha20poly1305`             | core               | ChaCha20-Poly1305 AEAD                   |
| `argon2`                       | core               | Argon2id KDF                             |
| `scrypt`                       | core               | scrypt KDF                               |
| `pbkdf2` + `sha2`              | core               | PBKDF2-HMAC-SHA256 KDF                   |
| `rand` / `getrandom`           | core               | CSPRNG for salt + nonce prefix           |
| `zeroize`                      | core               | Wipe key material from memory            |
| `base64`                       | core               | ASCII armor                              |
| `thiserror`                    | core, common       | Typed errors (`SymError`)                |
| `tempfile`                     | common, gtk, tests | Sibling temp files and test directories  |
| `clap` (derive)                | cli, tui¹          | Argument parsing                         |
| `rpassword`                    | cli                | No-echo password prompt                  |
| `indicatif`                    | cli                | Progress bar                             |
| `ratatui`                      | tui                | Terminal UI widgets/layout               |
| `crossterm`                    | tui                | Terminal backend, raw mode, key events   |
| `relm4` + `relm4-components`   | gtk                | GUI framework over gtk4-rs (Elm arch.)²  |
| `libadwaita`                   | gtk                | GNOME widgets and styling                |
| `anyhow`                       | cli, tui, gtk      | Error reporting / context                |

¹ The TUI uses `clap` only for an optional launch path; all interaction happens
in the UI, and password input is captured in its own masked field (not
`rpassword`).

² relm4 builds on gtk4-rs and pairs with libadwaita for styling;
`relm4-components` supplies file-dialog and worker helpers. `symcrypt-common`
depends only on `symcrypt-core`, the standard library, `thiserror`, and
`tempfile`.

Version requirements are selected at scaffolding time via `cargo add` (latest
compatible), and `Cargo.lock` pins the resolved versions. RustCrypto crates are
chosen for being pure-Rust and widely reviewed.

---

## 10. Testing strategy

**Core unit tests**

- KDF determinism: same `(secret, salt, params)` → identical key; different
  params → different key.
- Secret assembly: domain separation and length prefixes avoid password/keyfile
  ambiguity; empty password + empty keyfile is rejected, and a present keyfile
  buffer must be 1 byte..=1 MiB.
- Header serialize → parse round-trip for every cipher/KDF/flag combination.
- Header validation rejects out-of-range lengths, chunk sizes, reserved fields,
  and excessive KDF costs before allocation or key derivation, reporting them as
  `MalformedHeader` (exit 4); a non-UTF-8 stored name is likewise rejected, while
  a valid-UTF-8 but unsafe name is ignored in favor of input-path derivation.
- Encrypt-option validation rejects an unsafe or over-long stored filename,
  mismatched KDF params, and an out-of-range `chunk_size` with
  `InvalidOptions`; it rejects plaintext larger than the v1 size cap with
  `InputTooLarge` before any output is finalized.
- Decrypt/verify size-cap enforcement rejects authenticated plaintext larger
  than the v1 size cap with `InputTooLarge`.
- ASCII armor parser accepts LF/CRLF and surrounding whitespace, and rejects
  extra non-whitespace outside the markers, invalid base64, and missing end
  markers.
- STREAM nonce derivation: counter increments, final flag placement.
- Pure helpers: `default_encrypt_output` / `default_decrypt_output` (including
  the empty-basename fallback, e.g. `.symcrypt` → `.symcrypt.dec`) and
  exact lowercase cipher/KDF `FromStr`/`Display` round-trips with alias/case
  rejection.

**Round-trip** (parameterized over sizes: 0, 1, `chunk_size−1`, `chunk_size`,
`chunk_size+1`, several MiB): encrypt then decrypt reproduces the input exactly,
for each cipher and KDF.

**Negative / tamper**

- Flip a byte in the body → auth failure.
- Change a header byte to another valid value (e.g. `cipher_id` `0x01` →
  `0x02`) → auth failure (AAD); change it to an unknown ID → unsupported
  format.
- Wrong password / wrong-or-missing keyfile → auth failure.
- Truncate the last chunk → failure (final flag).
- Append a chunk → failure.
- Swap two chunks → failure (counter).
- Truncate the body to a sub-tag fragment, or drop it entirely → auth failure
  (exit 3), indistinguishable from tampering.

**Known-answer vectors:** commit fixed encrypted blobs to catch accidental
format changes across versions. Vector generation uses a test-only deterministic
salt/nonce-prefix source so fixtures are reproducible; production encryption
always uses OS randomness.

**Front-end tests.** Because the front-ends are thin, most coverage lives in
core. `symcrypt` gets CLI integration tests (`assert_cmd` + `tempfile`):
default-extension behavior, required `-o` for stdin encrypt/decrypt,
`--remove` rejection with stdin, `--remove` warning-but-success when deletion
fails after successful output finalization, output-equals-input refusal, `-o -`
/ stdout, armor round-trip, exact `--info` output, `--verify` success/failure,
clobber refusal vs `-f`, KDF-knob mismatch usage errors, `-q`/`-v` and
`--progress`/`--quiet` conflicts, rejection of `-` for `--password-file` and
`-k/--keyfile`, password-file and keyfile size caps, zero-byte keyfile
rejection, rejection of empty-password sources (`-p ''`, empty `--password-file`,
set-but-empty `--password-env`) except `--no-password`, temp-file cleanup and
Unix `0600` output mode, rejection of directories and special files for input,
password-file, keyfile, and existing output paths, symlink-resolved same-file
refusal, hardlink same-file refusal where platform metadata supports it, exit
codes including
130 for cancellation, exact lowercase cipher/KDF parsing, non-UTF-8
OS-native path handling where the platform supports it, and password bytes via
file/env/`--no-password`. The
`symcrypt-common`
glue (path-or-stdin opening, clobber check, best-effort remove, password-source
exclusivity/resolution, exit-code mapping, and temp-file finalization) is
unit-tested directly. `symcrypt-tui` gets light tests of its non-UI glue,
including rejection of `-` for path fields;
headless GTK testing is limited, so `symcrypt-gtk` relies on manual verification
plus the shared core/helper tests.

Per repo convention, tests accompany every code change.

---

## 11. Security considerations

- **`-p <password>` leaks** the password to `ps`, shell history, and process
  listings. The help text marks it discouraged; prefer prompting,
  `--password-file`, or `--password-env`.
- **Secure deletion is best-effort.** On SSDs, journaling, and copy-on-write
  filesystems, overwriting does not guarantee erasure. `--remove` does a plain
  delete and the help says so plainly — we will not pretend to "shred."
- **Filenames/sizes can be sensitive.** Storing the original filename is opt-in
  (`--name`) and stores only a well-formed basename. Approximate plaintext size
  always leaks from ciphertext length; symcrypt does not pad. v1 refuses to
  encrypt, decrypt, or verify plaintext larger than 64 GiB. (Padding is a
  possible future option.)
- **Wrong password vs. corruption** are indistinguishable by design and reported
  as one condition.
- **Unauthenticated header data is bounded.** Header lengths and KDF parameters
  are capped before allocation or key derivation so malformed files cannot demand
  unbounded memory or CPU.
- **Stdout output cannot be rolled back.** File outputs use temporary files and
  are finalized only after success, but stdout may already contain partial output
  if an operation fails late.
- **File outputs are private by default.** On Unix, temporary output files are
  created with mode `0600` and source-file permissions are not preserved in v1.
- **Nonce reuse is avoided under the RNG assumption:** a random per-file key
  (random salt) plus a random nonce prefix and per-chunk counter/final-flag nonce
  means no `(key, nonce)` pair repeats unless the RNG repeats the relevant
  values or fails.
- **Header downgrade/tamper** is prevented during decrypt/verify by
  authenticating the full header as AAD. Header metadata shown by `--info` is
  unauthenticated until decrypt or verify succeeds.
- **Keyfiles** can add a second factor but are read into process memory (size-capped at 1 MiB); they
  are zeroized after key derivation, and their loss is unrecoverable.
  Keyfile-only operation requires an explicit `--no-password` / keyfile-only
  choice and relies on possession of that file as the only secret.
- **Memory hygiene:** keys and derived buffers are wrapped in `zeroize` types and
  wiped on drop. We cannot prevent the OS from paging secrets to swap.
- **KDF defaults** target meaningful offline-guessing cost on commodity hardware
  while staying usable; experts can raise them, and the chosen values are stored
  per file so old files still decrypt.

Per repo policy, these implications are flagged for confirmation before
implementation begins, and tests in §10 verify each integrity property.

---

## 12. Defaults summary

| Parameter            | Default                         |
|----------------------|---------------------------------|
| Cipher               | AES-256-GCM                     |
| KDF                  | Argon2id                        |
| Argon2id memory      | 65536 KiB (64 MiB)              |
| Argon2id time        | 3 passes                        |
| Argon2id parallelism | 1 lane                          |
| scrypt (alt)         | log₂N=15 (N=32768), r=8, p=1    |
| PBKDF2 (alt)         | 600 000 iterations, HMAC-SHA256 |
| Salt length          | 16 bytes                        |
| Nonce prefix         | 7 bytes (12-byte STREAM nonce)  |
| Chunk size           | 65536 bytes (64 KiB)            |
| Plaintext size cap   | 64 GiB                          |
| Key length           | 32 bytes (256-bit)              |
| Tag length           | 16 bytes (128-bit)              |
| Output extension     | `.symcrypt` (`.symcrypt.asc` armored) |

---

## 13. Out of scope for v1

Asymmetric crypto, compression, plaintext padding / size hiding, keyfiles
managed by a keyring/agent, multi-recipient files, special handling of Windows
reserved device names (`CON`, `NUL`, …) in stored filenames, and HKDF-based
per-file subkey separation (the random-salt-per-file design already prevents key
reuse except on salt collision or RNG failure; HKDF separation is a possible
hardening later).

---

## 14. Resolved decisions

All open questions are now settled:

- [x] **Keyfile in v1.** Yes — keyfiles ship in the initial version (§4.2, §6).
- [x] **GTK framework.** Use **relm4** (Elm architecture over gtk4-rs) with
      libadwaita styling (§8), superseding the earlier plain-GTK4 vs. libadwaita
      question.
- [x] **Argon2id parallelism default.** Keep **1 lane** (deterministic and
      portable; §12).
- [x] **`--info` and `--verify` in v1.** Yes — both ship in v1 (§6.2).
- [x] **Shared terminal glue.** Use a dedicated **`symcrypt-common`** crate for
      the CLI+TUI glue (§2) so nothing is reimplemented.
- [x] **TUI file selection.** Plain **path entry** for v1; a built-in
      file-browser popup is a post-v1 enhancement (§7.1).
- [x] **Secret input encoding.** Use domain-separated, length-prefixed password
      + keyfile bytes, and reject empty password + empty keyfile (§4.2).
- [x] **Header/KDF validation caps.** Bound all unauthenticated lengths,
      `chunk_size`, and KDF costs before allocation or derivation (§5.4).
- [x] **KDF-specific CLI knobs.** Expose Argon2id, scrypt, and PBKDF2 parameters
      with explicit KDF-specific flags rather than overloaded generic flags
      (§6.3).
- [x] **Stdin and output finalization.** Require `-o` for stdin encrypt/decrypt,
      reject `--remove` with stdin, and finalize file outputs via temp-file
      rename only after success (§6.5).
- [x] **Keyfile-only and cancellation semantics.** Keyfile-only mode requires
      `--no-password`; cancellation returns `SymError::Canceled`, maps to CLI
      exit 130, and is shown as non-error cancellation in UIs (§6.4, §6.6, §7,
      §8).
- [x] **CLI edge-case behavior.** `--info` has stable `key: value` output;
      password/keyfile paths reject `-`; password files and keyfiles are
      size-capped; empty keyfiles are rejected; quiet/verbose/progress conflicts
      are defined; and `--remove` warns but still exits 0 if deletion fails
      after a successful operation (§6).
- [x] **Post-review contract details.** The 64 GiB plaintext cap applies to
      encrypt, decrypt, and verify; front-end path fields reject `-` where
      stdin/stdout are not supported; filesystem inputs/keyfiles/password files
      must be regular files; output same-file checks resolve symlinks and use
      hardlink identity where available; cipher/KDF names are exact lowercase
      strings with no aliases; non-UTF-8 OS-native paths are allowed except
      where text is stored in the header; and password-file/env sources are
      CLI-only (§4, §6, §7, §8).

---

## 15. Implementation plan

The step-by-step implementation plan now lives in per-component files, so this
document stays focused on *what* to build while the plans capture *how* and *in
what order*. They currently start as stubs holding the original checklist items
and will be expanded once this design stabilizes.

| Plan file                          | Covers                                                       |
| ---------------------------------- | ------------------------------------------------------------ |
| `IMPLEMENTATION_PLAN_01_CORE.md`   | Workspace scaffold, `symcrypt-core`, and `symcrypt-common`.  |
| `IMPLEMENTATION_PLAN_02_CLI.md`    | `symcrypt` command-line front-end.                           |
| `IMPLEMENTATION_PLAN_03_TUI.md`    | `symcrypt-tui` terminal front-end.                           |
| `IMPLEMENTATION_PLAN_04_GTK.md`    | `symcrypt-gtk` relm4/libadwaita desktop front-end.           |
