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
15. [Implementation checklist](#15-implementation-checklist)

---

## 1. Goals & non-goals

### Goals

- **Confidentiality + integrity** of file contents at rest, using authenticated
  encryption (AEAD). Any tampering or corruption is detected on decrypt.
- **Self-describing files**: a magic marker and a versioned, authenticated
  header carry everything needed to decrypt (cipher, KDF, KDF params, salt,
  nonce, chunk size) — only the secret (password/keyfile) is external.
- **Streaming**: encrypt/decrypt files of arbitrary size with bounded memory.
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
    │   └── src/lib.rs          # path-or-stdin I/O, clobber check, secure remove,
    │                           #   password-source resolution, exit-code mapping
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
| Header inspection for `--info`                            | ✓               | call it    |
| Parsing args / drawing widgets / reading keypresses       |                 | ✓          |
| Acquiring the password (prompt / file / env / entry)      |                 | ✓          |
| Opening files or stdin/stdout, the clobber *decision*, `--remove` |         | ✓          |
| Rendering progress, formatting errors, exit codes         |                 | ✓          |

The core never reads argv, never prompts, never touches the filesystem on its
own, never decides whether to overwrite, and never exits the process. It takes
generic `Read`/`Write` and reports progress through a callback. The terminal glue
shared by `symcrypt` and `symcrypt-tui` (open-path-or-stdin, clobber check,
secure remove, password-source resolution, exit-code mapping) lives in the
`symcrypt-common` crate so it is written once. `symcrypt-gtk` does not use it —
it relies on the core plus GTK-native file handling.

### 2.3 Core public API (sketch)

```rust
// ---- Inputs the front-ends assemble and hand to the core ----

/// Password and/or keyfile material; zeroized on drop.
pub struct Secret { /* … */ }
impl Secret {
    pub fn new(password: &[u8], keyfile: Option<&[u8]>) -> Self;
}

pub enum CipherId { Aes256Gcm, ChaCha20Poly1305 }   // FromStr / Display
pub enum KdfId    { Argon2id, Scrypt, Pbkdf2 }       // FromStr / Display

pub struct EncryptOptions {
    pub cipher: CipherId,
    pub kdf: KdfId,
    pub kdf_params: KdfParams,
    pub chunk_size: u32,
    pub filename: Option<String>,  // Some(name) ⇒ store in header (--name)
    pub armor: bool,
}
impl Default for EncryptOptions { /* secure defaults from §12 */ }

/// Progress callback payload; returning Break aborts the operation.
pub struct Progress { pub done: u64, pub total: Option<u64> }
type OnProgress = dyn FnMut(Progress) -> std::ops::ControlFlow<()>;

// ---- The four operations every front-end calls ----

pub fn encrypt<R: Read, W: Write>(
    input: R, output: W, secret: &Secret,
    opts: &EncryptOptions, on_progress: &mut OnProgress,
) -> Result<()>;

pub fn decrypt<R: Read, W: Write>(
    input: R, output: W, secret: &Secret,
    on_progress: &mut OnProgress,
) -> Result<()>;

pub fn inspect<R: Read>(input: R) -> Result<Header>;       // powers --info
pub fn verify<R: Read>(input: R, secret: &Secret,
                       on_progress: &mut OnProgress) -> Result<()>;  // powers --verify

// ---- Pure helpers shared by all front-ends (no I/O) ----

pub fn default_encrypt_output(input: &Path, armor: bool) -> PathBuf;
pub fn default_decrypt_output(input: &Path, header: &Header) -> PathBuf;
```

### 2.4 Data flow

**Encrypt.** A front-end gathers options (args / keys / widgets), acquires the
password in its own way, builds a `Secret` and `EncryptOptions`, opens the input
as a `Read` and the output as a `Write`, then calls
`core::encrypt(input, output, &secret, &opts, on_progress)`. The core derives the
key, writes the authenticated header, and STREAM-encrypts the body, invoking
`on_progress` per chunk. The front-end only renders progress and the result.

**Decrypt.** Same shape: the front-end opens streams and calls `core::decrypt`;
the core parses/validates the header, re-derives the key, and STREAM-decrypts,
verifying every tag.

**Info / verify.** `core::inspect(input)` returns header metadata for display;
`core::verify(input, &secret, on_progress)` decrypts-and-discards to confirm
integrity. Front-ends never parse the format themselves.

---

## 3. Threat model

**In scope.** An attacker who obtains the encrypted file (at rest, in transit,
in backups) must not learn the contents and must not be able to alter them
undetected. Offline password guessing must be made expensive via a memory-hard
KDF. Truncation, reordering, and bit-flips of the ciphertext must be detected.

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

All primitives come from the [RustCrypto](https://github.com/RustCrypto)
project (pure-Rust, widely reviewed). We do not roll our own crypto.

### 4.2 Key derivation

```
key (32 bytes) = KDF(secret, salt, params)
```

- `salt` is 16 random bytes, fresh per file, stored in the header.
- `secret` is the password bytes, or — if a keyfile is supplied —
  `password_bytes ‖ 0x00 ‖ keyfile_bytes` (keyfile is the second factor; either
  part may be empty but not both).
- `params` are stored in the header so decrypt re-derives the identical key.
- Because the salt is random per file, encrypting two files with the same
  password yields different keys — so AEAD keys are never reused across files.

**Keyfiles (v1).** A keyfile is read in full as raw bytes, combined with the
password as shown above, and zeroized after key derivation. It is a second
factor — an attacker needs *both* the password and the keyfile. Advisory flag
bit1 is set when a keyfile was used, so on decrypt a front-end can say "this file
needs a keyfile" rather than only reporting an auth failure when `-k` is missing.
Keyfile contents are never stored; losing the keyfile means the file cannot be
decrypted.

### 4.3 Streaming AEAD (the STREAM construction)

Large files are encrypted as a sequence of fixed-size chunks using the
**STREAM** construction (Hoang–Reyhanitabar–Rogaway–Vizár; the same scheme used
by Tink and `age`). The plaintext is split into chunks of `chunk_size` bytes
(default 64 KiB); the final chunk may be shorter (and may be empty).

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
- **Counter overflow:** refuse to encrypt a stream needing ≥ 2³² chunks
  (≈ 256 TiB at 64 KiB), which is far beyond practical inputs.

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
carries no secrets) but *is* authenticated via AAD.

### 5.2 Header fields

| Offset           | Size       | Field             | Notes                                            |
|------------------|------------|-------------------|--------------------------------------------------|
| 0                | 8          | `magic`           | ASCII `"SYMCRYPT"`                                |
| 8                | 1          | `version`         | `0x01`                                            |
| 9                | 1          | `cipher_id`       | `0x01` AES-256-GCM · `0x02` ChaCha20-Poly1305    |
| 10               | 1          | `kdf_id`          | `0x01` Argon2id · `0x02` scrypt · `0x03` PBKDF2   |
| 11               | 1          | `flags`           | bit0 filename-present · bit1 keyfile-used (hint)  |
| 12               | 4          | `kdf_p1`          | u32, meaning per KDF (§5.4)                        |
| 16               | 4          | `kdf_p2`          | u32                                               |
| 20               | 4          | `kdf_p3`          | u32                                               |
| 24               | 1          | `salt_len`        | bytes (default 16)                                |
| 25               | `salt_len` | `salt`            | random                                            |
| 25+`salt_len`    | 1          | `nonce_prefix_len`| bytes (default 7)                                 |
| 26+`salt_len`    | `npfx_len` | `nonce_prefix`    | random                                            |
| …                | 4          | `chunk_size`      | u32, plaintext bytes per chunk (default 65536)     |
| … (if flags bit0)| 2          | `name_len`        | u16, 1..=65535                                     |
| …                | `name_len` | `name`            | UTF-8 **basename only** (path components stripped) |

The "serialized header" used as AAD spans `magic` through the end of the
optional `name` field, i.e. everything before the body.

### 5.3 Identifiers & flags

- **cipher_id:** `0x01` = AES-256-GCM, `0x02` = ChaCha20-Poly1305.
  (`0x03` reserved for XChaCha20-Poly1305.)
- **kdf_id:** `0x01` = Argon2id, `0x02` = scrypt, `0x03` = PBKDF2-HMAC-SHA256.
- **flags:** bit0 (`0x01`) = original filename field present; bit1 (`0x02`) =
  keyfile was used (advisory, so decrypt can give a clearer error if the keyfile
  is missing). Bits 2–7 reserved, must be 0.

### 5.4 KDF parameter encoding

The three `kdf_p*` u32 fields are interpreted per `kdf_id`:

| KDF      | `kdf_p1`         | `kdf_p2`           | `kdf_p3`                                |
|----------|------------------|--------------------|-----------------------------------------|
| Argon2id | memory cost, KiB | time cost (passes) | parallelism (lanes)                     |
| scrypt   | log₂(N)          | r                  | p                                       |
| PBKDF2   | iterations       | 0 (reserved)       | 0 (reserved) — PRF fixed at HMAC-SHA256 |

### 5.5 Body / chunk layout

The body is a sequence of chunks. Each on-disk chunk is the AEAD output
`ciphertext ‖ tag` (16-byte tag appended). Non-final chunks carry exactly
`chunk_size` plaintext bytes (so `chunk_size + 16` on disk); the final chunk
carries 0..=`chunk_size` plaintext bytes.

The decryptor reads `chunk_size + 16` bytes at a time and buffers one chunk
ahead so it can set `final_flag` correctly: a chunk is final iff no bytes follow
it. An empty file produces exactly one final chunk of 16 bytes (tag only).

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

Decrypt auto-detects armor by the `-----BEGIN SYMCRYPT MESSAGE-----` line and
strips it before parsing the binary header. Armor is purely an outer transport
encoding; it is not represented in the binary header.

### 5.7 Versioning & forward compatibility

The `version` byte is checked first. An unknown `version`, `cipher_id`, or
`kdf_id`, or any reserved `flags` bit set, is rejected with a clear error (exit
code 4) — symcrypt never guesses at an unrecognized format. New ciphers or KDFs
take new IDs (with a version bump if the layout changes). Because every file
stores its own KDF parameters, files remain decryptable as the *defaults* for
new files evolve over time.

---

## 6. CLI specification

`symcrypt` is the command-line front-end: a thin wrapper that parses arguments,
resolves the password, opens streams, calls `symcrypt-core`, and maps results to
exit codes. It contains no crypto or format logic. The flags below are also the
shared vocabulary the TUI and GTK app expose through their own controls — cipher
and KDF names, defaults, and output-path rules all come from core helpers, so
all three front-ends stay identical.

### 6.1 Synopsis

```
symcrypt (-e|--encrypt | -d|--decrypt | -i|--info | --verify) <FILE> [options]
```

Exactly one mode is required. `<FILE>` of `-` means **stdin**.

### 6.2 Modes

| Mode             | Action                                                            |
|------------------|-------------------------------------------------------------------|
| `-e, --encrypt`  | Encrypt `<FILE>` → output.                                         |
| `-d, --decrypt`  | Decrypt `<FILE>` → output.                                         |
| `-i, --info`     | Print header metadata (cipher, KDF + params, version, flags, chunk size) without decrypting. No password needed. |
| `--verify`       | Decrypt in memory to verify integrity + password, write nothing. Exit 0 if valid. |

### 6.3 Options

| Flag                      | Applies to | Description                                                            |
|---------------------------|------------|-----------------------------------------------------------------------|
| `-o, --output <FILE>`     | enc/dec    | Output path; `-` = stdout. Defaults in §6.4.                            |
| `-p, --password <PW>`     | enc/dec/verify | Password inline (**discouraged**, see §11).                       |
| `--password-file <FILE>`  | enc/dec/verify | Read password from a file (trailing newline trimmed).             |
| `--password-env <VAR>`    | enc/dec/verify | Read password from an environment variable.                       |
| `-k, --keyfile <FILE>`    | enc/dec/verify | Keyfile as a second factor (combined with password).              |
| `-c, --cipher <NAME>`     | encrypt    | `aes-256-gcm` (default) or `chacha20-poly1305`.                        |
| `--kdf <NAME>`            | encrypt    | `argon2id` (default), `scrypt`, or `pbkdf2`.                           |
| `--kdf-memory <KiB>`      | encrypt    | Argon2/scrypt memory cost.                                             |
| `--kdf-time <N>`          | encrypt    | Argon2 passes / PBKDF2 iterations.                                     |
| `--kdf-parallelism <N>`   | encrypt    | Argon2/scrypt parallelism.                                             |
| `-a, --armor`             | encrypt    | ASCII-armored (base64) output. (Decrypt auto-detects.)                 |
| `--name`                  | encrypt    | Store the original filename in the header (off by default; sensitive).|
| `-f, --force`             | enc/dec    | Overwrite an existing output file (default: refuse).                   |
| `--remove`                | enc/dec    | Best-effort delete the input after success (default: keep).            |
| `--progress/--no-progress`| enc/dec    | Progress bar. Default: auto (on when stderr is a TTY).                  |
| `-v, --verbose`           | all        | More diagnostics on stderr.                                            |
| `-q, --quiet`             | all        | Suppress non-error output.                                             |
| `-V, --version`           | —          | Print version.                                                         |
| `-h, --help`              | —          | Print help.                                                            |

### 6.4 Password input precedence

Highest to lowest: `-p` → `--password-file` → `--password-env` → **interactive
prompt** (no echo). On **encrypt**, an interactive prompt asks twice and must
match. A keyfile (`-k`), if given, is always combined with whatever password
source is used; a keyfile alone (empty password) is permitted.

### 6.5 Output defaults

- **Encrypt, no `-o`:** `<input>.symcrypt` (`.symcrypt.asc` if `--armor`).
- **Decrypt, no `-o`:** use the stored filename if present; else strip a
  trailing `.symcrypt`/`.asc`; else append `.dec`. Refuse to overwrite unless
  `-f`.
- `-o -` writes to stdout (progress is then forced off; armor recommended for
  terminals).

### 6.6 Exit codes

| Code | Meaning                                          |
|------|--------------------------------------------------|
| 0    | Success                                          |
| 1    | General error (I/O, etc.)                        |
| 2    | Usage / argument error                           |
| 3    | Authentication failure (wrong password or tampered file) |
| 4    | Unsupported format or version                    |

These codes map directly from `symcrypt-core`'s `SymError` variants — the
front-end classifies nothing itself: `Auth` → 3; `UnsupportedVersion` /
`UnknownCipher` / `UnknownKdf` → 4; `Io` and the like → 1; argument/usage
problems caught before the core is called → 2. The mapping lives in
`symcrypt-common` and is shared by the CLI and TUI.

### 6.7 Examples

```sh
symcrypt -e report.pdf                      # → report.pdf.symcrypt (prompts for password)
symcrypt -e report.pdf -o - --armor > out   # armored to stdout
symcrypt -d report.pdf.symcrypt             # → report.pdf (or prompts/derives name)
symcrypt -i report.pdf.symcrypt             # show header metadata
echo -n secret | symcrypt -e - -o s.symcrypt --password-env PW
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

- **Mode tabs:** Encrypt / Decrypt / Info.
- **Input path** field (plain text entry for v1; a built-in file-browser popup
  is a post-v1 enhancement).
- **Output path** field, prefilled from `core::default_*_output` (§6.5);
  editable.
- **Password** field (masked, captured inside the event loop) plus a **confirm**
  field shown only in Encrypt mode, with a show/hide toggle.
- **Advanced** (collapsible): cipher and KDF selectors, `--name` and armor
  toggles, keyfile path, KDF cost knobs.
- **Progress gauge** + status line during an operation.
- **Footer** key hints (Tab/Shift-Tab to move, Enter to run, Esc to cancel/quit,
  `?` for help).

Optionally launch with a path (`symcrypt-tui <file>`) to prefill the input
field.

### 7.2 Concurrency & cancellation

The ratatui event loop stays on the main thread; the crypto call runs on a
worker thread. `Progress` updates are sent over an `mpsc` channel that the UI
drains each tick to redraw the gauge. Esc requests cancellation — the worker's
`on_progress` callback returns `ControlFlow::Break`, and the core aborts cleanly
and removes any partial output. The password lives in a zeroizing buffer moved
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
selected mode, input/output paths, password + confirm, advanced options (cipher,
KDF, cost knobs, keyfile, `--name`, armor), and run status/progress. UI events
become `Input` messages — `SetInputFile`, `PickOutput`, `SetPassword`,
`SetKeyfile`, `ToggleAdvanced`, `Run`, `Cancel` — handled in `update`, which
mutates the model and re-renders. The model never calls crypto directly; it
builds a `Secret` + `EncryptOptions` and invokes the core.

### 8.2 Widgets (libadwaita)

- `adw::ApplicationWindow` + `adw::ToolbarView` / `adw::HeaderBar`.
- `adw::ViewStack` + `ViewSwitcher` for the Encrypt / Decrypt / Info modes.
- `adw::EntryRow` for paths, each with a "browse" button opening
  `gtk::FileDialog`; output prefilled from `core::default_*_output` (§6.5).
- `adw::PasswordEntryRow` for the password (+ a confirm row in Encrypt mode) and
  a keyfile chooser row (`-k`).
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
handle (a shared `AtomicBool`) — the core's `on_progress` callback observes it
and returns `ControlFlow::Break`, and any partial output is removed. The password
is moved into the worker in a zeroizing buffer.

---

## 9. Dependencies

| Crate                          | Used in        | Purpose                                  |
|--------------------------------|----------------|------------------------------------------|
| `aes-gcm`                      | core           | AES-256-GCM AEAD                         |
| `chacha20poly1305`             | core           | ChaCha20-Poly1305 AEAD                   |
| `argon2`                       | core           | Argon2id KDF                             |
| `scrypt`                       | core           | scrypt KDF                               |
| `pbkdf2` + `sha2`              | core           | PBKDF2-HMAC-SHA256 KDF                   |
| `rand` / `getrandom`           | core           | CSPRNG for salt + nonce prefix          |
| `zeroize`                      | core           | Wipe key material from memory           |
| `base64`                       | core           | ASCII armor                             |
| `thiserror`                    | core, common   | Typed errors (`SymError`)                |
| `clap` (derive)                | cli, tui¹      | Argument parsing                        |
| `rpassword`                    | cli            | No-echo password prompt                 |
| `indicatif`                    | cli            | Progress bar                            |
| `ratatui`                      | tui            | Terminal UI widgets/layout              |
| `crossterm`                    | tui            | Terminal backend, raw mode, key events  |
| `relm4` + `relm4-components`   | gtk            | GUI framework over gtk4-rs (Elm arch.)²  |
| `anyhow`                       | cli, tui, gtk  | Error reporting / context               |

¹ The TUI uses `clap` only for an optional launch path; all interaction happens
in the UI, and password input is captured in its own masked field (not
`rpassword`).

² relm4 builds on gtk4-rs and pairs with libadwaita for styling;
`relm4-components` supplies file-dialog and worker helpers. `symcrypt-common`
depends only on `symcrypt-core` and the standard library (plus `thiserror`).

Exact versions are pinned at scaffolding time via `cargo add` (latest
compatible). RustCrypto crates are chosen for being pure-Rust and widely
reviewed.

---

## 10. Testing strategy

**Core unit tests**

- KDF determinism: same `(secret, salt, params)` → identical key; different
  params → different key.
- Header serialize → parse round-trip for every cipher/KDF/flag combination.
- STREAM nonce derivation: counter increments, final flag placement.
- Pure helpers: `default_encrypt_output` / `default_decrypt_output` and
  cipher/KDF `FromStr`/`Display` round-trips.

**Round-trip** (parameterized over sizes: 0, 1, `chunk_size−1`, `chunk_size`,
`chunk_size+1`, several MiB): encrypt then decrypt reproduces the input exactly,
for each cipher and KDF.

**Negative / tamper**

- Flip a byte in the body → auth failure.
- Flip a byte in the header (e.g. cipher_id) → auth failure (AAD).
- Wrong password / wrong-or-missing keyfile → auth failure.
- Truncate the last chunk → failure (final flag).
- Append a chunk → failure.
- Swap two chunks → failure (counter).

**Known-answer vectors:** commit fixed encrypted blobs to catch accidental
format changes across versions.

**Front-end tests.** Because the front-ends are thin, most coverage lives in
core. `symcrypt` gets CLI integration tests (`assert_cmd` + `tempfile`):
default-extension behavior, `-o -` / stdin, armor round-trip, `--info` output,
clobber refusal vs `-f`, exit codes, password via file/env. The `symcrypt-common`
glue (path-or-stdin opening, clobber check, secure remove, password-source
precedence, exit-code mapping) is unit-tested directly. `symcrypt-tui` gets light
tests of its non-UI glue; headless GTK testing is limited, so `symcrypt-gtk`
relies on manual verification plus the shared core/helper tests.

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
  (`--name`). Approximate plaintext size always leaks from ciphertext length;
  symcrypt does not pad. (Padding is a possible future option.)
- **Wrong password vs. corruption** are indistinguishable by design and reported
  as one condition.
- **Nonce reuse is structurally avoided:** a random per-file key (random salt) +
  per-chunk counter/final-flag nonce means no `(key, nonce)` pair repeats.
- **Header downgrade/tamper** is prevented by authenticating the full header as
  AAD.
- **Keyfiles** add a second factor but are read into process memory; they are
  zeroized after key derivation, and their loss is unrecoverable.
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
| Key length           | 32 bytes (256-bit)              |
| Tag length           | 16 bytes (128-bit)              |
| Output extension     | `.symcrypt` (`.symcrypt.asc` armored) |

---

## 13. Out of scope for v1

Asymmetric crypto, compression, plaintext padding / size hiding, key files
managed by a keyring/agent, multi-recipient files, and HKDF-based per-file
subkey separation (the random-salt-per-file design already prevents key reuse;
HKDF separation is a possible hardening later).

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

---

## 15. Implementation checklist

- [ ] Scaffold Cargo workspace + five crates; pin dependencies.
- [ ] `core`: error types (`SymError`, `Result`).
- [ ] `core`: `Secret` (password + keyfile) with zeroization.
- [ ] `core`: cipher dispatch (AES-256-GCM, ChaCha20-Poly1305).
- [ ] `core`: KDF dispatch (Argon2id, scrypt, PBKDF2) + param encoding + defaults.
- [ ] `core`: header serialize / parse (+ optional filename, flags, versioning).
- [ ] `core`: STREAM chunked encrypt/decrypt with progress + cancellation.
- [ ] `core`: ASCII armor wrap/unwrap + auto-detect.
- [ ] `core`: pure helpers — default output paths, cipher/KDF name parsing.
- [ ] `core`: unit, round-trip, tamper, and KAT tests.
- [ ] `symcrypt-common`: path-or-stdin I/O, clobber check, secure remove, password-source resolution, exit-code mapping (+ unit tests).
- [ ] `symcrypt` (cli): arg parsing (clap) and mode dispatch.
- [ ] `symcrypt` (cli): password resolution (flag/file/env/prompt + confirm) and keyfile.
- [ ] `symcrypt` (cli): encrypt/decrypt/info/verify; output defaults; clobber; remove.
- [ ] `symcrypt` (cli): progress bar; verbosity; exit codes.
- [ ] `symcrypt` (cli): integration tests.
- [ ] `symcrypt-tui`: ratatui/crossterm scaffold, event loop, form widgets.
- [ ] `symcrypt-tui`: masked password capture, advanced options, path prefill.
- [ ] `symcrypt-tui`: worker thread + progress gauge + cancellation.
- [ ] `symcrypt-gtk`: relm4 component (model/inputs/view), libadwaita widgets, `gtk::FileDialog`, drag-and-drop.
- [ ] `symcrypt-gtk`: relm4 Command/Worker for off-thread crypto; progress + cancellation; encrypt/decrypt/info flows.
- [ ] Docs: README, `--help` text, man pages; `.desktop` file for `symcrypt-gtk`.
- [ ] Packaging: `cargo install` for `symcrypt`/`symcrypt-tui`; build/run notes for GTK (needs GTK4 + libadwaita dev libs).
```

