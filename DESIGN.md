# symcrypt — Design

**Status:** Design phase. No implementation yet.
**Target stack:** Rust 1.94+, [gtk4-rs](https://gtk-rs.org/) (GTK 4.20).
**Last updated:** 2026-05-29

`symcrypt` is a simple, safe symmetric file encryption tool. It ships as a CLI
(`symcrypt`) and a GTK4 desktop app (`symcrypt-gui`), both built on a shared
core library. The default cipher is AES-256-GCM. Encrypted files begin with a
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
7. [GTK application design](#7-gtk-application-design)
8. [Dependencies](#8-dependencies)
9. [Testing strategy](#9-testing-strategy)
10. [Security considerations](#10-security-considerations)
11. [Defaults summary](#11-defaults-summary)
12. [Out of scope for v1](#12-out-of-scope-for-v1)
13. [Open decisions](#13-open-decisions)
14. [Implementation checklist](#14-implementation-checklist)

---

## 1. Goals & non-goals

### Goals

- **Confidentiality + integrity** of file contents at rest, using authenticated
  encryption (AEAD). Any tampering or corruption is detected on decrypt.
- **Self-describing files**: a magic marker and a versioned, authenticated
  header carry everything needed to decrypt (cipher, KDF, KDF params, salt,
  nonce, chunk size) — only the secret (password/keyfile) is external.
- **Streaming**: encrypt/decrypt files of arbitrary size with bounded memory.
- **Simple, scriptable CLI** plus an approachable GTK GUI sharing one core.
- **Strong, modern defaults** that a non-expert gets for free, with knobs for
  experts.

### Non-goals (v1)

- Public-key / asymmetric encryption, signing, or key exchange.
- Hiding *that* a file is a symcrypt file (the magic is intentionally
  identifiable) or hiding the approximate plaintext size.
- Deniable encryption, hidden volumes, or secure erasure guarantees on modern
  storage (see [§10](#10-security-considerations)).
- Compression (can be added later; compressing before encrypting has known
  side-channel caveats, so it stays off by default and out of v1).

---

## 2. Architecture

A Cargo **workspace** with three crates: a pure logic core plus two thin
front-ends. The core performs no UI and no policy decisions (e.g. clobber
prompts); it exposes streaming encrypt/decrypt over `Read`/`Write` and a header
type. This keeps the security-critical code small, front-end-agnostic, and
unit-testable.

```
symcrypt/
├── Cargo.toml                 # workspace manifest
├── DESIGN.md
├── README.md                  # (later)
└── crates/
    ├── symcrypt-core/         # library: format, crypto, KDF, streaming
    │   ├── src/
    │   │   ├── lib.rs
    │   │   ├── error.rs        # SymError, Result
    │   │   ├── header.rs       # serialize/parse, IDs, flags, params
    │   │   ├── kdf.rs          # Argon2id / scrypt / PBKDF2 dispatch
    │   │   ├── cipher.rs       # AEAD dispatch (AES-256-GCM, ChaCha20-Poly1305)
    │   │   ├── stream.rs       # STREAM chunked encrypt/decrypt
    │   │   └── armor.rs        # base64 ASCII-armor wrap/unwrap
    │   └── tests/              # round-trip, tamper, KAT vectors
    ├── symcrypt-cli/           # binary `symcrypt`
    │   └── src/main.rs
    └── symcrypt-gui/           # binary `symcrypt-gui`
        └── src/main.rs
```

**Data flow (encrypt):** front-end resolves the password → calls
`core::encrypt(reader, writer, &Options)` → core derives key via KDF, writes the
authenticated header, then STREAM-encrypts the body chunk by chunk, reporting
progress via a callback.

**Data flow (decrypt):** front-end → `core::decrypt(reader, writer, secret)` →
core parses + validates the header, re-derives the key, STREAM-decrypts,
verifying each chunk's tag.

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

| KDF      | `kdf_p1`         | `kdf_p2` | `kdf_p3`      |
|----------|------------------|----------|---------------|
| Argon2id | memory cost, KiB | time cost (passes) | parallelism (lanes) |
| scrypt   | log₂(N)          | r        | p             |
| PBKDF2   | iterations       | 0 (reserved) | 0 (reserved) — PRF fixed at HMAC-SHA256 |

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

---

## 6. CLI specification

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
| `-p, --password <PW>`     | enc/dec/verify | Password inline (**discouraged**, see §10).                       |
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

## 7. GTK application design

**Toolkit:** gtk4-rs (the `gtk4` crate). [libadwaita](https://gnome.pages.gitlab.gnome.org/libadwaita/)
is optional for modern GNOME styling; v1 may use plain GTK4 to minimize
dependencies. The GUI links the same `symcrypt-core`.

### 7.1 Window layout

- **Mode switch:** Encrypt / Decrypt (a `ViewSwitcher`/toggle).
- **Input file:** chooser button + drag-and-drop target on the window.
- **Output file:** chooser, prefilled with the default name (§6.5); editable.
- **Password:** masked `PasswordEntry` with show/hide; in Encrypt mode a second
  "confirm" field that must match before the action enables.
- **Advanced (collapsible):** cipher dropdown, KDF dropdown + cost knobs,
  "store original filename" and "armor output" checkboxes.
- **Action button:** "Encrypt" / "Decrypt".
- **Progress bar + status label**; non-blocking error dialogs.
- **Info action:** pick an encrypted file → show header metadata in a dialog.

### 7.2 Threading model

Crypto runs **off the main thread** (`gio::spawn_blocking` or a `std::thread`),
streaming through the core. Progress and completion are marshaled back to the UI
via a `glib` channel / `MainContext` so the window stays responsive and
cancelable. The password is moved into the worker and zeroized when done.

---

## 8. Dependencies

| Crate                         | Used in | Purpose                                  |
|-------------------------------|---------|------------------------------------------|
| `aes-gcm`                     | core    | AES-256-GCM AEAD                         |
| `chacha20poly1305`            | core    | ChaCha20-Poly1305 AEAD                   |
| `argon2`                      | core    | Argon2id KDF                             |
| `scrypt`                      | core    | scrypt KDF                               |
| `pbkdf2` + `sha2`             | core    | PBKDF2-HMAC-SHA256 KDF                   |
| `rand` / `getrandom`          | core    | CSPRNG for salt + nonce prefix          |
| `zeroize`                     | core    | Wipe key material from memory           |
| `base64`                      | core    | ASCII armor                             |
| `thiserror`                   | core    | Typed errors                            |
| `clap` (derive)               | cli     | Argument parsing                        |
| `rpassword`                   | cli     | No-echo password prompt                 |
| `anyhow`                      | cli     | Error reporting / context               |
| `indicatif`                   | cli     | Progress bar                            |
| `gtk4` (+ optional `libadwaita`) | gui  | GUI toolkit                             |

Exact versions are pinned at scaffolding time via `cargo add` (latest
compatible). RustCrypto crates are chosen for being pure-Rust and widely
reviewed.

---

## 9. Testing strategy

**Core unit tests**

- KDF determinism: same `(secret, salt, params)` → identical key; different
  params → different key.
- Header serialize → parse round-trip for every cipher/KDF/flag combination.
- STREAM nonce derivation: counter increments, final flag placement.

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

**CLI integration** (`assert_cmd` + `tempfile`): default-extension behavior,
`-o -` / stdin, armor round-trip, `--info` output, clobber refusal vs `-f`,
exit codes, password via file/env.

Per repo convention, tests accompany every code change.

---

## 10. Security considerations

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
- **Memory hygiene:** keys and derived buffers are wrapped in `zeroize` types and
  wiped on drop. We cannot prevent the OS from paging secrets to swap.
- **KDF defaults** target meaningful offline-guessing cost on commodity hardware
  while staying usable; experts can raise them, and the chosen values are stored
  per file so old files still decrypt.

Per repo policy, these implications are flagged for confirmation before
implementation begins, and tests in §9 verify each integrity property.

---

## 11. Defaults summary

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

## 12. Out of scope for v1

Asymmetric crypto, compression, plaintext padding / size hiding, key files
managed by a keyring/agent, multi-recipient files, and HKDF-based per-file
subkey separation (the random-salt-per-file design already prevents key reuse;
HKDF separation is a possible hardening later).

---

## 13. Open decisions

These are decided with sensible defaults above but flagged for confirmation:

- [ ] Keyfile support in v1, or defer to v1.1? (Currently specified, marked
      advisory via flag bit1.)
- [ ] GUI: plain GTK4 vs. libadwaita for v1 styling.
- [ ] Default Argon2id parallelism (1 chosen for determinism/portability).
- [ ] Whether `--info` and `--verify` ship in v1 or follow encrypt/decrypt.

---

## 14. Implementation checklist

- [ ] Scaffold Cargo workspace + three crates; pin dependencies.
- [ ] `core`: error types (`SymError`, `Result`).
- [ ] `core`: cipher dispatch (AES-256-GCM, ChaCha20-Poly1305).
- [ ] `core`: KDF dispatch (Argon2id, scrypt, PBKDF2) + param encoding.
- [ ] `core`: header serialize / parse (+ optional filename, flags).
- [ ] `core`: STREAM chunked encrypt/decrypt with progress callback.
- [ ] `core`: ASCII armor wrap/unwrap + auto-detect.
- [ ] `core`: unit, round-trip, tamper, and KAT tests.
- [ ] `cli`: arg parsing (clap) and mode dispatch.
- [ ] `cli`: password resolution (flag/file/env/prompt + confirm) and keyfile.
- [ ] `cli`: encrypt / decrypt / info / verify; output defaults; clobber; remove.
- [ ] `cli`: progress bar; verbosity; exit codes.
- [ ] `cli`: integration tests.
- [ ] `gui`: window, widgets, file chooser, drag-and-drop.
- [ ] `gui`: worker thread + progress marshaling; encrypt/decrypt/info flows.
- [ ] Docs: README, `--help` text, man page; `.desktop` file for the GUI.
- [ ] Packaging: `cargo install` for the CLI; build/run notes for the GUI.
