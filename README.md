# symcrypt

A simple, safe symmetric file-encryption tool: three thin front-ends over one
shared core. The default cipher is **AES-256-GCM** and the default KDF is
**Argon2id**. Encrypted files begin with a self-describing, authenticated header,
so they can be identified and decrypted with only the password (or keyfile) — no
out-of-band parameters.

> **Project status.** The shared libraries — `symcrypt-core` (all crypto, file
> format, streaming, helpers) and `symcrypt-common` (terminal glue) — and the
> `symcrypt` command-line front-end are implemented and tested. The
> `symcrypt-tui` and `symcrypt-gtk` binaries remain scaffold stubs; they are
> built out in `docs/IMPLEMENTATION_PLAN_03_TUI.md` and `_04_GTK.md`.
> [`DESIGN.md`](docs/DESIGN.md) is the authoritative specification.

## Highlights

- **Confidentiality + integrity** via authenticated encryption (AEAD). Any
  tampering, truncation, reordering, or corruption is detected on decrypt.
- **Self-describing files**: a versioned, authenticated header carries the
  cipher, KDF, KDF parameters, salt, nonce prefix, and chunk size. Only the
  secret is external.
- **Streaming** with bounded memory using the STREAM construction
  (Hoang–Reyhanitabar–Rogaway–Vizár, as used by `age` and Tink).
- **Strong, modern defaults** a non-expert gets for free, with expert knobs.
- **Pure-Rust crypto** from the [RustCrypto](https://github.com/RustCrypto)
  project — no hand-rolled primitives.

## Architecture

A Cargo workspace of five crates. **`symcrypt-core` does all the work**; each
front-end is a thin view that gathers input, hands it to the core, and renders
the result.

| Crate             | Kind               | Responsibility                                                                                 |
| ----------------- | ------------------ | ---------------------------------------------------------------------------------------------- |
| `symcrypt-core`   | lib                | All crypto, KDF, file format/header, STREAM chunking, ASCII armor, and pure helpers.            |
| `symcrypt-common` | lib                | Terminal glue shared by the CLI + TUI: path-or-stdin I/O, clobber check, secure remove, password resolution, exit-code mapping. |
| `symcrypt-cli`    | bin `symcrypt`     | clap argument parsing; password resolution; calls the core.                                     |
| `symcrypt-tui`    | bin `symcrypt-tui` | ratatui + crossterm interactive form. *(stub)*                                                  |
| `symcrypt-gtk`    | bin `symcrypt-gtk` | relm4 (gtk4-rs) + libadwaita desktop app. *(stub)*                                              |

The core never reads argv, never prompts, never touches the filesystem on its
own, never decides whether to overwrite, and never exits the process. It takes
generic `Read`/`Write` and reports progress through a callback.

## Requirements

- **Rust 1.94+** (Cargo workspace).
- The GTK app additionally needs **GTK4 + libadwaita** development libraries
  (only relevant once `symcrypt-gtk` is implemented).

## Build and test

| Task                      | Command                                            |
| ------------------------- | -------------------------------------------------- |
| Build everything (debug)  | `cargo build`                                      |
| Build release             | `cargo build --release`                            |
| Test the whole workspace  | `cargo test`                                       |
| Test one crate            | `cargo test -p symcrypt-core`                      |
| Run a single test by name | `cargo test -p symcrypt-core round_trip`           |
| Lint                      | `cargo clippy --all-targets --all-features`        |
| Format                    | `cargo fmt` (check only: `cargo fmt --check`)      |

The CLI lives in package **`symcrypt-cli`** but produces a binary named
**`symcrypt`** — use `-p symcrypt-cli` (or `--bin symcrypt`) to run it. The
`symcrypt-tui` and `symcrypt-gtk` binaries currently print a "not yet
implemented" message and exit `2`.

## Command-line usage

Install the `symcrypt` binary with Cargo:

```sh
cargo install --path crates/symcrypt-cli
```

`symcrypt` takes exactly one mode (`-e`/`-d`/`-i`/`--verify`) and one `<FILE>`
(`-` means stdin). With no password source it prompts interactively (no echo);
non-interactively, supply `-p`, `--password-file`, `--password-env`, and/or a
keyfile (`-k`). See `symcrypt --help` for every option and
[`DESIGN.md`](docs/DESIGN.md) §6 for the full specification.

```sh
symcrypt -e report.pdf                      # → report.pdf.symcrypt (prompts for a password)
symcrypt -e report.pdf -o - --armor > out   # armored, written to stdout
symcrypt -d report.pdf.symcrypt             # → report.pdf (or the stored/derived name)
symcrypt -i report.pdf.symcrypt             # print unauthenticated header metadata
symcrypt --verify report.pdf.symcrypt       # check integrity + password, writing nothing
printf 'secret' | PW=passphrase symcrypt -e - -o s.symcrypt --password-env PW
symcrypt -e vault.tar -k usb.key --no-password   # keyfile-only
symcrypt -e big.iso -c chacha20-poly1305 --remove
```

Existing output files are refused unless `-f/--force` is given; on Unix the
output is created with mode `0600`. Exit codes: `0` success, `1` I/O or general
error, `2` usage error, `3` authentication failure, `4` unsupported or invalid
format, `130` canceled.

## Library usage

`symcrypt-core` exposes four operations — `encrypt`, `decrypt`, `inspect`
(unauthenticated header metadata, no secret needed), and `verify`
(decrypt-and-discard) — each over generic `Read`/`Write`:

```rust
use std::ops::ControlFlow;
use symcrypt_core::{decrypt, encrypt, EncryptOptions, Progress, Secret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Password and/or keyfile material, zeroized on drop.
    let secret = Secret::new(b"correct horse battery staple", None)?;
    // Secure defaults: AES-256-GCM + Argon2id (see DESIGN §12).
    let opts = EncryptOptions::default();

    let plaintext = b"top secret";
    let mut ciphertext = Vec::new();
    let mut on_progress = |_: Progress| ControlFlow::Continue(());
    encrypt(
        &plaintext[..],
        &mut ciphertext,
        &secret,
        &opts,
        Some(plaintext.len() as u64),
        &mut on_progress,
    )?;

    let mut recovered = Vec::new();
    let mut on_progress = |_: Progress| ControlFlow::Continue(());
    decrypt(&ciphertext[..], &mut recovered, &secret, None, &mut on_progress)?;
    assert_eq!(recovered, plaintext);
    Ok(())
}
```

A failed authentication tag is reported as a single condition — *wrong password
or corrupted/tampered file* — because the two are cryptographically
indistinguishable.

## File format and cryptography

A container is an authenticated **header** (plaintext, but bound as AEAD
associated data) followed by a **STREAM**-chunked body; all integers are
big-endian. The entire serialized header is the associated data for chunk 0, so
the cipher, KDF, parameters, and optional filename cannot be tampered with
(downgrade-resistant). With `--armor`, the binary container is base64-wrapped in
PEM-style `-----BEGIN/END SYMCRYPT MESSAGE-----` markers.

- **Ciphers:** AES-256-GCM (default) or ChaCha20-Poly1305.
- **KDFs:** Argon2id (default), scrypt, or PBKDF2-HMAC-SHA256.
- **Key/tag/nonce:** 256-bit key, 128-bit tag, 96-bit per-chunk nonce
  (7-byte random prefix ‖ u32 counter ‖ final-flag).

The full wire format, threat model, and parameter ranges are specified in
[`DESIGN.md`](docs/DESIGN.md) (§4–§5).

## Security notes

- Secure deletion is **best-effort** only; `--remove` does a plain delete and
  cannot guarantee erasure on SSDs/journaling/CoW filesystems.
- Storing the original filename is opt-in (`--name`) and stores only a
  well-formed basename. Approximate plaintext size always leaks from ciphertext
  length.
- Passing a password inline leaks it to process listings and shell history;
  prefer prompting, `--password-file`, or `--password-env`.
- Key material is wrapped in `zeroize` and wiped on drop, but secrets paged to
  swap cannot be controlled.

See [`DESIGN.md`](docs/DESIGN.md) §3 and §11 for the full threat model and security
considerations.

## Documentation

- [`DESIGN.md`](docs/DESIGN.md) — the authoritative specification (architecture,
  threat model, crypto design, exact file format, CLI/TUI/GTK specs, defaults).
- `docs/IMPLEMENTATION_PLAN_01_CORE.md` … `_04_GTK.md` — per-component build plans.

## License

Licensed under either of MIT or Apache-2.0 at your option. (License texts are
not yet committed to the repository.)
