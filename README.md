# symcrypt

A simple, safe symmetric file-encryption tool: three thin front-ends over one
shared core. The default cipher is **AES-256-GCM** and the default KDF is
**Argon2id**. Encrypted files begin with a self-describing, authenticated header,
so they can be identified and decrypted with only the password (or keyfile) — no
out-of-band parameters.

> **Project status.** All three front-ends are implemented. The shared
> libraries — `symcrypt-core` (all crypto, file format, streaming, helpers) and
> `symcrypt-common` (terminal glue) — and the `symcrypt` command-line and
> `symcrypt-tui` terminal front-ends are implemented and tested. The
> `symcrypt-gtk` desktop app is implemented; it builds clean and its logic is
> unit-tested, but manual UI verification on a graphical session is still
> pending. [`DESIGN.md`](docs/DESIGN.md) is the authoritative specification.

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
| `symcrypt-tui`    | bin `symcrypt-tui` | ratatui + crossterm interactive form. Reuses `symcrypt-common`.                                 |
| `symcrypt-gtk`    | bin `symcrypt-gtk` | relm4 (gtk4-rs) + libadwaita desktop app.                                                       |

The core never reads argv, never prompts, never touches the filesystem on its
own, never decides whether to overwrite, and never exits the process. It takes
generic `Read`/`Write` and reports progress through a callback.

## Building from source

`symcrypt` builds with a standard Rust toolchain and Cargo. The `symcrypt` CLI
and `symcrypt-tui` terminal app are pure Rust and need no system libraries — only
the `symcrypt-gtk` desktop app needs the GTK4 + libadwaita development packages.

### 1. Install the Rust toolchain

symcrypt targets a **minimum supported Rust version (MSRV) of 1.94** (edition
2021); no `rust-toolchain.toml` is pinned, so current stable works. The easiest
way to get it is [`rustup`](https://rustup.rs):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"          # add ~/.cargo/bin to PATH (or restart your shell)
rustc --version               # confirm it reports 1.94 or newer
```

A Rust toolchain from your distribution's packages works too, as long as it is
at least 1.94.

### 2. Install system dependencies (GTK app only)

Skip this step unless you are building `symcrypt-gtk`. The desktop app links
against **GTK4** and **libadwaita**, so it needs their development packages plus
a C compiler and `pkg-config` to locate them:

- **Fedora / RHEL:** `sudo dnf install gtk4-devel libadwaita-devel gcc pkg-config`
- **Debian / Ubuntu:** `sudo apt install libgtk-4-dev libadwaita-1-dev build-essential pkg-config`
- **Arch Linux:** `sudo pacman -S gtk4 libadwaita base-devel`
- **macOS (Homebrew):** `brew install gtk4 libadwaita pkg-config`

On macOS you also need the Xcode Command Line Tools (`xcode-select --install`)
for the C compiler and linker.

### 3. Get the source

```sh
git clone https://github.com/FreedomBen/symcrypt.git
cd symcrypt
```

### 4. Build

```sh
cargo build                   # debug build of the whole workspace
cargo build --release         # optimized build → target/release/
```

Build a single front-end with `-p`. Note the CLI package is **`symcrypt-cli`**
but its binary is named **`symcrypt`**:

```sh
cargo build -p symcrypt-cli   # CLI only      (binary: symcrypt)
cargo build -p symcrypt-tui   # terminal app only
cargo build -p symcrypt-gtk   # desktop app only (needs the deps from step 2)
```

### 5. Run the tests

Confirm the build with the workspace test suite:

```sh
cargo test                               # the whole workspace
cargo test -p symcrypt-core              # one crate
cargo test -p symcrypt-core round_trip   # a single test by name (substring match)
```

### 6. Build, test, and lint commands

| Task                      | Command                                       |
| ------------------------- | --------------------------------------------- |
| Build everything (debug)  | `cargo build`                                 |
| Build release             | `cargo build --release`                       |
| Test the whole workspace  | `cargo test`                                  |
| Test one crate            | `cargo test -p symcrypt-core`                 |
| Run a single test by name | `cargo test -p symcrypt-core round_trip`      |
| Lint                      | `cargo clippy --all-targets --all-features`   |
| Format                    | `cargo fmt` (check only: `cargo fmt --check`) |

A `Makefile` wraps these for convenience — `make build`, `make release`,
`make test`, `make lint`, `make fmt`, and `make ci` (format-check + lint +
test). Run `make help` to list every target; it is a thin wrapper over Cargo, so
the commands above work just as well directly.

### 7. Install the binaries

Install any front-end into Cargo's binary directory (`~/.cargo/bin`, which
`rustup` puts on your `PATH`):

```sh
cargo install --path crates/symcrypt-cli    # the `symcrypt` CLI
cargo install --path crates/symcrypt-tui    # the terminal app
cargo install --path crates/symcrypt-gtk    # the desktop app (needs step 2)
```

Or use the Makefile to install a binary **and** its packaged extras — a man page
for the CLI/TUI, or the `.desktop` entry, icon, and AppStream metainfo for GTK —
under a prefix (default `/usr/local`; override with `PREFIX=`, stage with
`DESTDIR=`):

```sh
make install                       # symcrypt CLI + man page
make install-tui                   # symcrypt-tui + man page
make install-gtk                   # symcrypt-gtk + .desktop + icon + metainfo
make install PREFIX="$HOME/.local"
```

The matching `make uninstall`, `make uninstall-tui`, and `make uninstall-gtk`
targets remove them again. The per-front-end usage sections below cover each
binary in more detail.

## Command-line usage

Install the `symcrypt` binary with Cargo:

```sh
cargo install --path crates/symcrypt-cli
```

Or install the binary **and** its man page under a prefix (default
`/usr/local`, override with `PREFIX=`, stage with `DESTDIR=`):

```sh
make install                      # → /usr/local/bin/symcrypt + man page
make install PREFIX="$HOME/.local"
make uninstall                    # remove both again
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

## Terminal usage

`symcrypt-tui` is a full-screen, keyboard-driven terminal front-end over the same
core as the CLI, so the file format, cryptography, and defaults are identical. It
presents one form with four mode tabs — Encrypt, Decrypt, Info, and Verify — and
runs each operation off the UI thread with a live progress gauge.

Install the `symcrypt-tui` binary with Cargo, or install the binary **and** its
man page under a prefix with the Makefile:

```sh
cargo install --path crates/symcrypt-tui
make install-tui                       # → /usr/local/bin/symcrypt-tui + man page
make install-tui PREFIX="$HOME/.local"
```

Launch it (optionally prefilling the input-path field with a file):

```sh
symcrypt-tui                 # start with an empty form
symcrypt-tui report.pdf      # prefill the input path
```

Switch modes with the `←`/`→` keys while the tabs are focused; each mode shows
only the fields it needs (Encrypt adds a confirm field; Info reads no password).
The output path is prefilled automatically — `input.symcrypt` (or `.symcrypt.asc`
with armor) on encrypt, and the stored/derived name on decrypt — but a manual
edit is never overwritten. An **Advanced** pane (collapsible) holds the
Encrypt-only cipher and KDF selectors with the selected KDF's cost knobs, the
`--name` and `--armor` switches, remove-input-after-success and overwrite (`-f`)
switches, and a keyfile field for Encrypt/Decrypt/Verify. As in the CLI, an
authentication failure is reported as "wrong password or corrupted/tampered
file".

### Key bindings

| Key                 | Action                                                               |
| ------------------- | -------------------------------------------------------------------- |
| `Tab` / `Shift-Tab` | Move focus between fields                                             |
| `←` / `→`           | Switch the mode tab (when tabs are focused) or change a selector      |
| `Space`             | Toggle the focused checkbox / expander                               |
| `Enter`             | Run the selected operation                                           |
| `Esc`               | Cancel a running operation, or quit when idle                        |
| `Ctrl-C`            | Quit (restores the terminal first; exits 130 if it interrupts a run) |
| `?`                 | Toggle the help overlay                                              |

### Differences from the CLI

- **Filesystem paths only.** Every path field rejects a literal `-`; the TUI owns
  stdin and stdout, so stdin/stdout streaming stays a CLI-only feature.
- **No `--password-file` / `--password-env`.** The password is typed into the
  masked field, captured inside the TUI's own event loop under raw mode.

## Desktop (GTK) usage

`symcrypt-gtk` is a libadwaita desktop front-end (relm4 + gtk4-rs) over the same
core as the CLI and TUI, so the file format, cryptography, and defaults are
identical. It is implemented; it builds clean and its pure logic is unit-tested,
but manual UI verification on a graphical session is still pending.

Building it requires the **GTK4 + libadwaita** development libraries — Fedora:
`gtk4-devel libadwaita-devel`; Debian/Ubuntu: `libgtk-4-dev libadwaita-1-dev`.

The window presents a `ViewSwitcher` over four modes — Encrypt, Decrypt, Info,
and Verify — sharing one form whose rows show and hide per mode. It offers:

- input and output file pickers via `gtk::FileDialog`, plus drag-and-drop of an
  input file onto the window;
- output prefill — `input.symcrypt` (or `.symcrypt.asc` with armor) on encrypt,
  and the stored/derived name on decrypt — that never clobbers a manual edit;
- password and confirm (Encrypt) entries, a keyfile-only toggle, and a keyfile
  chooser;
- an **Advanced** expander holding the Encrypt-only cipher and KDF selectors,
  the selected KDF's cost knobs, and the `--name`, armor, remove-input, and
  overwrite switches;
- crypto on a background worker with a live progress gauge and a Cancel button,
  an overwrite-confirm dialog, and an Info mode that inspects the header inline
  with no password.

As in the CLI and TUI, an authentication failure is reported as the single
condition "wrong password or corrupted/tampered file".

Run it from the workspace, or install the binary together with its `.desktop`
entry, icon, and AppStream metainfo:

```sh
cargo run -p symcrypt-gtk                 # run from the source tree
make run-gtk                              # same, via the Makefile

cargo install --path crates/symcrypt-gtk  # binary only
make install-gtk                          # binary + .desktop + icon + metainfo
make install-gtk PREFIX="$HOME/.local"
make uninstall-gtk                        # remove them again
```

### Differences from the CLI

- **Filesystem paths only.** The path fields are file-chooser backed and do not
  accept a literal `-`, so stdin/stdout streaming stays a CLI-only feature.
- **No `--password-file` / `--password-env`.** The password is typed into the
  masked entry; those non-interactive sources remain CLI-only.

Flatpak packaging (sandboxed, with the `.desktop`/icon/metainfo already
provided) is a possible future distribution path.

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
