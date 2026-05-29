# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Agent Instructions

- `docs/DESIGN.md` is the source of truth for how the application and library should work.  If the user requests a change that conflicts, update docs/DESIGN.md so it stays in sync.
- When changing the CLI, TUI, or GTK, update the relevant `IMPLEMENTATION_PLAN_0X_*.md` with the new behavior and API details before implementing it.  This keeps design and implementation aligned.
- Write exhaustive tests that cover base functionality and any edge cases, particularly for the core shared library.
- Use a Test Driven Development (TDD) approach: write failing tests before implementing features, then implement the code to make the tests pass.
- After changing code, format and lint it with `cargo fmt` and `cargo clippy`, ensuring no warnings remain.
- Commit after making changes.  Do not push.
- For containers, use Containerfile and compose.yaml and always build and run with rootless podman unless explicitly told otherwise.
- Commit messages should respect git conventions: The first line should be a subject line of 50 characters or less (though go up to 80 if needed), followed by a blank line, and then a body that provides more detail about the change.
- When asked to verify things in CI, us the Github CLI tool `gh`
- Multiple agents may be working in this repository simultaneously.  Serialize commits with a simple lock file at `commit.lock`.  Use three separate shell commands so failures at any step stay visible — do **not** bundle creation, commit, and removal into one chained command:
  1. **Acquire**: check the lock does not exist and create it.  Run `[ ! -e commit.lock ] && touch commit.lock` as its own command.  If the file already exists, another agent is mid-commit — wait briefly and retry rather than overwriting it.
  2. **Commit**: `git add <files> && git commit -m "<msg>"` as its own command.
  3. **Release**: `rm commit.lock` as its own command, only after the commit step has returned.
  Keeping these as three discrete commands minimizes the window where a created lock could be paired with a failed-but-unobserved commit, and lets you see at each step what state the working tree is in.  If you find a stale lock from a crashed prior agent (no commit in flight per `git status` / `git log`), remove it before proceeding.
- Ask before using git stash or git checkout as that could disrupt the in-progress work from another agent.

## Project status

`symcrypt` is in the **design phase — there is no Rust code yet.** The repository
currently holds only design/planning documents; the Cargo workspace and crates
described below do **not** exist on disk until the scaffolding step runs (see
`IMPLEMENTATION_PLAN_01_CORE.md`). Until then, treat the documents as the source
of truth and build against them.

- **`DESIGN.md`** — the authoritative specification: architecture, threat model,
  cryptographic design, the exact binary file format, CLI/TUI/GTK specs,
  dependencies, testing strategy, and defaults. Read it before implementing.
- **`IMPLEMENTATION_PLAN_01_CORE.md` … `_04_GTK.md`** — per-component checklists
  (core+common, CLI, TUI, GTK) defining build order. `01_CORE` comes first; the
  three front-ends all depend on it.
- `TODO.md` is git-ignored and maintained by humans — do not rely on it.

## What symcrypt is

A simple, safe symmetric file-encryption tool: three thin front-ends over one
shared core. Default cipher AES-256-GCM, default KDF Argon2id. Encrypted files
begin with a self-describing, authenticated header so they can be decrypted with
only the password/keyfile — no out-of-band parameters.

## Development commands

These become valid once the workspace is scaffolded (`IMPLEMENTATION_PLAN_01_CORE.md`);
**nothing compiles yet.** It is a standard multi-crate Cargo workspace.

| Task                       | Command                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------ |
| Build everything (debug)   | `cargo build`                                                                        |
| Build release              | `cargo build --release`                                                              |
| Run the CLI                | `cargo run -p symcrypt-cli -- -e file.txt` (package `symcrypt-cli`, binary `symcrypt`) |
| Run the TUI                | `cargo run -p symcrypt-tui`                                                           |
| Run the GTK app            | `cargo run -p symcrypt-gtk` (needs GTK4 + libadwaita dev libraries installed)        |
| Test the whole workspace   | `cargo test`                                                                          |
| Test one crate             | `cargo test -p symcrypt-core`                                                         |
| Run a single test by name  | `cargo test -p symcrypt-core round_trip` (substring; add `-- --exact` / `-- --nocapture`) |
| Lint                       | `cargo clippy --all-targets --all-features`                                          |
| Format                     | `cargo fmt` (check-only: `cargo fmt --check`)                                         |

Gotcha: the CLI lives in package **`symcrypt-cli`** but produces a binary named
**`symcrypt`** — use `-p symcrypt-cli` (or `--bin symcrypt`) to run it.

## Architecture

### One core, thin front-ends (the central rule)

A Cargo workspace of five crates. **`symcrypt-core` does all the work** — every
front-end is just a view that gathers input, hands it to the core, and renders
the result. This keeps the security-critical code small, testable, and identical
across front-ends.

The core's hard boundary — when implementing, never cross it:

> `symcrypt-core` never reads argv, never prompts, never touches the filesystem,
> never decides whether to overwrite, and never exits the process. It takes
> generic `Read`/`Write` and reports progress through an `on_progress` callback
> that returns `ControlFlow::Break` to cancel.

Everything medium-specific — parsing args, drawing widgets, acquiring the
password, opening files/stdin, the clobber decision, `--remove`, formatting
errors, exit codes — lives in the front-ends.

### Crates & dependency direction

| Crate            | Kind             | Responsibility                                                                                                                                |
| ---------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `symcrypt-core`  | lib              | All crypto, KDF, file format/header, STREAM chunking, ASCII armor, and pure helpers (default output paths, cipher/KDF name parsing). Holds the unit/round-trip/tamper/KAT tests. |
| `symcrypt-common`| lib              | Terminal glue shared by CLI + TUI: path-or-stdin I/O, clobber check, secure remove, password-source resolution, exit-code mapping. Depends only on core + std. |
| `symcrypt-cli`   | bin `symcrypt`   | clap arg parsing; password resolution; calls core.                                                                                            |
| `symcrypt-tui`   | bin `symcrypt-tui` | ratatui + crossterm interactive form. Reuses `symcrypt-common`.                                                                             |
| `symcrypt-gtk`   | bin `symcrypt-gtk` | relm4 (gtk4-rs) + libadwaita desktop app. **Does not use `symcrypt-common`** — relies on core + GTK-native file handling.                   |

Dependency direction: `common`/`cli`/`tui`/`gtk` → `core`; `cli`/`tui` → `common`.
`gtk` deliberately skips `common`.

### Core public API — four operations

Every front-end calls the same four functions: `encrypt`, `decrypt`, `inspect`
(powers `--info`, no password needed), and `verify` (decrypt-and-discard to
check integrity). They take a `Secret` (password + optional keyfile, zeroized on
drop) and `EncryptOptions`. Output paths come from the pure helpers
`default_encrypt_output` / `default_decrypt_output` so all front-ends agree.
(See DESIGN §2.3.)

### File format & crypto (DESIGN §4–§5)

- Container = authenticated **header** (plaintext, but bound as AEAD AAD) followed
  by a **STREAM**-chunked body; all integers big-endian. Magic `"SYMCRYPT"`,
  `version` byte checked first.
- The entire serialized header is the AAD for chunk 0, so cipher/KDF/params/
  filename cannot be tampered with (downgrade-resistant).
- **STREAM** construction (Hoang–Reyhanitabar–Rogaway–Vizár, as used by `age`/
  Tink): fixed-size chunks (default 64 KiB); 12-byte nonce = 7-byte random prefix
  ‖ u32 big-endian counter ‖ 1-byte final-flag. The counter prevents reordering;
  the final-flag prevents truncation/appending; a random per-file salt makes each
  file's key unique so no `(key, nonce)` pair ever repeats.
- Primitives are **RustCrypto crates only — do not roll your own crypto.**
  AES-256-GCM or ChaCha20-Poly1305; Argon2id / scrypt / PBKDF2-HMAC-SHA256; all
  key material wrapped in `zeroize`.
- A failed auth tag is reported as a single condition ("wrong password or
  corrupted/tampered file") — the two are intentionally indistinguishable.
- Unknown `version`/`cipher_id`/`kdf_id` or any reserved flag bit → reject with
  exit code 4; symcrypt never guesses at an unrecognized format.

### Front-end concurrency pattern (TUI & GTK)

Crypto runs off the UI thread (TUI: worker thread + `mpsc`; GTK: relm4
`Command`/`Worker`). `Progress` is streamed back to redraw a gauge; cancellation
flips a shared signal that the core's `on_progress` observes and returns
`ControlFlow::Break`, after which any partial output is removed. The password is
moved into the worker inside a zeroizing buffer.

## Conventions

- **Tests accompany every code change.** Most coverage lives in `symcrypt-core`
  (round-trip across sizes 0/1/chunk±1/large; tamper/truncate/reorder; KDF
  determinism; committed KAT vectors). The CLI gets `assert_cmd` integration
  tests; GTK relies on manual verification plus the shared core tests.
- **Security-affecting changes:** state the implications and confirm before
  implementing, and add tests that verify the integrity property.
- Exit codes: 0 ok · 1 general/IO · 2 usage · 3 auth failure · 4 unsupported
  format/version — mapped from `SymError` in `symcrypt-common`, never classified
  in the front-ends.
- Dependency versions are pinned via `cargo add` at scaffolding time.
