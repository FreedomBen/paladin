# paladin — Implementation plan 02: CLI (`paladin`)

**Status:** Ready for implementation. The two crates this front-end builds on —
`paladin-core` and `paladin-common` — are complete (see
[`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)), so the design
is stable enough to expand this from a checklist stub into ordered steps.
**Last updated:** 2026-05-30.

**Scope.** The `paladin` binary (package `paladin-cli`) — a thin front-end that
parses arguments, resolves the password, opens streams, calls `paladin-core`,
and maps results to exit codes ([DESIGN §6](DESIGN.md#6-cli-specification)). It
holds **no crypto or format logic**: cipher/KDF names, defaults, output-path
rules, validation caps, and exit-code mapping all come from the shared crates.

**Depends on:** [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)
— `paladin-core` (the four operations + pure helpers) and the `paladin-common`
terminal glue.
**Sibling plans:** [`IMPLEMENTATION_PLAN_03_TUI.md`](IMPLEMENTATION_PLAN_03_TUI.md),
[`IMPLEMENTATION_PLAN_04_GTK.md`](IMPLEMENTATION_PLAN_04_GTK.md).

---

## 1. What already exists (the CLI only wires these together)

The CLI never re-implements any of the following; it gathers input and calls
into these APIs. Verified against the current source.

### From `paladin-core`

| Item                                              | Used by the CLI for                                            |
| ------------------------------------------------- | -------------------------------------------------------------- |
| `encrypt` / `decrypt` / `inspect` / `verify`      | The four modes (`-e` / `-d` / `-i` / `--verify`).              |
| `Secret::new(password, keyfile)`                  | Building the zeroized secret from resolved bytes.             |
| `EncryptOptions` + `Default`                      | Encrypt knobs; secure defaults from [DESIGN §12](DESIGN.md#12-defaults-summary). |
| `CipherId` (`FromStr`/`Display`)                  | Parsing `-c/--cipher`; display in `--info`.                   |
| `KdfId` (`FromStr`/`Display`)                     | Parsing `--kdf`; KDF name in `--info`.                       |
| `KdfParams` + `KdfParams::default_for(KdfId)`     | Per-KDF cost-knob assembly: start from the KDF default, override supplied knobs. `KdfParams` has no `FromStr`/`Display`; `--info` formats it directly (§7). |
| `Header`, `NameStatus`                            | `--info` field values and `name_status`.                     |
| `Progress`, `OnProgress`                          | Progress-callback payload and signature.                     |
| `default_encrypt_output` / `default_decrypt_output` | Default `-o` derivation (§6.5); decrypt needs a parsed `Header`. |
| `KEYFILE_MAX_BYTES`                               | (Already enforced inside `read_keyfile`.)                    |
| `SymError`                                         | Mapped to exit codes via `paladin-common` (never reclassified). |

### From `paladin-common`

| Item                                                       | Used by the CLI for                                              |
| ---------------------------------------------------------- | ---------------------------------------------------------------- |
| `password_source_from_flags(inline, file, env, no_password)` | Exclusivity check; `Ok(None)` ⇒ prompt interactively.          |
| `resolve_password(&PasswordSource)`                        | Non-interactive password bytes (handles empty/unset/UTF-8/caps). |
| `read_keyfile(path)`                                       | Keyfile bytes (existing regular file, 1 B..=1 MiB, non-empty).  |
| `open_input(path)` / `is_stdio(path)` / `require_regular_file(path)` | Input stream + `-`/regular-file rules.                  |
| `open_output(target, force, input)` → `OutputSink`         | Clobber + same-file + regular-file checks; stdout vs temp file.  |
| `OutputSink::as_write()` / `OutputSink::commit()`          | Hand a `&mut dyn Write` to the core; finalize on success.        |
| `best_effort_remove(path)`                                 | `--remove` after success.                                       |
| `is_same_file(a, b)`                                       | (Already used inside `open_output`.)                            |
| `exit_code(&SymError)` + `AppError::exit_code()` + `EXIT_*` | The single exit-code mapping.                                  |
| `AppError` / `AppResult` / `AppError::usage(msg)`          | The CLI's error currency before/around core calls.              |

> **Cleanup-on-failure is automatic.** `OutputSink::File` holds a
> `NamedTempFile`; if the CLI returns early (error, auth failure, cancellation)
> without calling `commit()`, the temp file is removed on drop. The CLI must
> simply *not* `commit()` on a failed/canceled core call, and must skip
> `--remove`.

---

## 2. Proposed module layout (`crates/paladin-cli/src`)

Split the stub `main.rs` into small, testable modules. Pure logic (arg
validation, options assembly, `--info` formatting) is unit-testable without
spawning a process; end-to-end behavior is covered by `assert_cmd`.

```
crates/paladin-cli/
├── Cargo.toml            # add deps (§3); keep [[bin]] name = "paladin"
├── src/
│   ├── main.rs           # entry: parse → run → map AppError to process::exit
│   ├── cli.rs            # clap `Cli` derive struct + Mode enum + raw flags
│   ├── validate.rs       # semantic checks: mode/flag applicability, knob↔kdf, q/v/progress
│   ├── options.rs        # build EncryptOptions (cipher/kdf/params/armor/name) from Cli
│   ├── secret.rs         # password resolution + interactive prompt/confirm → Secret
│   ├── progress.rs       # indicatif bar + cancel flag + on_progress closure factory
│   ├── run.rs            # mode dispatch + path/IO orchestration (encrypt/decrypt/verify)
│   └── info.rs           # `--info`: Header → stable `key: value` lines
└── tests/
    └── cli.rs            # assert_cmd integration tests (§10)
```

`main.rs` stays tiny: build `Cli`, call `run::dispatch(cli)`, and on `Err(e)`
print the message to stderr and `std::process::exit(e.exit_code())`.

---

## 3. Dependencies to add (`cargo add`, pinned at implementation time)

Per [DESIGN §9](DESIGN.md#9-dependencies). Versions resolved via `cargo add`
(latest compatible) and pinned in `Cargo.lock`.

| Crate                            | Why                                                            |
| -------------------------------- | -------------------------------------------------------------- |
| `paladin-core` (path)           | The four operations + helpers.                                |
| `paladin-common` (path)         | Terminal glue + exit-code mapping.                            |
| `clap` (features = `derive`)     | Argument parsing, `--help`, `--version`.                      |
| `rpassword`                      | No-echo interactive password prompt.                         |
| `indicatif`                      | Progress bar on stderr.                                       |
| `zeroize`                        | Hold prompt-captured password bytes in a zeroizing buffer. New CLI use — added to DESIGN §9 (was core-only); see §10–§11. |
| `ctrlc`                          | SIGINT handler to flip the cancel flag (§6.6). New CLI dep — added to DESIGN §9; see §10–§11. |
| `assert_cmd`, `predicates` *(dev)* | Integration tests.                                          |
| `tempfile` *(dev)*               | Test fixtures / temp dirs.                                   |

---

## 4. Argument model (`cli.rs`)

A single `#[derive(Parser)]` struct mirroring [DESIGN §6.3](DESIGN.md#63-options).
Mode is a required, mutually-exclusive group (`-e` / `-d` / `-i` / `--verify`);
`<FILE>` is a required positional (`-` = stdin). Cipher/KDF arrive as raw
strings and are parsed by the core's `FromStr` in `options.rs` (exact lowercase,
no aliases — let core reject bad values as `InvalidOptions` → exit 2, or
pre-validate for a friendlier message).

| Field (struct)        | Flag(s)                                  | Type                     | Notes                                  |
| --------------------- | ---------------------------------------- | ------------------------ | -------------------------------------- |
| `encrypt`             | `-e, --encrypt`                          | `bool` (group `mode`)    | Exactly one mode required.             |
| `decrypt`             | `-d, --decrypt`                          | `bool` (group `mode`)    |                                        |
| `info`                | `-i, --info`                             | `bool` (group `mode`)    | No password, no output.                |
| `verify`              | `--verify`                               | `bool` (group `mode`)    | No output.                             |
| `file`                | `<FILE>` positional                      | `PathBuf`                | `-` = stdin.                           |
| `output`              | `-o, --output`                           | `Option<PathBuf>`        | enc/dec only; `-` = stdout.            |
| `password`            | `-p, --password`                         | `Option<OsString>`       | Discouraged; non-UTF-8 ⇒ usage error. |
| `password_file`       | `--password-file`                        | `Option<PathBuf>`        |                                        |
| `password_env`        | `--password-env`                         | `Option<OsString>`       |                                        |
| `no_password`         | `--no-password`                          | `bool`                   | Valid only with `-k`.                  |
| `keyfile`             | `-k, --keyfile`                          | `Option<PathBuf>`        | `-` rejected.                          |
| `cipher`              | `-c, --cipher`                           | `Option<String>`         | encrypt only.                          |
| `kdf`                 | `--kdf`                                  | `Option<String>`         | encrypt only.                          |
| `argon2_memory/time/parallelism` | `--argon2-*`                  | `Option<u32>`            | require argon2id.                      |
| `scrypt_log_n/r/p`    | `--scrypt-*`                             | `Option<u32>`            | require scrypt.                        |
| `pbkdf2_iterations`   | `--pbkdf2-iterations`                    | `Option<u32>`            | require pbkdf2.                        |
| `armor`               | `-a, --armor`                            | `bool`                   | encrypt only.                          |
| `name`                | `--name`                                 | `bool`                   | encrypt only; rejected with stdin.     |
| `force`               | `-f, --force`                            | `bool`                   | enc/dec.                               |
| `remove`              | `--remove`                               | `bool`                   | enc/dec; rejected with stdin.          |
| `progress`            | `--progress` / `--no-progress`           | `Option<bool>`           | default auto (stderr TTY).             |
| `verbose` / `quiet`   | `-v, --verbose` / `-q, --quiet`          | `bool`                   | mutually exclusive.                    |

clap expresses what it can (the required mode group, `-V`/`-h`). Cross-flag
rules that clap can't cleanly state (mode→flag applicability, KDF-knob↔`--kdf`,
`--name`+stdin, `--progress`+`--quiet`) live in `validate.rs` (§5, step 3) so the
messages are precise and uniformly mapped to exit 2.

**`-v/--verbose` output.** Verbose prints a defined, secret-free set of
diagnostics to stderr: before streaming, the mode, the resolved input and output
paths (`-` for stdin/stdout), and — on encrypt — the chosen cipher and KDF with
their cost parameters plus whether a keyfile is in use; on success, a one-line
summary naming the operation and the finalized output path. It never prints
passwords, keyfile contents, or derived keys, and `-q/--quiet` suppresses it (the
two are mutually exclusive). With neither flag, only the progress bar (§6.5) and
errors are shown.

---

## 5. Ordered implementation steps (TDD)

Each step writes failing tests first, then the code. Phases 1–9 build the binary;
10 is the integration suite (many cases already have unit coverage from earlier
phases).

### Step 1 — Crate wiring & skeleton
- Add dependencies (§3); keep `[[bin]] name = "paladin"`.
- Replace the stub `main.rs` with the module skeleton (§2); `run::dispatch`
  returns `AppResult<()>`; `main` maps the error to a message + `exit_code()`.
- **Test first:** `paladin --version` / `--help` succeed (exit 0) and `--help`
  lists every flag in §6.3 (`assert_cmd` + `predicates`).

### Step 2 — Arg model
- Implement `cli.rs` (§4). Required mode group; positional `<FILE>`.
- **Test first:** missing mode, two modes, missing `<FILE>` ⇒ exit 2; `-h`/`-V`
  need no mode/file.

### Step 3 — Semantic validation (`validate.rs`)
Reject, with `AppError::usage` (exit 2), before any work:
- A flag used in a mode it does not apply to (per the §6.3 *Applies to* column):
  `-c`/KDF knobs with `-d`/`-i`/`--verify`; `-o` with `-i`/`--verify`; `-p` (and
  other secret flags) with `-i`; `-a`/`--name` outside encrypt; `-f`/`--remove`
  outside enc/dec.
- KDF cost knob without its matching `--kdf` (argon2 knobs need argon2id-or-default,
  scrypt knobs need scrypt, pbkdf2 knobs need pbkdf2); a knob never implies a KDF.
- `--name` with stdin input; `--remove` with stdin input.
- `-q` + `-v` together; `--progress` + `--quiet` together (`--no-progress` +
  `--quiet` allowed, redundant).
- **Test first:** one case per rule asserts exit 2 and a clear message.

### Step 4 — Options assembly (`options.rs`)
- Parse `-c/--cipher`, `--kdf` via core `FromStr` (exact lowercase).
- Build `KdfParams` for the selected KDF: start from the §12 default for that
  KDF, override only the supplied knobs. Out-of-range values are left for core
  (`InvalidOptions` → exit 2) but may be pre-checked for nicer messages.
- `armor` from `-a`; `filename` = `Some(basename)` when `--name` (convert the
  input path's basename `OsStr`→`str`; non-UTF-8 ⇒ usage error; the safe-basename
  rules in §5.2 are enforced by `core::encrypt`).
- **Test first (unit):** default `EncryptOptions` matches §12; each KDF selection
  yields the right `KdfParams` variant; knob overrides apply; unknown
  cipher/KDF name ⇒ usage error.

### Step 5 — Password & secret (`secret.rs`)
- Call `password_source_from_flags(inline, file, env, no_password)`.
  - `Ok(Some(src))` ⇒ `resolve_password(&src)`.
  - `Ok(None)` ⇒ interactive prompt via `rpassword` into a `Zeroizing<Vec<u8>>`;
    on **encrypt**, prompt twice and require a match; reject an empty entry and
    re-ask (empty is allowed only via `--no-password`).
- Keyfile: `read_keyfile(path)` when `-k` given.
- `Secret::new(&password, keyfile.as_deref())` — core rejects empty+empty as
  `InvalidOptions` (exit 2), matching the "at least one byte" rule.
- **Resolve/validate paths before prompting** so a clobber/same-file error
  doesn't waste a password entry.
- **Test first:** non-interactive sources (`-p`, file, env, `--no-password`) via
  `assert_cmd` (interactive TTY prompt is covered manually / by `secret.rs`
  unit seams). Empty-source rejection and `--no-password` requires `-k` are
  already enforced upstream — assert the exit code/message here.

### Step 6 — Paths, I/O & finalization (`run.rs`)
- Input: `is_stdio` ⇒ stdin (`input_len = None`); else `require_regular_file`,
  `open_input`, and read length from metadata for `input_len`.
- Output target:
  - **Encrypt, no `-o`:** `default_encrypt_output(input, armor)` (needs a file
    input; stdin requires `-o`).
  - **Decrypt, no `-o`:** must parse the header first — open the file, `inspect`
    it, then `default_decrypt_output(input, &header)`, then re-open for the
    decrypt pass. (Stdin decrypt requires `-o`, so no header peek is needed.)
  - `open_output(target, force, input)` performs clobber, regular-file, and
    same-file refusals (exit 2); returns an `OutputSink`.
- Run the core op against `sink.as_write()`; on `Ok`, `sink.commit()`. On any
  `Err`, return it (temp file auto-drops; no `--remove`).
- **`--remove`:** only after `commit()` succeeds — `best_effort_remove(input)`;
  on failure print a stderr warning and still exit 0.
- **Test first:** default extensions (encrypt `.paladin`/`.paladin.asc`);
  decrypt name from header vs extension-strip vs `.dec`; required `-o` for stdin
  enc/dec; `--remove` rejected with stdin; output-equals-input refusal
  (incl. symlink/hardlink where supported); `0600` temp mode on Unix; temp-file
  cleanup on failure; failed-rename ⇒ exit 1 with no `--remove`.

### Step 7 — Progress & cancellation (`progress.rs`)
- Decide whether to show progress: `--progress`/`--no-progress` override;
  default on when `stderr().is_terminal()` (std `IsTerminal`); always off under
  `--quiet`.
- Build the `OnProgress` closure: update an `indicatif::ProgressBar`
  (length = `total` when `Some`, else a spinner) to `done`; return
  `ControlFlow::Break` if the shared cancel flag (`Arc<AtomicBool>`) is set.
- Install a SIGINT handler (`ctrlc`) once in `main` that sets the cancel flag.
  The core observes it before/after KDF and between chunks, returns
  `SymError::Canceled` ⇒ exit 130; the unfinalized temp output drops away.
- **Test first:** `--progress` with `--quiet` already rejected (step 3);
  `--no-progress` produces no bar; quiet suppresses progress but not `--info`
  stdout or errors. (SIGINT timing is covered manually + a core-level cancel
  unit test; an `assert_cmd` cancel test is best-effort.)

### Step 8 — Mode handlers
- **Encrypt:** options + secret + input/output ⇒ `core::encrypt(.., input_len,
  on_progress)`.
- **Decrypt:** secret + input/output ⇒ `core::decrypt(..)`.
- **Verify:** secret + input, **no output** ⇒ `core::verify(..)`; print nothing
  on success (exit 0), map `Auth` ⇒ exit 3.
- **Info:** see §7 below.
- **Test first:** armor round-trip; `--verify` success and failure exit codes;
  wrong password ⇒ exit 3; unknown cipher/KDF id / reserved flag in a crafted
  header ⇒ exit 4.

### Step 9 — `--info` formatting (`info.rs`)
Implement the exact, stable output contract (§7). **Test first:** byte-exact
`--info` output for an Argon2id file, a scrypt file, a PBKDF2 file, a file with a
stored name (`present`), an unsafe stored name (`ignored_unsafe`), and a
keyfile-hint file; armored input auto-detected.

### Step 10 — Integration suite (`tests/cli.rs`)
Consolidate/extend the `assert_cmd` cases enumerated in §8.

### Step 11 — Docs & packaging
`--help` text reviewed for accuracy; man page; `cargo install` (§9).

---

## 6. Behavioral-contract → enforcement-point map

Confirms every §6 rule has a home and is not duplicated.

| Rule (DESIGN §6)                                          | Enforced in                                  |
| --------------------------------------------------------- | -------------------------------------------- |
| Exactly one mode; one `<FILE>`; `-`=stdin                 | `cli.rs` (clap group) + `run.rs`             |
| Flag-not-applicable-to-mode ⇒ exit 2                      | `validate.rs`                                |
| KDF knob requires matching `--kdf`                        | `validate.rs`                                |
| `-q`/`-v` exclusive; `--progress`+`--quiet` invalid       | `validate.rs`                                |
| Password-source exclusivity / empty-source rejection      | `common::password_source_from_flags` + `resolve_password` |
| Interactive prompt; encrypt confirms twice                | `secret.rs` (`rpassword`)                    |
| `--no-password` only with `-k`                            | `validate.rs` (+ `Secret::new` backstop)     |
| Keyfile caps / `-` rejected / regular-file                | `common::read_keyfile`                       |
| Default output paths                                      | `core::default_*_output`                     |
| Clobber / same-file / regular-file output                 | `common::open_output`                        |
| Temp-file finalize; `0600`; cleanup on failure            | `common::OutputSink` (drop/commit)           |
| Stdin requires `-o`; `--remove` rejected with stdin       | `validate.rs` / `run.rs`                     |
| `--remove` warns-but-exits-0 on delete failure            | `run.rs` + `common::best_effort_remove`      |
| Size cap, tamper, truncation                              | `paladin-core` (CLI just maps the error)    |
| Exit-code mapping (`SymError` → 0/1/2/3/4/130)            | `common::exit_code` / `AppError::exit_code`  |
| SIGINT ⇒ cancel flag ⇒ `Canceled` ⇒ 130                   | `progress.rs` + `main` (`ctrlc`)             |

---

## 7. `--info` output contract (§6.2)

Stable UTF-8 `key: value` lines to **stdout**, in this exact order; not
suppressed by `--quiet`. Values come from core display helpers / the `Header`.

```
format: paladin
version: <decimal>
cipher: <lowercase name>
kdf: <lowercase name>
kdf_params: <see below>
flags: 0x<two-digit lowercase hex>
keyfile_hint: <true|false>
chunk_size: <decimal>
salt_len: <decimal>
nonce_prefix_len: <decimal>
name_status: <absent|present|ignored_unsafe>
name: <basename when name_status: present, else empty>
```

`kdf_params` is `memory=<KiB>,time=<N>,parallelism=<N>` (Argon2id),
`log_n=<N>,r=<N>,p=<N>` (scrypt), or `iterations=<N>` (PBKDF2). A non-UTF-8
stored name is a `MalformedHeader` (exit 4), not normal output. Armored input is
auto-detected by `inspect`. No password is read in this mode.

---

## 8. Integration tests (`tests/cli.rs`, `assert_cmd` + `tempfile`)

From [DESIGN §10](DESIGN.md#10-testing-strategy). One test (or a small table)
per item:

- Default extensions: encrypt → `.paladin` / `.paladin.asc`.
- Decrypt default output: stored name; extension-strip; `.dec` fallback;
  empty-basename fallback (`.paladin` → `.paladin.dec`).
- Required `-o` for stdin encrypt/decrypt; `--remove` rejected with stdin.
- `--remove` warning-but-success when deletion fails after a good output.
- Output-equals-input refusal; symlink-resolved and hardlink same-file refusal
  where platform metadata supports it.
- `-o -` / stdout path; armor round-trip via stdout.
- Exact `--info` output (per KDF; `present`/`ignored_unsafe`/keyfile-hint).
- `--verify` success and failure (exit 0 vs 3).
- Clobber refusal vs `-f`.
- KDF-knob/mode mismatch usage errors; `-q`/`-v` and `--progress`/`--quiet`
  conflicts.
- Reject `-` for `--password-file` and `-k/--keyfile`.
- Password-file and keyfile size caps; zero-byte keyfile rejection.
- Reject empty-password sources (`-p ''`, empty `--password-file`, set-but-empty
  `--password-env`) except `--no-password`.
- Temp-file cleanup on failure; Unix `0600` output mode.
- Reject directories/special files for input, password-file, keyfile, and
  existing output paths.
- Exit codes incl. 130 for cancellation (best-effort).
- Exact lowercase cipher/KDF parsing; alias/case rejection.
- Non-UTF-8 OS-native path handling where the platform supports it.
- Password bytes via file/env/`--no-password` produce a decryptable file.

After code changes: `cargo fmt`, `cargo clippy --all-targets --all-features`
(no warnings), `cargo test -p paladin-cli`.

---

## 9. Docs & packaging

- **`--help`:** mark `-p/--password` discouraged (§11); state `--remove` is a
  plain delete (no secure erase); note armor recommended when stdout is a TTY.
- **Man page:** `paladin(1)` mirroring §6 (consider generating from clap).
- **`cargo install`:** `cargo install --path crates/paladin-cli` installs the
  `paladin` binary; document in the README once it builds.
- Update the README's CLI usage/examples to match §6.7 once implemented.

---

## 10. Open items / confirmations

- **SIGINT crate — resolved.** §6.6 requires a handler but [DESIGN §9](DESIGN.md#9-dependencies)
  listed no signal crate. The CLI uses **`ctrlc`** (small, cross-platform; chosen
  over `signal-hook`) and it has been added to the DESIGN §9 table.
- **`zeroize` for the CLI — resolved.** The interactive prompt buffer is held in
  `Zeroizing<Vec<u8>>`, so the CLI takes a direct `zeroize` dependency. DESIGN §9
  listed `zeroize` as core-only; its row now also lists `cli`.
- **`anyhow` dropped from the CLI — resolved.** The CLI's error currency is
  `AppError`/`AppResult` (message + `exit_code()`), which `anyhow` does not
  compose with, so the CLI takes no `anyhow` dependency; DESIGN §9's `anyhow` row
  no longer lists `cli`.
- **`-v/--verbose` — resolved.** Verbose prints a defined, secret-free set of
  stderr diagnostics (§4); it is no longer left unspecified.
- **TTY detection** uses std `IsTerminal` (Rust ≥ 1.70; workspace is 1.94) — no
  extra crate.
- Everything else is fully determined by `paladin-core` + `paladin-common`,
  which are already implemented and tested.

---

## 11. Master checklist

- [x] **Step 1** — deps added; module skeleton; `main` error→exit mapping; `--help`/`--version`.
- [x] **Step 2** — `cli.rs` arg model; mode group + positional `<FILE>`.
- [x] **Step 3** — `validate.rs` semantic rules (mode/flag, knob↔kdf, `--name`/`--remove`+stdin, q/v/progress).
- [x] **Step 4** — `options.rs` cipher/KDF parse + `KdfParams` assembly + `--name` basename + armor.
- [x] **Step 5** — `secret.rs` non-interactive resolution + interactive prompt/confirm → `Secret`.
- [x] **Step 6** — `run.rs` input/output paths, decrypt-needs-`inspect` sequencing, `OutputSink` finalize, `--remove`.
- [x] **Step 7** — `progress.rs` indicatif bar + `ctrlc` cancel flag + `OnProgress` closure.
- [x] **Step 8** — encrypt / decrypt / verify handlers wired to core.
- [x] **Step 9** — `info.rs` exact stable `--info` output.
- [x] **Step 10** — `assert_cmd` integration suite (§8); `fmt` + `clippy` clean.
- [x] **Step 11** — `--help` text, `paladin(1)` man page, `cargo install`, README CLI section.
- [x] DESIGN §9 updated: add `ctrlc` (cli); add `cli` to `zeroize`; drop `cli` from `anyhow`.
