# paladin — Implementation plan 03: TUI (`paladin-tui`)

**Status:** Implemented and tested. `paladin-core` and `paladin-common` are
complete (see
[`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)); the TUI
builds only on their public APIs and adds no crypto or format logic. The
checklist below is fully checked off.

**Target stack:** Rust 1.94+, [ratatui](https://ratatui.rs/) widgets/layout over
[crossterm](https://docs.rs/crossterm) (raw mode, key + resize events).

**Scope.** The `paladin-tui` binary — a single-screen, keyboard-driven
interactive form that gathers input, builds the same `Secret` /
`EncryptOptions` every front-end uses, and calls the four core operations
(`encrypt` / `decrypt` / `inspect` / `verify`). It reuses `paladin-common` for
all terminal glue (path validation, output finalization, best-effort remove,
exit-code mapping) and captures the password in its own masked field
(DESIGN §7).

**Depends on:** [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)
— `paladin-core` and the `paladin-common` terminal glue.

**Sibling plans:** [`IMPLEMENTATION_PLAN_02_CLI.md`](IMPLEMENTATION_PLAN_02_CLI.md),
[`IMPLEMENTATION_PLAN_04_GTK.md`](IMPLEMENTATION_PLAN_04_GTK.md).

---

## 1. Constraints inherited from DESIGN

The TUI is a *thin view*. It owns only medium-specific concerns and must not
re-implement anything the core or common crate already provides.

- **No crypto / no format logic.** All four operations go through
  `paladin-core`; all path/clobber/remove logic goes through `paladin-common`.
- **No stdin/stdout streaming.** The terminal UI owns stdin/stdout, so every
  path field accepts filesystem paths only; a literal `-` is **rejected**
  (DESIGN §7.1). The CLI remains the only v1 front-end with `-` streaming.
- **Regular-file rule.** Input and keyfile paths must be existing regular files;
  output paths may be a new or existing regular file, with the same overwrite
  and same-file checks as the CLI (DESIGN §6.5).
- **Password capture is local.** The password is read in the TUI's own masked
  field under crossterm raw mode — **not** `rpassword`, which would fight raw
  mode (DESIGN §7.2). Password-file and password-env sources are CLI-only.
- **Off-thread crypto.** The event loop stays on the main thread; the crypto
  call runs on a worker thread, streams `Progress` back over an `mpsc` channel,
  and is cancellable. The password is moved into the worker in a zeroizing
  buffer (DESIGN §7.2).

---

## 2. Crate layout & dependencies

`paladin-tui` is currently an empty scaffold (`src/main.rs`). Pin versions with
`cargo add` at implementation time (latest compatible; `Cargo.lock` records the
resolved set).

| Dependency                  | Purpose                                                        |
| --------------------------- | ------------------------------------------------------------- |
| `paladin-core` (path)      | The four operations, `EncryptOptions`, helpers, error type.   |
| `paladin-common` (path)    | Path/stdin-reject validators, `OutputSink`, remove, exit map. |
| `ratatui`                   | Widgets and layout (`Tabs`, `Gauge`, `Paragraph`, blocks).    |
| `crossterm`                 | Terminal backend: raw mode, alternate screen, key/resize.     |
| `clap` (derive)             | Optional launch path only (`paladin-tui <file>`).            |
| `zeroize`                   | `Zeroizing` buffer for the masked password (DESIGN §7.2).     |
| `anyhow`                    | Error context in `main` startup/teardown paths.               |

`tempfile` is pulled in transitively through `paladin-common` (temp-file
finalization) and directly under `[dev-dependencies]` for tests.

Proposed internal modules (organization detail; DESIGN only mandates the
binary):

| Module        | Responsibility                                                           |
| ------------- | ------------------------------------------------------------------------ |
| `main.rs`     | Terminal setup/teardown, panic-safe restore, optional launch path, exit. |
| `app.rs`      | `App` state (mode, fields, focus, advanced, run status, progress).       |
| `event.rs`    | Key/resize handling, focus navigation, per-field editing.                |
| `ui.rs`       | ratatui rendering: tabs, fields, advanced pane, gauge, footer, help.     |
| `field.rs`    | Single-line text editor (cursor, insert/delete, Home/End) + masking.     |
| `options.rs`  | Pure UI-state → `EncryptOptions`/`KdfParams` + secret assembly + checks.  |
| `worker.rs`   | Worker thread, `mpsc` progress, cancel flag, output finalize, remove.    |

---

## 3. Application model

A single full-screen form (DESIGN §7.1). State lives in one `App` struct that
`update` mutates and `ui` renders.

- **Mode** — `Encrypt | Decrypt | Info | Verify` (ratatui `Tabs`). Switching
  mode shows/hides the relevant fields.
- **Fields** — input path; output path (Encrypt/Decrypt); password + confirm
  (Encrypt) / password (Decrypt/Verify); each tracked by a `field::Editor`.
- **Toggles** — show/hide password; keyfile-only (≡ `--no-password`).
- **Advanced (collapsible)** — Encrypt-only cipher and KDF selectors, the
  selected KDF's cost knobs, `--name` and `--armor` switches; Encrypt/Decrypt
  remove-input and overwrite (`-f`) switches; keyfile path for
  Encrypt/Decrypt/Verify.
- **Focus** — index into the visible widget list; `Tab`/`Shift-Tab` cycle,
  selectors use `←/→`, checkboxes toggle with `Space`.
- **Run status** — `Idle | Running { progress } | Done { msg } | Failed { msg }
  | Canceled`, plus an Info results buffer.
- **Output dirty flag** — set once the user edits the output field, so prefill
  never clobbers a manual edit.

---

## 4. Behavior by area

### 4.1 Path fields & output prefill

- Reject a literal `-` in any path field with an inline message (the UI owns
  stdin/stdout).
- Validate the input path with `common::require_regular_file`; surface failures
  as a field error rather than waiting for the run.
- **Encrypt prefill:** when the input becomes valid (and output is not dirty),
  set output to `core::default_encrypt_output(input, armor)`. Re-derive when the
  `--armor` toggle flips (`.paladin` ↔ `.paladin.asc`).
- **Decrypt prefill:** stored names need the header, so on a valid input call
  `core::inspect(open_input(input))` and prefill with
  `core::default_decrypt_output(input, &header)`. If inspect fails (not a
  paladin file / malformed), show a hint and leave the field for the user.

### 4.2 Password & secret assembly (`options.rs`, pure + tested)

Mirror DESIGN §6.4 semantics in-UI, then hand bytes to the core:

- Capture password bytes into `Zeroizing<Vec<u8>>`; never echo to logs.
- **Encrypt** requires the confirm field to match and rejects an empty
  passphrase (re-prompt by keeping focus, like the CLI re-asks).
- **Keyfile-only** toggle requires a keyfile and uses an empty password
  (the `--no-password` equivalent); reading uses `common::read_keyfile` (1
  byte..=`core::KEYFILE_MAX_BYTES`, regular file).
- Build `core::Secret::new(&password, keyfile.as_deref())`; an empty
  password + empty keyfile is rejected before any worker starts.

### 4.3 Advanced options → `EncryptOptions`

- Cipher/KDF selectors parse via the core `CipherId`/`KdfId` `FromStr` and
  display via `Display`, so names stay identical to the CLI (exact lowercase).
- Show only the selected KDF's knobs, prefilled from
  `KdfId::default_params(kdf)`; validate against the §5.4 ranges with inline
  messages and assemble the matching `KdfParams` variant. The core re-validates,
  so the UI check is for fast feedback only.
- `--name` stores the input basename (Encrypt only); the basename must be valid
  UTF-8 (DESIGN §5.2), so toggling `--name` pre-checks it and shows an inline
  field error otherwise (the core re-validates → `InvalidOptions`/exit 2).
  `--armor` wraps output and changes the default extension. `chunk_size` is not
  user-settable in v1 (`EncryptOptions::default()` carries 64 KiB).

### 4.4 Running an operation (`worker.rs`)

- On `Enter`, validate all visible fields; block with a status message if
  invalid.
- Open input with `common::open_input`; open output with
  `common::open_output(target, overwrite, Some(input))` (returns an
  `OutputSink::File` — `-` is already rejected). Move the zeroizing
  password/keyfile, paths, and the sink into the worker thread.
- The worker builds the `Secret`/`EncryptOptions` and calls the matching core
  function with an `on_progress` closure that (a) checks the shared
  `Arc<AtomicBool>` cancel flag and returns `ControlFlow::Break` when set, and
  (b) sends `Progress { done, total }` over the `mpsc` channel.
- **Success:** `sink.commit()` finalizes via temp-file rename; if remove-input
  is set, `common::best_effort_remove(input)` runs and a failure only warns.
- **Failure / cancel:** drop the sink (its `NamedTempFile` auto-removes the
  partial output); report the result to the UI.
- The UI drains the channel each tick to redraw a `Gauge` and a status line.
  Because the TUI streams only regular files (never stdin), `input_len` is always
  known, so `total` is always `Some` and the gauge is always determinate; the
  indeterminate (`total == None`) branch is handled defensively but never arises
  in the TUI.

### 4.5 Info & Verify

- **Info** needs no secret and derives no key, so it runs inline:
  `core::inspect` → render stable `key: value` lines in the results pane in the
  DESIGN §6.2 order (`format`, `version`, `cipher`, `kdf`, `kdf_params`,
  `flags`, `keyfile_hint`, `chunk_size`, `salt_len`, `nonce_prefix_len`,
  `name_status`, `name`) using the shared display forms.
- **Verify** runs on the worker like decrypt but writes nothing; success/failure
  shows in the status line.

### 4.6 Cancellation & errors

- `Esc` during a run flips the cancel flag; the core observes it before/after
  KDF work and between chunks, returns `PalError::Canceled`, the worker removes
  any temp output, and the UI shows a **non-error** canceled state. A KDF call
  already running may finish first.
- Error messages and the **process exit code** come from
  `paladin-common` (`exit_code` / `AppError::exit_code`): per-operation
  failures are shown in-UI without exiting, and the last **completed**
  operation's result maps to the exit status on a normal quit (success → 0, auth
  failure → 3, and so on). A user-acknowledged cancellation is non-error — it
  resets the pending status to idle and never sets a sticky non-zero exit. Exit
  **130** is reserved for `Ctrl-C` terminating the process while an operation is
  running (the worker's temporary output is removed during teardown). This keeps
  the shared 0/1/2/3/4/130 contract (DESIGN §6.6) intact for callers that launch
  the TUI.

### 4.7 Keys & help

- `Tab`/`Shift-Tab` move focus · `←/→` change selectors · `Space` toggles ·
  `Enter` runs · `Esc` cancels a run or quits · `?` opens a help overlay ·
  `Ctrl-C` quits (restoring the terminal first).
- Footer renders the context-relevant hints; `?` shows the full key map.

---

## 5. UI → core/common API map

| UI action                         | Call                                                              |
| --------------------------------- | ----------------------------------------------------------------- |
| Validate input/keyfile path       | `common::require_regular_file` (+ reject `-` via `common::is_stdio`) |
| Open input stream                 | `common::open_input(&input)`                                       |
| Open output (temp + checks)       | `common::open_output(&target, overwrite, Some(&input))`           |
| Finalize / roll back output       | `OutputSink::as_write` then `OutputSink::commit` (drop on failure) |
| Remove input after success        | `common::best_effort_remove(&input)`                              |
| Read keyfile                      | `common::read_keyfile(&path)`                                     |
| Assemble secret                   | `core::Secret::new(&password, keyfile.as_deref())`               |
| Build options                     | `core::EncryptOptions { .. }`, `core::KdfId::default_params`      |
| Prefill output (enc / dec)        | `core::default_encrypt_output` / `core::inspect` + `default_decrypt_output` |
| Run                               | `core::{encrypt, decrypt, inspect, verify}` with `OnProgress`     |
| Map error → exit code / message   | `common::exit_code` / `AppError::exit_code`                       |

---

## 6. Testing strategy (TDD; DESIGN §10)

The rendering and event loop need manual verification, so push all decision
logic into pure, unit-tested functions (`options.rs`, `field.rs`) and keep
`ui.rs`/`event.rs` thin. Write the failing test first, then implement.

- **Path-field rules:** a literal `-` is rejected in every mode; non-regular and
  missing inputs are rejected (delegating to `common`).
- **Output prefill:** Encrypt extension follows the `--armor` toggle; the dirty
  flag stops prefill from overwriting manual edits; Decrypt prefill uses the
  inspected header.
- **Secret assembly:** keyfile-only requires a keyfile; Encrypt requires a
  matching, non-empty confirm; empty password + empty keyfile is rejected.
- **Options mapping:** UI state → `EncryptOptions`/`KdfParams` for each
  cipher/KDF; out-of-range knobs are caught with the §5.4 message before the core
  is called; a non-UTF-8 `--name` basename is rejected with an inline error
  before the core is called; cipher/KDF names round-trip through
  `FromStr`/`Display`.
- **Line editor (`field.rs`):** insert/delete, cursor moves, Home/End, and
  masking render.
- **Exit-code passthrough:** `PalError` variants map to the shared codes via
  `common::exit_code`; a user-acknowledged cancel leaves the exit status at the
  last completed operation's code (not 130) on a normal quit.

Headless terminal-driver tests over a ratatui `TestBackend` are a stretch goal
for the static layout; the four operations are already covered exhaustively in
`paladin-core`, so the TUI tests focus on its own glue (DESIGN §10).

---

## 7. Docs & packaging

- `paladin-tui.1` man page (synopsis, key bindings, mode descriptions).
- README usage section + key-binding reference; note GTK/CLI differences
  (no `-` streaming, no password-file/env).
- `cargo install -p paladin-tui` produces the `paladin-tui` binary.

---

## Checklist

**Phase 0 — Scaffold**

- [x] Add deps via `cargo add` (ratatui, crossterm, clap derive, zeroize,
      anyhow) + `paladin-core`/`paladin-common` path deps.
- [x] Terminal setup/teardown: raw mode + alternate screen, panic-safe restore,
      `main` mapping startup errors via `common`.
- [x] App skeleton renders an empty form; `Esc`/`Ctrl-C` quit cleanly.

**Phase 1 — State & rendering**

- [x] `App` state (mode, fields, focus, advanced, status, progress).
- [x] Mode tabs + per-mode field layout; footer hints; `?` help overlay.

**Phase 2 — Input & navigation**

- [x] `field::Editor` line editor (cursor/insert/delete/Home/End) + unit tests.
- [x] Focus navigation (`Tab`/`Shift-Tab`, selector `←/→`, `Space` toggles).
- [x] Masked password + confirm fields with show/hide toggle.

**Phase 3 — Paths & prefill**

- [x] Reject `-`; `require_regular_file` validation with inline errors.
- [x] Output prefill (Encrypt via `default_encrypt_output`; Decrypt via
      `inspect` + `default_decrypt_output`) with dirty-flag + armor-extension
      switch.

**Phase 4 — Options & secret**

- [x] Advanced toggles, cipher/KDF selectors, per-KDF cost knobs (prefilled,
      range-checked).
- [x] Pure UI-state → `EncryptOptions`/`KdfParams` mapping (+ tests).
- [x] Password/keyfile → `Secret` assembly with §6.4 validation (+ tests).

**Phase 5 — Execution**

- [x] Worker thread + `mpsc` `Progress` channel + cancel `AtomicBool`.
- [x] Encrypt/Decrypt/Verify via core; `OutputSink::commit`; `--remove` via
      `best_effort_remove`.
- [x] Info inline via `inspect` → ordered `key: value` results pane.
- [x] Progress gauge + status line; `Esc` cancellation → non-error canceled
      state + temp removal.

**Phase 6 — Errors & exit codes**

- [x] Map `PalError`/`AppError` → messages + process exit via `common::exit_code`.
- [x] Light unit tests of non-UI glue (`-` rejection, validation, mapping).

**Phase 7 — Docs & packaging**

- [x] `paladin-tui.1` man page.
- [x] README usage + key-binding reference.
- [x] `cargo install -p paladin-tui`.

---

## Post-v1 (out of scope here)

- Built-in file-browser popup for path fields (DESIGN §7.1 / §14: plain path
  entry in v1).
- Headless `TestBackend` snapshot tests of the full layout.
- stdin/stdout streaming (CLI-only by design).
