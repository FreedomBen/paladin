# paladin — Implementation plan 04: GTK (`paladin-gtk`)

**Status:** Expanded. [DESIGN.md](DESIGN.md) §8 is the source of truth for the
GTK front-end; this plan turns it into ordered, trackable steps. If a step here
conflicts with DESIGN.md, update DESIGN.md first so design and plan stay in sync.

**Scope.** The `paladin-gtk` binary — a [relm4](https://relm4.org/)
(gtk4-rs + libadwaita) desktop front-end over `paladin-core` (DESIGN §8). It is
a thin view: it gathers input through widgets, builds a `Secret` and
`EncryptOptions`, calls the four core operations, and renders progress and
results. It holds **no** crypto or format logic.

**Depends on:** [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)
— `paladin-core` only. Note: `paladin-gtk` does **not** use `paladin-common`;
it relies on the core plus GTK-native file handling and a small, unit-tested glue
module of its own (DESIGN §2.2, §8). Terminal-only concerns — stdin/stdout
streaming, `rpassword`, `--password-file`/`--password-env`, exit codes — do not
apply to the GUI and are intentionally absent.

**Sibling plans:** [`02_CLI`](IMPLEMENTATION_PLAN_02_CLI.md),
[`03_TUI`](IMPLEMENTATION_PLAN_03_TUI.md).

---

## 1. Core API this front-end consumes

Everything below is already implemented in `paladin-core` (plan 01). The GTK app
only calls these — it never re-derives behavior:

| Item | Use in GTK |
| --- | --- |
| `encrypt(input, output, &secret, &opts, input_len, on_progress)` | Encrypt mode, on the worker. |
| `decrypt(input, output, &secret, input_len, on_progress)` | Decrypt mode, on the worker. |
| `inspect(input) -> Header` | Info mode + output-name prefill on Decrypt. No password. |
| `verify(input, &secret, input_len, on_progress)` | Verify mode, on the worker. |
| `default_encrypt_output(&Path, armor)` / `default_decrypt_output(&Path, &Header)` | Prefill the editable output row (DESIGN §6.5). |
| `Secret::new(password, keyfile)` · `KEYFILE_MAX_BYTES` | Assemble the secret; reject empty+empty; bound keyfile size. |
| `EncryptOptions` · `CipherId` · `KdfId` · `KdfParams::default_for(kdf)` | Build encrypt options from the Advanced controls. |
| `Progress { done, total }` · `OnProgress` (`-> ControlFlow<()>`) | Stream progress; `Break` cancels. |
| `Header` (`version`, `cipher`, `kdf`, `kdf_params`, `flags`, `keyfile_hint`, `chunk_size`, `salt_len`, `nonce_prefix_len`, `name`, `name_status`) · `NameStatus` | Render Info mode. |
| `PalError` (`Auth`, `BadMagic`, `UnsupportedVersion`, `UnknownCipher`, `UnknownKdf`, `ReservedFlags`, `MalformedHeader`, `InvalidOptions`, `InputTooLarge`, `Canceled`, `Io`) | Map to user-facing toast/dialog text. |

`CipherId`/`KdfId` provide `FromStr`/`Display` (exact lowercase
names, no aliases) so the Advanced selectors and Info display reuse the shared
vocabulary.

## 2. Crate layout

Keep medium-independent logic out of the `view!`/`update` wiring so it is
unit-testable without a display (DESIGN §10). Proposed `crates/paladin-gtk/src/`:

| File | Responsibility | Tested |
| --- | --- | --- |
| `main.rs` | `adw::Application` bootstrap; init libadwaita; run `AppModel`. | manual |
| `app.rs` | Root relm4 component: `AppModel`, `AppInput`, `CommandOutput`, `view!`, `update`, `update_cmd`. | manual |
| `mode.rs` | `Mode` enum (Encrypt/Decrypt/Info/Verify) + per-mode field visibility rules. | unit |
| `options.rs` | Build `EncryptOptions` + secret material from model state; confirm-match; cipher/KDF/knob assembly; `--name` basename derivation. | unit |
| `fsio.rs` | GTK-native file glue: regular-file check, same-file/self-overwrite check, sibling temp-file finalization (mode `0600` on Unix), best-effort remove, keyfile read (1 B..=1 MiB). | unit + temp-dir |
| `task.rs` | Off-thread crypto runner: orchestrate open → temp output → core call → commit/rollback; owns the cancel flag and progress throttling. | temp-dir |
| `message.rs` | `PalError` → user-facing string; the `Auth` single-condition message (DESIGN §4.4). | unit |
| `info.rs` | Format a `Header` into display rows (same fields/order as CLI `--info`, DESIGN §6.2). | unit |

`fsio.rs` deliberately re-implements the finalize/same-file/keyfile logic that
`paladin-common` provides for the terminal front-ends, because GTK does not
depend on `common` (DESIGN §2.2). The duplication is small, kept pure, and
covered by its own tests.

## 3. Dependencies to add

Per DESIGN §9, add to `crates/paladin-gtk/Cargo.toml` (pin via `cargo add` at
implementation time, latest compatible; `Cargo.lock` records the resolved
versions):

| Crate | Purpose |
| --- | --- |
| `relm4` + `relm4-components` | Elm-architecture GUI over gtk4-rs; file-dialog/worker helpers. |
| `libadwaita` (as `adw`, with the `vNN` feature matching the GTK runtime) | GNOME widgets and styling. |
| `gtk4` (as `gtk`, re-exported by relm4) | Base widgets, `DropTarget`, `ProgressBar`. |
| `anyhow` | Front-end error context (never used to classify core errors). |
| `tempfile` | Sibling temp output before atomic rename. |
| `zeroize` | Hold the captured password in a `Zeroizing<Vec<u8>>` moved into the worker (DESIGN §8.3). |

> The `zeroize` row makes §8.3's "password moved into the worker in a zeroizing
> buffer" explicit; it is not listed in DESIGN §9's table — note it there when
> wiring deps so the table stays accurate.

GTK4 + libadwaita **development** libraries must be present to build (e.g. Fedora:
`gtk4-devel`, `libadwaita-devel`). Capture this in the build notes (§9 below).

## 4. relm4 architecture (DESIGN §8.1, §8.3)

**Model.** `AppModel` holds: `mode: Mode`; `input: Option<PathBuf>`;
`output: Option<PathBuf>` + an `output_edited: bool` so prefill stops overriding
manual edits; `password`/`confirm` (live in the entry widgets, read on `Run`);
`keyfile: Option<PathBuf>`; `keyfile_only: bool` (the `--no-password`
equivalent); Advanced state (`cipher`, `kdf`, per-KDF cost knobs, `name: bool`,
`armor: bool`, `remove_input: bool`, `overwrite_approved: bool`); and run state
(`Idle` / `Running { progress, cancel: Arc<AtomicBool> }` / `Done` / `Canceled` /
`Error`). The model never calls crypto directly.

**Inputs** (`AppInput`): `SetMode`, `SetInputFile(PathBuf)`, `BrowseInput`,
`BrowseOutput`, `SetOutput(String)`, `SetPassword`, `SetConfirm`,
`ToggleKeyfileOnly`, `SetKeyfile(PathBuf)`, `BrowseKeyfile`, `ToggleAdvanced`,
`SetCipher`/`SetKdf`/`SetKnob(...)`, `ToggleName`/`ToggleArmor`/`ToggleRemove`,
`Run`, `Cancel`. Handled in `update`, which mutates the model and re-renders.

**Commands** (`CommandOutput`): `Progress(Progress)` and `Finished(Result<(),
PalError>)`. The crypto runs as a relm4 **command** (`sender.command(...)` driving
`relm4::spawn_blocking`), streaming `Progress` and a final `Finished`, applied in
`update_cmd`. `Info`/`Verify` produce no output file.

**Concurrency & cancellation.** On `Run`, build the `Secret` material and
`EncryptOptions`, move them with a `Zeroizing` password into the command. The
`on_progress` closure (a) reads the shared `Arc<AtomicBool>` cancel flag and
returns `ControlFlow::Break` when set, and (b) sends a throttled `Progress`
(emit only when the percentage bucket changes, to avoid flooding the channel at
64 KiB/chunk). `Cancel` flips the flag; the core returns `PalError::Canceled`;
`task.rs` removes any temp output; `update_cmd` shows a **non-error** canceled
state. A KDF call already in flight may finish before the flag is observed.
`Info`'s `inspect` only reads the bounded header, so it can run inline.

## 5. CLI-concept → GTK realization (parity map)

| CLI concept (DESIGN §6) | GTK realization |
| --- | --- |
| `-f, --force` | Native save-dialog overwrite confirmation; for typed/prefilled existing paths, `Run` confirms before finalizing. No approval ⇒ refuse (DESIGN §8.2). |
| `--remove` | Advanced toggle; best-effort delete input after success; on failure, warn via toast but keep the output and treat the run as successful (DESIGN §6.5). |
| `--name` | Advanced toggle; derive the input **basename** and pass via `EncryptOptions.filename`; core validates and returns `InvalidOptions` for unsafe/over-long names (DESIGN §5.2, §5.4). A basename that is not valid UTF-8 (so it cannot become the `Option<String>` core validates) is surfaced by `options.rs` as a user-facing error toast before `Run` proceeds, never silently dropped (DESIGN §6.4). |
| `-a, --armor` | Encrypt-only toggle; flips the prefilled extension via `default_encrypt_output(.., armor)`. Decrypt/Verify/Info auto-detect. |
| `-k, --keyfile` | Keyfile chooser row (Encrypt/Decrypt/Verify); read via `fsio`, 1 B..=1 MiB, combined with the password. |
| keyfile-only (`--no-password`) | Keyfile-only toggle; allowed only with a keyfile; empty password accepted only here (DESIGN §6.4). |
| password prompt (+ confirm on encrypt) | `adw::PasswordEntryRow` (+ confirm row in Encrypt); confirm must match; empty entry rejected unless keyfile-only. `--password-file`/`--password-env` are CLI-only. |
| stdin/stdout (`-`) | Not supported; path fields are filesystem-only and reject a literal `-` (DESIGN §7.1 note, §14). |
| output defaults / same-file refusal / regular-file checks | `fsio`: prefill from `default_*_output`; reject non-regular input/keyfile; refuse output == input by symlink + hardlink identity, else canonical path (DESIGN §6.5). |
| exit codes | N/A for a GUI; `PalError` maps to toast/dialog text via `message.rs` (Auth ⇒ the single "wrong password or corrupted/tampered file"). |

## 6. Widgets (DESIGN §8.2)

- `adw::ApplicationWindow` + `adw::ToolbarView`/`adw::HeaderBar`.
- `adw::ViewStack` + `ViewSwitcher` for **Encrypt / Decrypt / Info / Verify**.
- `adw::EntryRow` for input/output paths, each with a browse button opening
  `gtk::FileDialog`; the output row shows only for Encrypt/Decrypt and is
  prefilled from `core::default_*_output`.
- `adw::PasswordEntryRow` for password (+ confirm in Encrypt), a keyfile-only
  toggle, and a keyfile chooser row.
- `adw::PreferencesGroup` + `adw::ExpanderRow` for the collapsible Advanced
  section (cipher, KDF, per-KDF knobs, `--name`, armor, remove-input, overwrite).
- `gtk::ProgressBar` + `adw::ToastOverlay` for progress and status/errors;
  Info mode renders metadata rows from `info.rs`.
- `gtk::DropTarget` on the window for drag-and-drop of an input file (sets the
  input path and triggers output prefill).

## 7. Ordered build steps

Follow TDD where there is testable logic: write the `#[test]` first, then the
code (repo convention). After each step run `cargo fmt`, then
`cargo clippy --all-targets --all-features` with zero warnings.

1. **Scaffold + window.** Add deps (§3); replace the `main.rs` stub with an
   `adw::Application` that opens an empty `adw::ApplicationWindow`. Confirm
   `cargo run -p paladin-gtk` shows a window on a GTK4/libadwaita host.
2. **Non-UI glue (tested first).** Implement and unit-test `mode.rs`,
   `message.rs`, `info.rs`, `options.rs`, then `fsio.rs` (with `tempfile`):
   regular-file/same-file checks, `0600` temp finalization + atomic rename,
   best-effort remove, keyfile size caps, confirm-match, basename derivation,
   `PalError`→message mapping, `Header`→rows.
3. **Component skeleton.** Define `AppModel`/`AppInput`/`CommandOutput` and a
   `view!` with the `ViewStack` modes and per-mode visibility (`mode.rs`). No
   crypto yet — wire `SetMode` and field show/hide only.
4. **Input + output + drag-drop.** Browse dialogs (`gtk::FileDialog`),
   `gtk::DropTarget`, and output prefill via `default_*_output` (Decrypt prefill
   calls `inspect` for the stored name; failure is tolerated and surfaced at
   `Run`). Respect `output_edited` so prefill never clobbers manual edits.
5. **Password + keyfile + Advanced.** Password/confirm rows, keyfile-only
   toggle, keyfile chooser, and the `ExpanderRow` with cipher/KDF selectors,
   per-KDF knobs (defaults from `KdfParams::default_for`), `--name`, armor,
   remove-input, and overwrite approval.
6. **Run wiring (the worker).** On `Run`: validate (confirm-match, secret
   non-empty, regular-file input, output ≠ input, overwrite approval); assemble
   `Secret`/`EncryptOptions`; spawn the command running `task.rs`; stream
   throttled `Progress`; on success commit the temp file, optionally
   remove-input, and toast success.
7. **Cancellation + errors.** `Cancel` flips the cancel flag; render the
   non-error canceled state and remove temp output. Map every `PalError` via
   `message.rs` to a toast or error dialog; `Auth` shows the single combined
   condition.
8. **Info + Verify.** Info renders `inspect` output through `info.rs` (no
   password, no output row). Verify runs `verify` on the worker and toasts
   pass/fail.
9. **Polish.** Keyboard/focus order, sensible default focus, disable `Run`
   while running, `adw` styling, app id (e.g. `org.paladin.Gtk`), window icon.
10. **Docs + packaging** (§9).

## 8. Testing strategy (DESIGN §10)

Headless GTK testing is limited, so the strategy is: **push logic out of the UI
and test it; verify the UI by hand.**

- **Automated (no display):** `mode.rs` visibility rules; `options.rs` option
  assembly + confirm-match + basename derivation; `fsio.rs` finalization
  (including Unix `0600`), same-file/self-overwrite refusal, keyfile caps;
  `message.rs` mapping for every `PalError` variant; `info.rs` field/order
  parity with CLI `--info`; `task.rs` encrypt→decrypt round-trip and
  cancel-removes-temp via temp dirs. These run in normal `cargo test`.
- **Shared core tests** already cover crypto/format correctness — GTK does not
  duplicate them.
- **Manual verification checklist** (record in the PR): drag-and-drop;
  browse dialogs; overwrite confirmation honored/refused; live progress gauge;
  Cancel mid-run leaves no partial output and shows a non-error state; mode
  switch shows/hides the correct rows; keyfile-only toggle; wrong-password
  toast wording; Info renders all header fields; oversize/non-regular-file
  rejection.

## 9. Docs & packaging

- `data/org.paladin.Gtk.desktop` — `Name=paladin`, `Exec=paladin-gtk`,
  `Icon=org.paladin.Gtk`, `Categories=Utility;Security;`, `Terminal=false`.
  (Optional, recommended: an AppStream `metainfo.xml` and an SVG icon.)
- Build/run notes: requires GTK4 + libadwaita **dev** libraries; document the
  package names for at least Fedora and Debian/Ubuntu; `cargo run -p
  paladin-gtk` for development. Note Flatpak as a future packaging path.
- Update `README.md` (and `CLAUDE.md` only if a documented command changes) to
  mark the GTK front-end as implemented and link this plan.

---

## Checklist

- [x] Add GTK deps (relm4, relm4-components, libadwaita, gtk4, anyhow, tempfile, zeroize); note `zeroize` in DESIGN §9.
- [x] Scaffold `adw::Application` + empty window; `cargo run -p paladin-gtk` opens it.
- [x] `mode.rs`: `Mode` enum + per-mode field visibility (+ unit tests).
- [x] `message.rs`: `PalError` → user-facing text, incl. `Auth` single condition (+ tests).
- [x] `info.rs`: `Header` → display rows matching CLI `--info` fields/order (+ tests).
- [x] `options.rs`: build `EncryptOptions`/secret material, confirm-match, `--name` basename (+ tests).
- [x] `fsio.rs`: regular-file/same-file checks, `0600` temp finalization, best-effort remove, keyfile caps (+ temp-dir tests).
- [x] relm4 component skeleton: `AppModel`/`AppInput`/`CommandOutput`, `view!`, `ViewStack` modes + visibility.
- [x] Input/output rows + `gtk::FileDialog` browse + `gtk::DropTarget` drag-and-drop + output prefill (respecting manual edits).
- [x] Password/confirm rows, keyfile-only toggle, keyfile chooser, Advanced `ExpanderRow` (cipher/KDF/knobs/name/armor/remove/overwrite).
- [x] `task.rs` worker: off-thread crypto, throttled progress, temp commit/rollback, remove-input warn-but-success.
- [x] Cancellation via shared `AtomicBool`; non-error canceled state; temp cleanup.
- [x] Overwrite approval wired to finalization (GTK `-f` equivalent).
- [x] Info mode (inspect, no password) and Verify mode (worker, pass/fail toast).
- [x] Polish: focus order, disable Run while running, app id, icon, styling.
- [x] Automated tests green (`cargo test -p paladin-gtk`); `cargo fmt` + `cargo clippy` clean.
- [ ] Manual UI verification checklist completed. (Pending manual verification on a graphical session — this environment is headless.)
- [x] Docs: `.desktop` file, GTK build/run notes, README/CLAUDE updates.
- [x] Packaging: `cargo install`/build notes for `paladin-gtk`.
