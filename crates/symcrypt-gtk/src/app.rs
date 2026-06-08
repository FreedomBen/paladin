//! The relm4 `AppModel` component: the libadwaita UI shell. A thin view that
//! gathers input and delegates all logic to the crate's tested modules
//! (`mode`, `options`, `fsio`, `task`, `message`, `info`).
//!
//! This pass implements the component skeleton plus the full view and
//! field/state handling: modes and per-mode visibility, file browse,
//! drag-and-drop, output prefill, and every input control. It also wires the
//! actual crypto execution: Info inspects inline, while Encrypt/Decrypt/Verify
//! run on a background worker (a `spawn_command` blocking task) that streams
//! `Progress` and a terminal `RunSuccess`/`RunError` back as [`CommandOutput`],
//! with cooperative cancellation and an overwrite-confirm dialog.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use adw::prelude::*;
use relm4::prelude::*;
use relm4::{Component, ComponentParts, ComponentSender};
use zeroize::Zeroizing;

use symcrypt_core::{
    default_aescrypt_output, default_decrypt_output, default_encrypt_output, inspect, CipherId,
    EncryptOptions, KdfId, Metadata, Progress, Secret,
};

use crate::fsio::{self, FsError};
use crate::info;
use crate::message;
use crate::mode::{Field, Mode};
use crate::options::{self, KnobInput};
use crate::task::{self, Job, RunError, RunSuccess};

/// The four ciphers/KDFs offered in the Advanced selectors, kept in a stable
/// order so a `ComboRow` selection index maps back to the enum.
const CIPHERS: [CipherId; 2] = [CipherId::Aes256Gcm, CipherId::ChaCha20Poly1305];
const KDFS: [KdfId; 3] = [KdfId::Argon2id, KdfId::Scrypt, KdfId::Pbkdf2];

/// Which KDF cost knob a [`AppInput::SetKnob`] message targets.
#[derive(Debug, Clone, Copy)]
pub enum Knob {
    /// Argon2id memory cost (KiB).
    Argon2Memory,
    /// Argon2id time cost (passes).
    Argon2Time,
    /// Argon2id parallelism (lanes).
    Argon2Parallelism,
    /// scrypt log₂(N).
    ScryptLogN,
    /// scrypt block size `r`.
    ScryptR,
    /// scrypt parallelism `p`.
    ScryptP,
    /// PBKDF2 iteration count.
    Pbkdf2Iterations,
}

/// The run lifecycle. `Idle` at rest; `Running` while a worker operates;
/// terminal `Done`/`Canceled`/`Error` after it reports back.
#[derive(Debug, Clone)]
pub enum RunState {
    /// No operation in flight.
    Idle,
    /// A worker operation is running; `fraction` is its 0.0..=1.0 progress.
    Running {
        /// Current progress fraction for the gauge.
        fraction: f64,
        /// Shared flag the worker observes; setting it cancels the run.
        cancel: Arc<AtomicBool>,
    },
    /// The last operation finished successfully; `String` is a summary.
    Done(String),
    /// The last operation was canceled by the user.
    Canceled,
    /// The last operation failed; `String` is the rendered message.
    Error(String),
}

/// Component model: the full UI state. Logic lives in the tested sibling
/// modules; this struct only mirrors the form so the view can render it.
pub struct AppModel {
    /// The active operation/tab.
    mode: Mode,
    /// The chosen input file, if any.
    input: Option<PathBuf>,
    /// The output file (prefilled unless the user edited it).
    output: Option<PathBuf>,
    /// Whether the user manually edited the output, freezing prefill.
    output_edited: bool,
    /// The chosen keyfile, if any.
    keyfile: Option<PathBuf>,
    /// Whether to use only a keyfile (no password).
    keyfile_only: bool,
    /// Selected AEAD cipher (Encrypt only).
    cipher: CipherId,
    /// Selected KDF (Encrypt only).
    kdf: KdfId,
    /// Per-KDF cost knobs (Encrypt only).
    knobs: KnobInput,
    /// Whether to embed the input basename via `--name`.
    name_enabled: bool,
    /// Whether to ASCII-armor the output.
    armor: bool,
    /// Whether to remove the input after a successful run.
    remove_input: bool,
    /// Whether overwriting an existing output is approved.
    overwrite_approved: bool,
    /// The run lifecycle state.
    run_state: RunState,
    /// The Info pane contents (the rendered header, after a successful Info run).
    info_text: Option<String>,
    /// Toast surface; toasts are emitted via [`adw::ToastOverlay::add_toast`].
    toast_overlay: adw::ToastOverlay,
}

/// Messages handled in [`Component::update`].
#[derive(Debug)]
pub enum AppInput {
    /// Switch the active operation/tab.
    SetMode(Mode),
    /// Open the input file chooser.
    BrowseInput,
    /// Set the input path (from the chooser or a drag-and-drop).
    SetInput(PathBuf),
    /// Open the output file chooser.
    BrowseOutput,
    /// Set the output path from the editable field (marks it user-edited).
    SetOutput(String),
    /// Toggle keyfile-only (no password) mode.
    ToggleKeyfileOnly(bool),
    /// Open the keyfile chooser.
    BrowseKeyfile,
    /// Set the keyfile path.
    SetKeyfile(PathBuf),
    /// Clear the chosen keyfile.
    ClearKeyfile,
    /// Set the AEAD cipher.
    SetCipher(CipherId),
    /// Set the KDF.
    SetKdf(KdfId),
    /// Set one KDF cost knob.
    SetKnob(Knob, u32),
    /// Toggle the `--name` (embed basename) switch.
    ToggleName(bool),
    /// Toggle ASCII armor.
    ToggleArmor(bool),
    /// Toggle remove-input-after-success.
    ToggleRemove(bool),
    /// Toggle overwrite approval.
    ToggleOverwrite(bool),
    /// Start the active operation (Info inline; others on the worker).
    Run,
    /// Cancel the running worker operation.
    Cancel,
}

/// Messages produced by the worker command and handled in
/// [`Component::update_cmd`].
pub enum CommandOutput {
    /// A progress report from the worker.
    Progress(Progress),
    /// The terminal result of the worker operation.
    Finished(Result<RunSuccess, RunError>),
}

// relm4's `Component` requires `CommandOutput: Debug`. `RunSuccess` is not
// `Debug`, so format it by hand from its public field.
impl std::fmt::Debug for CommandOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandOutput::Progress(p) => f.debug_tuple("Progress").field(p).finish(),
            CommandOutput::Finished(Ok(s)) => f
                .debug_struct("Finished::Ok")
                .field("remove_warning", &s.remove_warning)
                .finish(),
            CommandOutput::Finished(Err(e)) => f.debug_tuple("Finished::Err").field(e).finish(),
        }
    }
}

impl AppModel {
    /// Whether `field`'s row should currently be visible (mode-driven).
    fn shows(&self, field: Field) -> bool {
        self.mode.shows(field)
    }

    /// Whether the KDF cost rows for `kdf` should be visible: only in Encrypt,
    /// and only for the currently-selected KDF.
    fn shows_kdf(&self, kdf: KdfId) -> bool {
        self.shows(Field::KdfKnobs) && self.kdf == kdf
    }

    /// The output path as a display string for the editable row.
    fn output_text(&self) -> String {
        self.output
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    /// The keyfile path as a display string (empty when none chosen).
    fn keyfile_text(&self) -> String {
        self.keyfile
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    /// The input path as a display subtitle (a hint when none chosen).
    fn input_text(&self) -> String {
        self.input
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "No file selected".to_owned())
    }

    /// Push a transient toast onto the overlay.
    fn toast(&self, message: &str) {
        self.toast_overlay
            .add_toast(adw::Toast::builder().title(message).build());
    }

    /// Recompute the prefilled output path from the current input and mode,
    /// unless the user has manually edited the output. Decrypt inspects the
    /// header to derive the plaintext name; an unreadable header leaves the
    /// output blank with a hint rather than blocking.
    fn refresh_output(&mut self) {
        if self.output_edited || !self.mode.needs_output() {
            return;
        }
        let Some(input) = self.input.clone() else {
            return;
        };
        match self.mode {
            Mode::Encrypt => {
                self.output = Some(default_encrypt_output(&input, self.armor));
            }
            Mode::Decrypt => match Self::inspect_path(&input) {
                Ok(meta) => {
                    let out = match meta {
                        Metadata::Symcrypt(h) => default_decrypt_output(&input, &h),
                        Metadata::AesCrypt(_) => default_aescrypt_output(&input),
                    };
                    self.output = Some(out);
                }
                Err(_) => {
                    self.output = None;
                    self.toast("Could not read header to prefill output name");
                }
            },
            Mode::Info | Mode::Verify => {}
        }
    }

    /// Open `path` and run the core `inspect`, returning its metadata (symcrypt
    /// or AES Crypt).
    fn inspect_path(path: &Path) -> Result<Metadata, ()> {
        let file = std::fs::File::open(path).map_err(|_| ())?;
        inspect(std::io::BufReader::new(file)).map_err(|_| ())
    }

    /// Refresh the Info header pane to match the current input. In Info mode
    /// with an input set, inspect it inline and render the header (toasting on
    /// error); otherwise clear any stale header text. A no-op outside Info so
    /// the pane is never populated for the crypto modes.
    fn refresh_info(&mut self) {
        if self.mode != Mode::Info {
            return;
        }
        match self.input.clone() {
            Some(input) => match Self::open_and_inspect(&input) {
                Ok(meta) => self.info_text = Some(info::metadata_text(&meta)),
                Err(e) => {
                    self.info_text = None;
                    self.toast(&message::user_message(&e));
                }
            },
            None => self.info_text = None,
        }
    }
}

/// Open a modern [`gtk::FileDialog`] (GTK 4.10+) transient for `parent`,
/// forwarding the chosen path back through `sender` as `to_msg(path)`.
/// Cancellation (or any selection error) is silently ignored — no path is set
/// and no toast is shown.
///
/// `save` picks the Save variant (a writable target with an editable name) for
/// output paths; otherwise the Open variant picks an existing file. The async
/// callback owns its `sender`; GTK keeps the dialog alive until it resolves.
fn pick_file<F>(
    parent: &adw::ApplicationWindow,
    sender: &ComponentSender<AppModel>,
    title: &str,
    save: bool,
    to_msg: F,
) where
    F: Fn(PathBuf) -> AppInput + 'static,
{
    let dialog = gtk::FileDialog::builder().title(title).modal(true).build();
    let sender = sender.clone();
    let on_result = move |result: Result<gtk::gio::File, gtk::glib::Error>| {
        // Ignore the user-cancel error; only act on a real path.
        if let Ok(Some(path)) = result.map(|f| f.path()) {
            sender.input(to_msg(path));
        }
    };
    if save {
        dialog.save(Some(parent), gtk::gio::Cancellable::NONE, on_result);
    } else {
        dialog.open(Some(parent), gtk::gio::Cancellable::NONE, on_result);
    }
}

#[relm4::component(pub)]
impl Component for AppModel {
    type Init = ();
    type Input = AppInput;
    type Output = ();
    type CommandOutput = CommandOutput;

    view! {
        adw::ApplicationWindow {
            set_title: Some("symcrypt"),
            set_icon_name: Some(crate::APP_ID),
            set_default_width: 560,
            set_default_height: 620,

            // Drag-and-drop a file anywhere on the window to set the input.
            add_controller = gtk::DropTarget {
                set_actions: gtk::gdk::DragAction::COPY,
                set_types: &[gtk::gio::File::static_type()],
                connect_drop[sender] => move |_, value, _, _| {
                    if let Ok(file) = value.get::<gtk::gio::File>() {
                        if let Some(path) = file.path() {
                            sender.input(AppInput::SetInput(path));
                            return true;
                        }
                    }
                    false
                },
            },

            adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &adw::ViewSwitcher {
                        set_policy: adw::ViewSwitcherPolicy::Wide,
                        set_stack: Some(&mode_stack),
                    },
                },

                #[wrap(Some)]
                #[local_ref]
                set_content = &toast_overlay -> adw::ToastOverlay {
                    set_vexpand: true,

                    gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,

                        // Hidden stack: pages are tab anchors for the switcher;
                        // the visible form below is shared across modes.
                        #[name = "mode_stack"]
                        adw::ViewStack {
                            set_visible: false,
                        },

                        #[name = "progress_bar"]
                        gtk::ProgressBar {
                            set_margin_start: 12,
                            set_margin_end: 12,
                            #[watch]
                            set_visible: matches!(model.run_state, RunState::Running { .. }),
                            #[watch]
                            set_fraction: match model.run_state {
                                RunState::Running { fraction, .. } => fraction,
                                _ => 0.0,
                            },
                        },

                        gtk::ScrolledWindow {
                            set_vexpand: true,
                            set_hscrollbar_policy: gtk::PolicyType::Never,

                            adw::Clamp {
                                set_margin_all: 12,

                                gtk::Box {
                                    set_orientation: gtk::Orientation::Vertical,
                                    set_spacing: 18,

                                    // --- Files ---------------------------------
                                    adw::PreferencesGroup {
                                        set_title: "Files",

                                        adw::ActionRow {
                                            set_title: "Input file",
                                            #[watch]
                                            set_subtitle: &model.input_text(),
                                            #[name = "input_browse_button"]
                                            add_suffix = &gtk::Button {
                                                set_label: "Browse…",
                                                set_valign: gtk::Align::Center,
                                                connect_clicked => AppInput::BrowseInput,
                                            },
                                        },

                                        #[name = "output_row"]
                                        adw::EntryRow {
                                            set_title: "Output file",
                                            #[watch]
                                            set_visible: model.shows(Field::Output),
                                            #[watch]
                                            #[block_signal(output_changed)]
                                            set_text: &model.output_text(),
                                            connect_changed[sender] => move |row| {
                                                sender.input(AppInput::SetOutput(row.text().into()));
                                            } @output_changed,
                                            add_suffix = &gtk::Button {
                                                set_label: "Browse…",
                                                set_valign: gtk::Align::Center,
                                                connect_clicked => AppInput::BrowseOutput,
                                            },
                                        },
                                    },

                                    // --- Secret --------------------------------
                                    adw::PreferencesGroup {
                                        set_title: "Secret",
                                        #[watch]
                                        set_visible: model.shows(Field::Password)
                                            || model.shows(Field::Keyfile),

                                        #[name = "password_row"]
                                        adw::PasswordEntryRow {
                                            set_title: "Password",
                                            #[watch]
                                            set_visible: model.shows(Field::Password)
                                                && !model.keyfile_only,
                                        },

                                        #[name = "confirm_row"]
                                        adw::PasswordEntryRow {
                                            set_title: "Confirm password",
                                            #[watch]
                                            set_visible: model.shows(Field::ConfirmPassword)
                                                && !model.keyfile_only,
                                        },

                                        adw::SwitchRow {
                                            set_title: "Keyfile only",
                                            set_subtitle: "Use a keyfile instead of a password",
                                            #[watch]
                                            set_visible: model.shows(Field::KeyfileOnly),
                                            #[watch]
                                            #[block_signal(keyfile_only_toggled)]
                                            set_active: model.keyfile_only,
                                            connect_active_notify[sender] => move |row| {
                                                sender.input(AppInput::ToggleKeyfileOnly(row.is_active()));
                                            } @keyfile_only_toggled,
                                        },

                                        adw::ActionRow {
                                            set_title: "Keyfile",
                                            #[watch]
                                            set_visible: model.shows(Field::Keyfile),
                                            #[watch]
                                            set_subtitle: &model.keyfile_text(),
                                            add_suffix = &gtk::Button {
                                                set_label: "Browse…",
                                                set_valign: gtk::Align::Center,
                                                connect_clicked => AppInput::BrowseKeyfile,
                                            },
                                            add_suffix = &gtk::Button {
                                                set_icon_name: "edit-clear-symbolic",
                                                set_valign: gtk::Align::Center,
                                                set_tooltip_text: Some("Clear keyfile"),
                                                connect_clicked => AppInput::ClearKeyfile,
                                            },
                                        },
                                    },

                                    // --- Advanced (Encrypt only) ---------------
                                    adw::PreferencesGroup {
                                        #[watch]
                                        set_visible: model.shows(Field::Cipher),

                                        adw::ExpanderRow {
                                            set_title: "Advanced",
                                            set_subtitle: "Cipher, KDF, and output options",

                                            #[name = "cipher_row"]
                                            add_row = &adw::ComboRow {
                                                set_title: "Cipher",
                                                set_model: Some(&gtk::StringList::new(&[
                                                    CipherId::Aes256Gcm.to_string().as_str(),
                                                    CipherId::ChaCha20Poly1305.to_string().as_str(),
                                                ])),
                                                connect_selected_notify[sender] => move |row| {
                                                    if let Some(c) = CIPHERS.get(row.selected() as usize) {
                                                        sender.input(AppInput::SetCipher(*c));
                                                    }
                                                },
                                            },

                                            #[name = "kdf_row"]
                                            add_row = &adw::ComboRow {
                                                set_title: "KDF",
                                                set_model: Some(&gtk::StringList::new(&[
                                                    KdfId::Argon2id.to_string().as_str(),
                                                    KdfId::Scrypt.to_string().as_str(),
                                                    KdfId::Pbkdf2.to_string().as_str(),
                                                ])),
                                                connect_selected_notify[sender] => move |row| {
                                                    if let Some(k) = KDFS.get(row.selected() as usize) {
                                                        sender.input(AppInput::SetKdf(*k));
                                                    }
                                                },
                                            },

                                            // Argon2id knobs
                                            add_row = &adw::SpinRow::with_range(8.0, 4_194_304.0, 1024.0) {
                                                set_title: "Argon2 memory (KiB)",
                                                #[watch]
                                                set_visible: model.shows_kdf(KdfId::Argon2id),
                                                set_value: model.knobs.argon2_memory_kib as f64,
                                                connect_value_notify[sender] => move |row| {
                                                    sender.input(AppInput::SetKnob(
                                                        Knob::Argon2Memory, row.value() as u32));
                                                },
                                            },
                                            add_row = &adw::SpinRow::with_range(1.0, 4_294_967_295.0, 1.0) {
                                                set_title: "Argon2 time cost",
                                                #[watch]
                                                set_visible: model.shows_kdf(KdfId::Argon2id),
                                                set_value: model.knobs.argon2_time_cost as f64,
                                                connect_value_notify[sender] => move |row| {
                                                    sender.input(AppInput::SetKnob(
                                                        Knob::Argon2Time, row.value() as u32));
                                                },
                                            },
                                            add_row = &adw::SpinRow::with_range(1.0, 16_777_215.0, 1.0) {
                                                set_title: "Argon2 parallelism",
                                                #[watch]
                                                set_visible: model.shows_kdf(KdfId::Argon2id),
                                                set_value: model.knobs.argon2_parallelism as f64,
                                                connect_value_notify[sender] => move |row| {
                                                    sender.input(AppInput::SetKnob(
                                                        Knob::Argon2Parallelism, row.value() as u32));
                                                },
                                            },

                                            // scrypt knobs
                                            add_row = &adw::SpinRow::with_range(1.0, 63.0, 1.0) {
                                                set_title: "scrypt log₂(N)",
                                                #[watch]
                                                set_visible: model.shows_kdf(KdfId::Scrypt),
                                                set_value: model.knobs.scrypt_log_n as f64,
                                                connect_value_notify[sender] => move |row| {
                                                    sender.input(AppInput::SetKnob(
                                                        Knob::ScryptLogN, row.value() as u32));
                                                },
                                            },
                                            add_row = &adw::SpinRow::with_range(1.0, 4_294_967_295.0, 1.0) {
                                                set_title: "scrypt r",
                                                #[watch]
                                                set_visible: model.shows_kdf(KdfId::Scrypt),
                                                set_value: model.knobs.scrypt_r as f64,
                                                connect_value_notify[sender] => move |row| {
                                                    sender.input(AppInput::SetKnob(
                                                        Knob::ScryptR, row.value() as u32));
                                                },
                                            },
                                            add_row = &adw::SpinRow::with_range(1.0, 4_294_967_295.0, 1.0) {
                                                set_title: "scrypt p",
                                                #[watch]
                                                set_visible: model.shows_kdf(KdfId::Scrypt),
                                                set_value: model.knobs.scrypt_p as f64,
                                                connect_value_notify[sender] => move |row| {
                                                    sender.input(AppInput::SetKnob(
                                                        Knob::ScryptP, row.value() as u32));
                                                },
                                            },

                                            // PBKDF2 knob
                                            add_row = &adw::SpinRow::with_range(1.0, 4_294_967_295.0, 10_000.0) {
                                                set_title: "PBKDF2 iterations",
                                                #[watch]
                                                set_visible: model.shows_kdf(KdfId::Pbkdf2),
                                                set_value: model.knobs.pbkdf2_iterations as f64,
                                                connect_value_notify[sender] => move |row| {
                                                    sender.input(AppInput::SetKnob(
                                                        Knob::Pbkdf2Iterations, row.value() as u32));
                                                },
                                            },

                                            #[name = "name_switch"]
                                            add_row = &adw::SwitchRow {
                                                set_title: "Embed filename",
                                                set_subtitle: "Store the input's name in the header",
                                                #[watch]
                                                #[block_signal(name_toggled)]
                                                set_active: model.name_enabled,
                                                connect_active_notify[sender] => move |row| {
                                                    sender.input(AppInput::ToggleName(row.is_active()));
                                                } @name_toggled,
                                            },

                                            add_row = &adw::SwitchRow {
                                                set_title: "ASCII armor",
                                                set_subtitle: "Wrap output in printable text",
                                                #[watch]
                                                set_active: model.armor,
                                                connect_active_notify[sender] => move |row| {
                                                    sender.input(AppInput::ToggleArmor(row.is_active()));
                                                },
                                            },
                                        },
                                    },

                                    // --- Output handling -----------------------
                                    adw::PreferencesGroup {
                                        #[watch]
                                        set_visible: model.shows(Field::RemoveInput)
                                            || model.shows(Field::OverwriteApproval),

                                        adw::SwitchRow {
                                            set_title: "Remove input on success",
                                            #[watch]
                                            set_visible: model.shows(Field::RemoveInput),
                                            #[watch]
                                            set_active: model.remove_input,
                                            connect_active_notify[sender] => move |row| {
                                                sender.input(AppInput::ToggleRemove(row.is_active()));
                                            },
                                        },

                                        adw::SwitchRow {
                                            set_title: "Overwrite existing output",
                                            #[watch]
                                            set_visible: model.shows(Field::OverwriteApproval),
                                            #[watch]
                                            set_active: model.overwrite_approved,
                                            connect_active_notify[sender] => move |row| {
                                                sender.input(AppInput::ToggleOverwrite(row.is_active()));
                                            },
                                        },
                                    },

                                    // --- Info results (Info only) --------------
                                    adw::PreferencesGroup {
                                        set_title: "Header",
                                        #[watch]
                                        set_visible: model.shows(Field::InfoResults),

                                        gtk::Label {
                                            add_css_class: "monospace",
                                            set_xalign: 0.0,
                                            set_selectable: true,
                                            set_wrap: true,
                                            #[watch]
                                            set_label: model.info_text.as_deref().unwrap_or(""),
                                        },
                                    },

                                    // --- Action buttons ------------------------
                                    gtk::Box {
                                        set_halign: gtk::Align::End,
                                        set_spacing: 6,

                                        gtk::Button {
                                            set_label: "Cancel",
                                            #[watch]
                                            set_visible: matches!(
                                                model.run_state, RunState::Running { .. }),
                                            connect_clicked => AppInput::Cancel,
                                        },

                                        gtk::Button {
                                            add_css_class: "suggested-action",
                                            #[watch]
                                            set_label: model.mode.title(),
                                            #[watch]
                                            set_sensitive: matches!(model.run_state, RunState::Idle)
                                                && model.input.is_some(),
                                            connect_clicked => AppInput::Run,
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
    }

    fn init(
        _init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = AppModel {
            mode: Mode::Encrypt,
            input: None,
            output: None,
            output_edited: false,
            keyfile: None,
            keyfile_only: false,
            cipher: CipherId::Aes256Gcm,
            kdf: KdfId::Argon2id,
            knobs: KnobInput::default(),
            name_enabled: false,
            armor: false,
            remove_input: false,
            overwrite_approved: false,
            run_state: RunState::Idle,
            info_text: None,
            toast_overlay: adw::ToastOverlay::new(),
        };

        let toast_overlay = model.toast_overlay.clone();
        let widgets = view_output!();

        // One hidden page per mode; the switcher renders them as tabs and the
        // visible-child name maps back to a `Mode` for `SetMode`.
        for mode in Mode::all() {
            widgets
                .mode_stack
                .add_titled(&gtk::Box::default(), Some(mode.title()), mode.title());
        }
        widgets.mode_stack.connect_visible_child_notify({
            let sender = sender.clone();
            move |stack| {
                if let Some(name) = stack.visible_child_name() {
                    if let Some(mode) = Mode::all().into_iter().find(|m| m.title() == name) {
                        sender.input(AppInput::SetMode(mode));
                    }
                }
            }
        });

        // Land keyboard focus on the input browse button so the form is usable
        // without reaching for the mouse first.
        widgets.input_browse_button.grab_focus();

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>, root: &Self::Root) {
        match msg {
            AppInput::SetMode(mode) => {
                self.mode = mode;
                // Re-prefill when entering a file-producing mode, and auto-inspect
                // when entering Info so the header pane is populated immediately.
                self.refresh_output();
                self.refresh_info();
            }
            AppInput::BrowseInput => {
                pick_file(
                    root,
                    &sender,
                    "Select input file",
                    false,
                    AppInput::SetInput,
                );
            }
            AppInput::SetInput(path) => {
                self.input = Some(path);
                self.output_edited = false;
                self.refresh_output();
                // Refresh the Info pane so it never shows stale header data when
                // the input changes (a no-op outside Info mode).
                self.refresh_info();
            }
            AppInput::BrowseOutput => {
                pick_file(root, &sender, "Select output file", true, |p| {
                    AppInput::SetOutput(p.display().to_string())
                });
            }
            AppInput::SetOutput(text) => {
                if text.is_empty() {
                    self.output = None;
                } else {
                    self.output = Some(PathBuf::from(text));
                }
                self.output_edited = true;
            }
            AppInput::ToggleKeyfileOnly(on) => self.keyfile_only = on,
            AppInput::BrowseKeyfile => {
                pick_file(root, &sender, "Select keyfile", false, AppInput::SetKeyfile);
            }
            AppInput::SetKeyfile(path) => self.keyfile = Some(path),
            AppInput::ClearKeyfile => self.keyfile = None,
            AppInput::SetCipher(cipher) => self.cipher = cipher,
            AppInput::SetKdf(kdf) => self.kdf = kdf,
            AppInput::SetKnob(knob, value) => self.set_knob(knob, value),
            AppInput::ToggleName(on) => {
                if on {
                    // Pre-check the basename so an unembeddable name is rejected
                    // up front rather than at Run time.
                    match self.input.as_deref().map(options::derive_name) {
                        Some(Err(e)) => {
                            self.toast(&e.to_string());
                            self.name_enabled = false;
                        }
                        _ => self.name_enabled = true,
                    }
                } else {
                    self.name_enabled = false;
                }
            }
            AppInput::ToggleArmor(on) => {
                self.armor = on;
                // The default encrypt extension depends on armor.
                self.refresh_output();
            }
            AppInput::ToggleRemove(on) => self.remove_input = on,
            AppInput::ToggleOverwrite(on) => self.overwrite_approved = on,
            AppInput::Run => {
                // `Run` needs the password widgets, so it is handled in
                // `update_with_view` (which has `&mut Widgets`). Reaching here
                // would mean the override was removed; do nothing rather than
                // silently misbehave.
            }
            AppInput::Cancel => {
                // Flip the shared flag the worker observes; the core returns
                // `SymError::Canceled` and `run_job` rolls back its temp. Stay
                // `Running` until the worker reports `Finished`.
                if let RunState::Running { cancel, .. } = &self.run_state {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
        }
    }

    /// relm4 calls this for every input; we intercept [`AppInput::Run`] here
    /// because it must read the password/confirm entry widgets, then refresh
    /// the view. All other inputs delegate to [`Self::update`].
    fn update_with_view(
        &mut self,
        widgets: &mut Self::Widgets,
        msg: Self::Input,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match msg {
            AppInput::Run => self.start_run(widgets, &sender, root),
            other => self.update(other, sender.clone(), root),
        }
        self.update_view(widgets, sender);
    }

    fn update_cmd(
        &mut self,
        msg: Self::CommandOutput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match msg {
            CommandOutput::Progress(p) => {
                let fraction = p
                    .total
                    .map(|t| {
                        if t == 0 {
                            1.0
                        } else {
                            p.done as f64 / t as f64
                        }
                    })
                    .unwrap_or(0.0);
                // Keep the existing cancel handle; only advance the gauge.
                if let RunState::Running { cancel, .. } = &self.run_state {
                    let cancel = cancel.clone();
                    self.run_state = RunState::Running { fraction, cancel };
                }
            }
            CommandOutput::Finished(Ok(success)) => {
                // The op succeeded; a remove failure is a non-fatal warning.
                self.run_state = RunState::Done(self.success_summary());
                self.toast(&self.success_summary());
                if let Some(warning) = success.remove_warning {
                    self.toast(&warning);
                }
                // Re-arm the overwrite gate so a later run re-confirms.
                self.overwrite_approved = false;
            }
            CommandOutput::Finished(Err(RunError::Core(ce))) if message::is_user_cancel(&ce) => {
                // A deliberate cancel is a neutral state, not a failure.
                self.run_state = RunState::Canceled;
                self.toast("Canceled");
                self.overwrite_approved = false;
            }
            CommandOutput::Finished(Err(RunError::Fs(FsError::OutputExists(path)))) => {
                // Do not toast: ask the user to confirm the overwrite, then
                // re-run with approval (or reset to Idle on cancel).
                self.run_state = RunState::Idle;
                self.confirm_overwrite(root, &sender, &path);
            }
            CommandOutput::Finished(Err(RunError::Core(ce))) => {
                let text = message::user_message(&ce);
                self.run_state = RunState::Error(text.clone());
                self.toast(&text);
                self.overwrite_approved = false;
            }
            CommandOutput::Finished(Err(RunError::Fs(fe))) => {
                let text = fe.to_string();
                self.run_state = RunState::Error(text.clone());
                self.toast(&text);
                self.overwrite_approved = false;
            }
        }
    }
}

impl AppModel {
    /// Handle [`AppInput::Run`]. Info inspects the header inline (no password,
    /// no worker); Encrypt/Decrypt/Verify validate the secret, build a [`Job`],
    /// and dispatch it to a background blocking task that streams progress and a
    /// terminal result back as [`CommandOutput`]. Every early return leaves the
    /// form interactive (the run never starts) after an explanatory toast.
    fn start_run(
        &mut self,
        widgets: &mut AppModelWidgets,
        sender: &ComponentSender<Self>,
        _root: &<Self as Component>::Root,
    ) {
        // --- Info: inline inspect, no password, no worker -------------------
        if !self.mode.runs_on_worker() {
            let Some(input) = self.input.clone() else {
                self.toast("Choose a file to inspect first.");
                return;
            };
            match Self::open_and_inspect(&input) {
                Ok(meta) => self.info_text = Some(info::metadata_text(&meta)),
                Err(e) => self.toast(&message::user_message(&e)),
            }
            return;
        }

        // --- Encrypt / Decrypt / Verify: validate then dispatch -------------
        let Some(input) = self.input.clone() else {
            self.toast("Choose an input file first.");
            return;
        };

        // Read the password (and, in Encrypt, the confirmation) into zeroizing
        // buffers. Never logged; moved into the worker.
        let password = Zeroizing::new(widgets.password_row.text().as_bytes().to_vec());
        let confirm = (self.mode == Mode::Encrypt)
            .then(|| Zeroizing::new(widgets.confirm_row.text().as_bytes().to_vec()));

        // Read the keyfile bytes (kept in the zeroizing buffer it returns).
        let keyfile_bytes = match &self.keyfile {
            Some(path) => match fsio::read_keyfile(path) {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    self.toast(&e.to_string());
                    return;
                }
            },
            None => None,
        };

        let confirm_arg: Option<&[u8]> = confirm.as_ref().map(|b| b.as_slice());
        let keyfile_arg: Option<&[u8]> = keyfile_bytes.as_ref().map(|b| b.as_slice());

        if let Err(e) =
            options::validate_secret(&password, confirm_arg, keyfile_arg, self.keyfile_only)
        {
            self.toast(&e.to_string());
            return;
        }

        let secret = match Secret::new(&password, keyfile_arg) {
            Ok(secret) => secret,
            Err(e) => {
                self.toast(&message::user_message(&e));
                return;
            }
        };

        // Encrypt needs full options; Decrypt/Verify ignore them.
        let options = if self.mode == Mode::Encrypt {
            match options::build_encrypt_options(
                &input,
                self.cipher,
                self.kdf,
                &self.knobs,
                self.name_enabled,
                self.armor,
            ) {
                Ok(opts) => opts,
                Err(e) => {
                    self.toast(&e.to_string());
                    return;
                }
            }
        } else {
            EncryptOptions::default()
        };

        let output = if self.mode.needs_output() {
            self.output.clone()
        } else {
            None
        };

        let job = Job {
            mode: self.mode,
            input,
            output,
            secret,
            options,
            overwrite_approved: self.overwrite_approved,
            remove_input: self.remove_input,
        };

        // Shared cancel flag: a clone lives in the state for `Cancel` to flip;
        // the worker borrows the moved copy.
        let cancel = Arc::new(AtomicBool::new(false));
        self.run_state = RunState::Running {
            fraction: 0.0,
            cancel: cancel.clone(),
        };

        // Crypto is CPU-bound, so run it on relm4's blocking pool. The `Job`
        // (with its `Secret` and zeroizing buffers) moves into the task.
        sender.spawn_command(move |out| {
            let result = task::run_job(job, &cancel, |p| {
                let _ = out.send(CommandOutput::Progress(p));
            });
            let _ = out.send(CommandOutput::Finished(result));
        });
    }

    /// Open `path` and run the core `inspect`, surfacing the [`SymError`] so the
    /// caller can render it via [`message::user_message`].
    fn open_and_inspect(path: &Path) -> Result<Metadata, symcrypt_core::SymError> {
        let file = std::fs::File::open(path).map_err(symcrypt_core::SymError::Io)?;
        inspect(std::io::BufReader::new(file))
    }

    /// A short per-mode success line for the toast and `Done` summary.
    fn success_summary(&self) -> String {
        let name = self
            .input
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_owned());
        match self.mode {
            Mode::Encrypt => format!("Encrypted {name}"),
            Mode::Decrypt => format!("Decrypted {name}"),
            Mode::Verify => "Integrity verified".to_owned(),
            // Info never runs on the worker, so it never reaches here.
            Mode::Info => "Done".to_owned(),
        }
    }

    /// Pop an overwrite-confirm dialog for an existing output. On confirm,
    /// approve the overwrite and re-run; on cancel, stay idle. Uses
    /// `adw::AlertDialog` (libadwaita 1.5+); it presents over `root` and closes
    /// itself once a response fires.
    fn confirm_overwrite(
        &self,
        root: &<Self as Component>::Root,
        sender: &ComponentSender<Self>,
        path: &Path,
    ) {
        let dialog = adw::AlertDialog::new(
            Some("Overwrite file?"),
            Some(&format!("{} already exists.", path.display())),
        );
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("overwrite", "Overwrite");
        dialog.set_response_appearance("overwrite", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let sender = sender.clone();
        dialog.connect_response(None, move |_dialog, response| {
            if response == "overwrite" {
                sender.input(AppInput::ToggleOverwrite(true));
                sender.input(AppInput::Run);
            }
            // `AlertDialog` closes itself once a response is chosen.
        });
        dialog.present(Some(root));
    }

    /// Apply a single KDF knob value to the model.
    fn set_knob(&mut self, knob: Knob, value: u32) {
        match knob {
            Knob::Argon2Memory => self.knobs.argon2_memory_kib = value,
            Knob::Argon2Time => self.knobs.argon2_time_cost = value,
            Knob::Argon2Parallelism => self.knobs.argon2_parallelism = value,
            Knob::ScryptLogN => self.knobs.scrypt_log_n = value,
            Knob::ScryptR => self.knobs.scrypt_r = value,
            Knob::ScryptP => self.knobs.scrypt_p = value,
            Knob::Pbkdf2Iterations => self.knobs.pbkdf2_iterations = value,
        }
    }
}
