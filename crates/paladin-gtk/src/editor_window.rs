//! The editor window relm4 component (DESIGN §8.4): one independent
//! `adw::Window` per opened file (or new note), owning the text buffer, the
//! dirty flag, and the session secret. It is a thin view — save-option
//! derivation lives in [`editor::SaveSource`] and the crypto in
//! [`task::save_from_editor`], both tested without a display.
//!
//! Lifecycle: the window is spawned from an [`EditorSeed`] (opened file) or
//! nothing (new note). Save re-encrypts the buffer to the backing path; Save
//! As re-targets it. An AES Crypt source's first save asks for migration
//! confirmation; a new note's first save asks for a target and a password.
//! Closing with unsaved changes asks Save / Discard / Cancel. When the window
//! closes, the component reports [`EditorOutput::Closed`] and the app drops
//! its controller, dropping (and zeroizing) the session secret.

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use adw::prelude::*;
use relm4::prelude::*;
use relm4::{Component, ComponentParts, ComponentSender};
use zeroize::Zeroizing;

use paladin_core::{EncryptOptions, Secret};

use crate::editor::SaveSource;
use crate::message;
use crate::options;
use crate::task::{self, EditorSeed, RunError};

/// What the app hands a new editor component.
pub struct EditorInit {
    /// The app-side registry key, echoed back in [`EditorOutput::Closed`].
    pub id: u64,
    /// The opened file's seed, or `None` for a new note.
    pub seed: Option<EditorSeed>,
}

/// Messages handled in `update`.
pub enum EditorInput {
    /// Save to the backing path (Ctrl+S / the Save button).
    Save,
    /// Pick a new target, then save to it.
    SaveAs,
    /// A save target was chosen in the file dialog.
    TargetChosen(PathBuf),
    /// The user confirmed the AES Crypt → paladin migration.
    MigrationConfirmed,
    /// A new note's first-save password entry (contents never logged).
    PasswordProvided {
        /// The password bytes.
        password: Zeroizing<Vec<u8>>,
        /// The confirmation entry's bytes.
        confirm: Zeroizing<Vec<u8>>,
    },
    /// The buffer's modified flag flipped.
    ModifiedChanged(bool),
    /// The window's close button was pressed.
    CloseRequested,
    /// The unsaved-changes dialog chose Discard.
    DiscardAndClose,
    /// The unsaved-changes dialog chose Save (close follows a successful save).
    SaveThenClose,
}

// Manual Debug so password material is never formatted.
impl fmt::Debug for EditorInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditorInput::Save => f.write_str("Save"),
            EditorInput::SaveAs => f.write_str("SaveAs"),
            EditorInput::TargetChosen(p) => f.debug_tuple("TargetChosen").field(p).finish(),
            EditorInput::MigrationConfirmed => f.write_str("MigrationConfirmed"),
            EditorInput::PasswordProvided { .. } => f.write_str("PasswordProvided(redacted)"),
            EditorInput::ModifiedChanged(m) => f.debug_tuple("ModifiedChanged").field(m).finish(),
            EditorInput::CloseRequested => f.write_str("CloseRequested"),
            EditorInput::DiscardAndClose => f.write_str("DiscardAndClose"),
            EditorInput::SaveThenClose => f.write_str("SaveThenClose"),
        }
    }
}

/// The worker's terminal message: the options actually written on success (fed
/// back into [`SaveSource::saved`]), or the error to render.
#[derive(Debug)]
pub enum EditorCmd {
    /// The save finished.
    SaveFinished(Result<EncryptOptions, RunError>),
}

/// Messages the app receives.
#[derive(Debug)]
pub enum EditorOutput {
    /// The window closed; the app drops the controller (and with it the
    /// session secret).
    Closed(u64),
}

/// Component model. See the module docs for the lifecycle.
pub struct EditorWindow {
    /// Registry key echoed in [`EditorOutput::Closed`].
    id: u64,
    /// The backing file; `None` until a new note's first save chooses one.
    path: Option<PathBuf>,
    /// Save-option derivation rule (DESIGN §8.4).
    source: SaveSource,
    /// Armor layer recorded at open; saves re-armor in kind.
    armored: bool,
    /// Session secret; `None` until a new note's first save sets one. `Arc`
    /// because each save's worker borrows it concurrently with the model.
    secret: Option<Arc<Secret>>,
    /// The buffer backing the `TextView` (undo enabled).
    buffer: gtk::TextBuffer,
    /// Whether the buffer has unsaved changes (mirrors the buffer's flag).
    dirty: bool,
    /// Whether a save worker is in flight (Save/Save As are disabled).
    saving: bool,
    /// Close the window once the in-flight save succeeds.
    close_after_save: bool,
    /// The migration dialog was already answered with "migrate" — do not ask
    /// again on a retry after a failed save.
    migration_ack: bool,
    /// Toast surface for save results and validation errors.
    toast_overlay: adw::ToastOverlay,
}

impl EditorWindow {
    /// The basename shown in the title, or the new-note placeholder.
    fn display_name(&self) -> String {
        self.path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "New note".to_owned())
    }

    /// Header-bar title: the GNOME modified dot plus the basename.
    fn title_text(&self) -> String {
        format!(
            "{}{}",
            if self.dirty { "• " } else { "" },
            self.display_name()
        )
    }

    /// Header-bar subtitle: the backing file's directory.
    fn subtitle_text(&self) -> String {
        self.path
            .as_ref()
            .and_then(|p| p.parent())
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    fn toast(&self, message: &str) {
        self.toast_overlay
            .add_toast(adw::Toast::builder().title(message).build());
    }

    /// Drive a save forward, stopping at whichever prerequisite is missing:
    /// no target → Save As dialog; no secret → password dialog; unconfirmed
    /// AES Crypt migration → confirmation dialog. Each dialog re-enters here
    /// via its input message, so the chain resumes where it stopped.
    fn try_save(&mut self, sender: &ComponentSender<Self>, root: &adw::Window) {
        if self.saving {
            return;
        }
        let Some(path) = self.path.clone() else {
            self.browse_save_target(root, sender);
            return;
        };
        let Some(secret) = self.secret.clone() else {
            self.ask_password(root, sender);
            return;
        };
        if self.source.needs_migration_confirm() && !self.migration_ack {
            self.confirm_migration(root, sender);
            return;
        }

        let options = match self.source.options_for(self.armored, &path) {
            Ok(options) => options,
            Err(e) => {
                self.toast(&e.to_string());
                return;
            }
        };

        // Copy the buffer text into a zeroizing transfer buffer for the
        // worker. The widget's own memory cannot be wiped (DESIGN §11).
        let (start, end) = self.buffer.bounds();
        let bytes = Zeroizing::new(self.buffer.text(&start, &end, true).as_bytes().to_vec());

        self.saving = true;
        sender.spawn_command(move |out| {
            // Saves are small and quick; no cancel UI, so the flag stays unset.
            let cancel = AtomicBool::new(false);
            let result = task::save_from_editor(&bytes, &path, &secret, &options, &cancel, |_p| {})
                .map(|()| options);
            let _ = out.send(EditorCmd::SaveFinished(result));
        });
    }

    /// Open the native save dialog; the chosen path re-enters the save chain
    /// as [`EditorInput::TargetChosen`]. The dialog itself confirms replacing
    /// an existing file, which is why saves need no separate overwrite gate.
    fn browse_save_target(&self, root: &adw::Window, sender: &ComponentSender<Self>) {
        let dialog = gtk::FileDialog::builder()
            .title("Save encrypted file")
            .modal(true)
            .build();
        let initial = self
            .path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "note.paladin".to_owned());
        dialog.set_initial_name(Some(&initial));
        let sender = sender.clone();
        dialog.save(
            Some(root),
            gtk::gio::Cancellable::NONE,
            move |result: Result<gtk::gio::File, gtk::glib::Error>| {
                // A canceled dialog simply leaves the save chain unresumed.
                if let Ok(Some(path)) = result.map(|f| f.path()) {
                    sender.input(EditorInput::TargetChosen(path));
                }
            },
        );
    }

    /// The new-note first-save password dialog (password + confirm rows).
    fn ask_password(&self, root: &adw::Window, sender: &ComponentSender<Self>) {
        let password_row = adw::PasswordEntryRow::builder().title("Password").build();
        let confirm_row = adw::PasswordEntryRow::builder()
            .title("Confirm password")
            .build();
        let list = gtk::ListBox::new();
        list.set_selection_mode(gtk::SelectionMode::None);
        list.add_css_class("boxed-list");
        list.append(&password_row);
        list.append(&confirm_row);

        let dialog = adw::AlertDialog::new(
            Some("Set a password"),
            Some("The file will be encrypted with this password."),
        );
        dialog.set_extra_child(Some(&list));
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("encrypt", "Encrypt");
        dialog.set_response_appearance("encrypt", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("encrypt"));
        dialog.set_close_response("cancel");
        let sender = sender.clone();
        dialog.connect_response(None, move |_, response| {
            if response == "encrypt" {
                sender.input(EditorInput::PasswordProvided {
                    password: Zeroizing::new(password_row.text().as_bytes().to_vec()),
                    confirm: Zeroizing::new(confirm_row.text().as_bytes().to_vec()),
                });
            }
        });
        dialog.present(Some(root));
    }

    /// The AES Crypt → paladin migration confirmation (DESIGN §8.4).
    fn confirm_migration(&self, root: &adw::Window, sender: &ComponentSender<Self>) {
        let dialog = adw::AlertDialog::new(
            Some("Migrate AES Crypt file?"),
            Some(&format!(
                "{} is an AES Crypt file. Saving will migrate it to the paladin \
                 format with paladin's default cipher and key derivation. The \
                 file keeps its name, but AES Crypt tools will no longer open it.",
                self.display_name()
            )),
        );
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("migrate", "Migrate and Save");
        dialog.set_response_appearance("migrate", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let sender = sender.clone();
        dialog.connect_response(None, move |_, response| {
            if response == "migrate" {
                sender.input(EditorInput::MigrationConfirmed);
            }
        });
        dialog.present(Some(root));
    }

    /// The unsaved-changes dialog: Save / Discard / Cancel.
    fn confirm_close(&self, root: &adw::Window, sender: &ComponentSender<Self>) {
        let dialog = adw::AlertDialog::new(
            Some("Save changes?"),
            Some(&format!("{} has unsaved changes.", self.display_name())),
        );
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("discard", "Discard");
        dialog.add_response("save", "Save");
        dialog.set_response_appearance("discard", adw::ResponseAppearance::Destructive);
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("save"));
        dialog.set_close_response("cancel");
        let sender = sender.clone();
        dialog.connect_response(None, move |_, response| match response {
            "discard" => sender.input(EditorInput::DiscardAndClose),
            "save" => sender.input(EditorInput::SaveThenClose),
            _ => {}
        });
        dialog.present(Some(root));
    }

    /// Destroy the window and tell the app to drop this component (and with
    /// it the session secret).
    fn finish_close(&self, root: &adw::Window, sender: &ComponentSender<Self>) {
        root.destroy();
        let _ = sender.output(EditorOutput::Closed(self.id));
    }
}

#[relm4::component(pub)]
impl Component for EditorWindow {
    type Init = EditorInit;
    type Input = EditorInput;
    type Output = EditorOutput;
    type CommandOutput = EditorCmd;

    view! {
        adw::Window {
            set_default_width: 640,
            set_default_height: 520,
            set_icon_name: Some(crate::APP_ID),
            #[watch]
            set_title: Some(&model.title_text()),

            // The model decides whether closing needs the unsaved dialog;
            // `finish_close` destroys the window directly, which does not
            // re-enter this handler.
            connect_close_request[sender] => move |_| {
                sender.input(EditorInput::CloseRequested);
                gtk::glib::Propagation::Stop
            },

            adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &adw::WindowTitle {
                        #[watch]
                        set_title: &model.title_text(),
                        #[watch]
                        set_subtitle: &model.subtitle_text(),
                    },

                    pack_start = &gtk::Button {
                        set_label: "Save",
                        add_css_class: "suggested-action",
                        set_tooltip_text: Some("Save (Ctrl+S)"),
                        #[watch]
                        set_sensitive: !model.saving,
                        connect_clicked => EditorInput::Save,
                    },

                    pack_end = &gtk::Button {
                        set_label: "Save As…",
                        #[watch]
                        set_sensitive: !model.saving,
                        connect_clicked => EditorInput::SaveAs,
                    },
                },

                #[wrap(Some)]
                #[local_ref]
                set_content = &toast_overlay -> adw::ToastOverlay {
                    gtk::ScrolledWindow {
                        set_vexpand: true,

                        #[name = "text_view"]
                        gtk::TextView {
                            set_buffer: Some(&model.buffer),
                            set_monospace: true,
                            set_wrap_mode: gtk::WrapMode::WordChar,
                            set_top_margin: 12,
                            set_bottom_margin: 12,
                            set_left_margin: 12,
                            set_right_margin: 12,
                        },
                    },
                },
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let EditorInit { id, seed } = init;

        let buffer = gtk::TextBuffer::new(None);
        buffer.set_enable_undo(true);

        let (path, source, armored, secret) = match seed {
            Some(seed) => {
                let EditorSeed {
                    text,
                    metadata,
                    armored,
                    path,
                    secret,
                } = seed;
                buffer.set_text(&text);
                // `text` (the zeroizing transfer buffer) drops — and wipes —
                // here; from now on the plaintext lives in widget memory
                // (DESIGN §11).
                (
                    Some(path),
                    SaveSource::from_metadata(&metadata),
                    armored,
                    Some(Arc::new(secret)),
                )
            }
            None => (None, SaveSource::new_note(), false, None),
        };
        // Loading the initial text must not count as a modification.
        buffer.set_modified(false);
        buffer.connect_modified_changed({
            let sender = sender.clone();
            move |b| sender.input(EditorInput::ModifiedChanged(b.is_modified()))
        });

        let model = EditorWindow {
            id,
            path,
            source,
            armored,
            secret,
            buffer,
            dirty: false,
            saving: false,
            close_after_save: false,
            migration_ack: false,
            toast_overlay: adw::ToastOverlay::new(),
        };

        let toast_overlay = model.toast_overlay.clone();
        let widgets = view_output!();

        // Ctrl+S anywhere in the window saves.
        let shortcuts = gtk::ShortcutController::new();
        shortcuts.set_scope(gtk::ShortcutScope::Global);
        shortcuts.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("<Control>s"),
            Some(gtk::CallbackAction::new({
                let sender = sender.clone();
                move |_, _| {
                    sender.input(EditorInput::Save);
                    gtk::glib::Propagation::Stop
                }
            })),
        ));
        root.add_controller(shortcuts);

        widgets.text_view.grab_focus();

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>, root: &Self::Root) {
        match msg {
            EditorInput::Save => self.try_save(&sender, root),
            EditorInput::SaveAs => {
                if !self.saving {
                    self.browse_save_target(root, &sender);
                }
            }
            EditorInput::TargetChosen(path) => {
                self.path = Some(path);
                self.try_save(&sender, root);
            }
            EditorInput::MigrationConfirmed => {
                self.migration_ack = true;
                self.try_save(&sender, root);
            }
            EditorInput::PasswordProvided { password, confirm } => {
                if let Err(e) = options::validate_secret(&password, Some(&confirm), None, false) {
                    self.toast(&e.to_string());
                    return;
                }
                match Secret::new(&password, None) {
                    Ok(secret) => {
                        self.secret = Some(Arc::new(secret));
                        self.try_save(&sender, root);
                    }
                    Err(e) => self.toast(&message::user_message(&e)),
                }
            }
            EditorInput::ModifiedChanged(modified) => self.dirty = modified,
            EditorInput::CloseRequested => {
                if self.saving {
                    // The close resumes via SaveThenClose semantics if wanted;
                    // keep it simple and let the save finish first.
                    self.toast("A save is in progress");
                } else if self.dirty {
                    self.confirm_close(root, &sender);
                } else {
                    self.finish_close(root, &sender);
                }
            }
            EditorInput::DiscardAndClose => self.finish_close(root, &sender),
            EditorInput::SaveThenClose => {
                self.close_after_save = true;
                self.try_save(&sender, root);
            }
        }
    }

    fn update_cmd(
        &mut self,
        msg: Self::CommandOutput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match msg {
            EditorCmd::SaveFinished(Ok(options)) => {
                self.saving = false;
                // An AES Crypt source is migrated now; later saves reuse what
                // was just written and show no dialog.
                self.source.saved(&options);
                // Clearing the buffer flag re-enters ModifiedChanged(false).
                self.buffer.set_modified(false);
                self.toast("Saved");
                if self.close_after_save {
                    self.finish_close(root, &sender);
                }
            }
            EditorCmd::SaveFinished(Err(error)) => {
                self.saving = false;
                self.close_after_save = false;
                let text = match &error {
                    RunError::Core(e) => message::user_message(e),
                    RunError::Fs(e) => e.to_string(),
                };
                self.toast(&text);
            }
        }
    }
}
