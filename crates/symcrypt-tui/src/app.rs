//! Application state for the symcrypt TUI. `event` mutates it; `ui` renders it.

use std::path::PathBuf;

use symcrypt_common as common;
use symcrypt_core as core;

use crate::field::Editor;

/// The operation the user is performing; rendered as tabs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Info,
    Verify,
}

impl Mode {
    /// All modes in tab order.
    pub const ALL: [Mode; 4] = [Mode::Encrypt, Mode::Decrypt, Mode::Info, Mode::Verify];

    /// Tab label.
    pub fn title(self) -> &'static str {
        match self {
            Mode::Encrypt => "Encrypt",
            Mode::Decrypt => "Decrypt",
            Mode::Info => "Info",
            Mode::Verify => "Verify",
        }
    }

    /// Index into [`Mode::ALL`].
    pub fn index(self) -> usize {
        Mode::ALL.iter().position(|&m| m == self).unwrap_or(0)
    }

    /// Does this mode write an output file?
    pub fn has_output(self) -> bool {
        matches!(self, Mode::Encrypt | Mode::Decrypt)
    }
}

/// A focusable widget. The visible set depends on mode and whether the advanced
/// pane is expanded; see [`App::ring`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Focus {
    Mode,
    Input,
    Output,
    Password,
    Confirm,
    ShowPassword,
    KeyfileOnly,
    Advanced,
    Name,
    Armor,
    Remove,
    Overwrite,
    Keyfile,
}

impl Focus {
    /// Is this a single-line text field (gets a caret and accepts typing)?
    pub fn is_text(self) -> bool {
        matches!(
            self,
            Focus::Input | Focus::Output | Focus::Password | Focus::Confirm | Focus::Keyfile
        )
    }
}

/// Status of the most recent / in-flight operation. Extended with the running,
/// done, failed, and canceled states when the worker lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunStatus {
    Idle,
}

/// Top-level application state.
pub struct App {
    pub mode: Mode,
    pub should_quit: bool,

    // Text fields (always allocated; shown per mode).
    pub input: Editor,
    pub output: Editor,
    pub password: Editor,
    pub confirm: Editor,
    pub keyfile: Editor,

    // Toggles.
    pub show_password: bool,
    pub keyfile_only: bool,
    pub advanced: bool,
    pub name: bool,
    pub armor: bool,
    pub remove_input: bool,
    pub overwrite: bool,

    /// Set once the user edits the output field, so prefill never clobbers it.
    pub output_dirty: bool,

    // Focus index into the current [`App::ring`].
    pub focus: usize,

    // Status / results / inline validation.
    pub status: RunStatus,
    pub info_lines: Vec<String>,
    pub field_error: Option<String>,
    pub help: bool,
}

impl App {
    /// Build the app, optionally prefilling the input path from the launch
    /// argument and deriving the output path from it.
    pub fn new(initial_input: Option<String>) -> Self {
        let input = match initial_input {
            Some(path) => Editor::with_text(path),
            None => Editor::new(),
        };
        let mut app = Self {
            mode: Mode::Encrypt,
            should_quit: false,
            input,
            output: Editor::new(),
            password: Editor::masked(),
            confirm: Editor::masked(),
            keyfile: Editor::new(),
            show_password: false,
            keyfile_only: false,
            advanced: false,
            name: false,
            armor: false,
            remove_input: false,
            overwrite: false,
            output_dirty: false,
            focus: 0,
            status: RunStatus::Idle,
            info_lines: Vec::new(),
            field_error: None,
            help: false,
        };
        app.sync_paths();
        app
    }

    /// Process exit code for a normal quit (refined as operations land).
    pub fn exit_code(&self) -> i32 {
        0
    }

    /// The ordered list of focusable widgets for the current state.
    pub fn ring(&self) -> Vec<Focus> {
        let mut r = vec![Focus::Mode, Focus::Input];
        match self.mode {
            Mode::Encrypt => {
                r.push(Focus::Output);
                if !self.keyfile_only {
                    r.push(Focus::Password);
                    r.push(Focus::Confirm);
                }
                r.push(Focus::ShowPassword);
                r.push(Focus::KeyfileOnly);
                r.push(Focus::Advanced);
                if self.advanced {
                    r.extend([
                        Focus::Name,
                        Focus::Armor,
                        Focus::Remove,
                        Focus::Overwrite,
                        Focus::Keyfile,
                    ]);
                }
            }
            Mode::Decrypt => {
                r.push(Focus::Output);
                if !self.keyfile_only {
                    r.push(Focus::Password);
                }
                r.push(Focus::ShowPassword);
                r.push(Focus::KeyfileOnly);
                r.push(Focus::Advanced);
                if self.advanced {
                    r.extend([Focus::Remove, Focus::Overwrite, Focus::Keyfile]);
                }
            }
            Mode::Info => {
                // Inspect needs no secret and no options.
            }
            Mode::Verify => {
                if !self.keyfile_only {
                    r.push(Focus::Password);
                }
                r.push(Focus::ShowPassword);
                r.push(Focus::KeyfileOnly);
                r.push(Focus::Advanced);
                if self.advanced {
                    r.push(Focus::Keyfile);
                }
            }
        }
        r
    }

    /// The currently focused widget (clamped to the ring).
    pub fn focus_target(&self) -> Focus {
        let ring = self.ring();
        ring[self.focus.min(ring.len() - 1)]
    }

    /// Clamp `focus` into range after the ring shrinks.
    pub fn clamp_focus(&mut self) {
        let len = self.ring().len();
        if self.focus >= len {
            self.focus = len - 1;
        }
    }

    /// Switch to the previous mode tab (wrapping) and reset transient state.
    pub fn prev_mode(&mut self) {
        let i = self.mode.index();
        let n = Mode::ALL.len();
        self.set_mode(Mode::ALL[(i + n - 1) % n]);
    }

    /// Switch to the next mode tab (wrapping) and reset transient state.
    pub fn next_mode(&mut self) {
        let i = self.mode.index();
        self.set_mode(Mode::ALL[(i + 1) % Mode::ALL.len()]);
    }

    fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.field_error = None;
        self.output_dirty = false;
        self.clamp_focus();
        self.sync_paths();
    }

    /// Advance focus to the next widget (wrapping).
    pub fn focus_next(&mut self) {
        let n = self.ring().len();
        self.focus = (self.focus + 1) % n;
        self.field_error = None;
        self.sync_paths();
    }

    /// Move focus to the previous widget (wrapping).
    pub fn focus_prev(&mut self) {
        let n = self.ring().len();
        self.focus = (self.focus + n - 1) % n;
        self.field_error = None;
        self.sync_paths();
    }

    /// Mutable editor behind a text-field focus, if `focus` names one.
    pub fn editor_mut(&mut self, focus: Focus) -> Option<&mut Editor> {
        match focus {
            Focus::Input => Some(&mut self.input),
            Focus::Output => Some(&mut self.output),
            Focus::Password => Some(&mut self.password),
            Focus::Confirm => Some(&mut self.confirm),
            Focus::Keyfile => Some(&mut self.keyfile),
            _ => None,
        }
    }

    /// Toggle the checkbox / expander named by `focus`, applying side effects:
    /// showing the password unmasks both password fields; keyfile-only opens the
    /// advanced pane and clears any typed password; armor re-derives the output
    /// extension.
    pub fn toggle(&mut self, focus: Focus) {
        match focus {
            Focus::ShowPassword => {
                self.show_password = !self.show_password;
                let masked = !self.show_password;
                self.password.set_masked(masked);
                self.confirm.set_masked(masked);
            }
            Focus::KeyfileOnly => {
                self.keyfile_only = !self.keyfile_only;
                if self.keyfile_only {
                    self.advanced = true;
                    self.password.clear();
                    self.confirm.clear();
                }
                self.clamp_focus();
            }
            Focus::Advanced => {
                self.advanced = !self.advanced;
                self.clamp_focus();
            }
            Focus::Name => self.name = !self.name,
            Focus::Armor => {
                self.armor = !self.armor;
                self.sync_paths();
            }
            Focus::Remove => self.remove_input = !self.remove_input,
            Focus::Overwrite => self.overwrite = !self.overwrite,
            _ => {}
        }
    }

    /// Validate the input path (surfacing an inline error) and, unless the user
    /// has edited the output field, prefill it. Encrypt uses the pure default;
    /// Decrypt inspects the header for any stored name.
    pub fn sync_paths(&mut self) {
        self.field_error = None;
        if self.input.is_empty() {
            return;
        }
        let input = self.input.text().to_owned();
        let path = match validate_input(&input) {
            Ok(p) => p,
            Err(msg) => {
                self.field_error = Some(msg);
                return;
            }
        };
        if self.output_dirty || !self.mode.has_output() {
            return;
        }
        match self.mode {
            Mode::Encrypt => {
                let out = core::default_encrypt_output(&path, self.armor);
                self.output.set_text(out.to_string_lossy().into_owned());
            }
            Mode::Decrypt => {
                if let Ok(mut reader) = common::open_input(&path) {
                    if let Ok(header) = core::inspect(&mut reader) {
                        let out = core::default_decrypt_output(&path, &header);
                        self.output.set_text(out.to_string_lossy().into_owned());
                    }
                }
            }
            _ => {}
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Validate a path destined for a path field: reject the stdio sentinel `-`
/// (the TUI owns stdin/stdout) and require an existing regular file.
fn validate_input(s: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(s);
    if common::is_stdio(&path) {
        return Err(
            "'-' (stdin/stdout) is not available in the TUI; enter a file path".to_string(),
        );
    }
    common::require_regular_file(&path).map_err(|e| e.to_string())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file() -> tempfile::NamedTempFile {
        tempfile::NamedTempFile::new().expect("temp file")
    }

    #[test]
    fn mode_index_round_trips() {
        for (i, &m) in Mode::ALL.iter().enumerate() {
            assert_eq!(m.index(), i);
        }
    }

    #[test]
    fn info_mode_ring_is_just_mode_and_input() {
        let mut app = App::new(None);
        app.mode = Mode::Info;
        assert_eq!(app.ring(), vec![Focus::Mode, Focus::Input]);
    }

    #[test]
    fn encrypt_ring_includes_password_and_confirm() {
        let app = App::new(None); // Encrypt by default
        let ring = app.ring();
        assert!(ring.contains(&Focus::Password));
        assert!(ring.contains(&Focus::Confirm));
        assert!(ring.contains(&Focus::Output));
    }

    #[test]
    fn keyfile_only_drops_password_fields() {
        let mut app = App::new(None);
        app.keyfile_only = true;
        let ring = app.ring();
        assert!(!ring.contains(&Focus::Password));
        assert!(!ring.contains(&Focus::Confirm));
    }

    #[test]
    fn advanced_expands_the_ring() {
        let mut app = App::new(None);
        let collapsed = app.ring().len();
        app.advanced = true;
        assert!(app.ring().len() > collapsed);
        assert!(app.ring().contains(&Focus::Keyfile));
    }

    #[test]
    fn clamp_focus_keeps_index_in_bounds() {
        let mut app = App::new(None);
        app.advanced = true;
        app.focus = app.ring().len() - 1;
        app.advanced = false; // ring shrinks
        app.clamp_focus();
        assert!(app.focus < app.ring().len());
    }

    #[test]
    fn focus_next_wraps_around() {
        let mut app = App::new(None);
        let n = app.ring().len();
        app.focus = n - 1;
        app.focus_next();
        assert_eq!(app.focus, 0);
    }

    #[test]
    fn show_password_unmasks_both_fields() {
        let mut app = App::new(None);
        app.password.insert('s');
        app.confirm.insert('s');
        // Masked: the rendered form differs from the underlying text.
        assert_ne!(app.password.display(), app.password.text());
        app.toggle(Focus::ShowPassword);
        assert!(app.show_password);
        assert_eq!(app.password.display(), app.password.text());
        assert_eq!(app.confirm.display(), app.confirm.text());
    }

    #[test]
    fn keyfile_only_opens_advanced_and_clears_password() {
        let mut app = App::new(None);
        app.password.insert('x');
        app.toggle(Focus::KeyfileOnly);
        assert!(app.keyfile_only);
        assert!(app.advanced); // so the keyfile field is reachable
        assert!(app.password.is_empty());
    }

    #[test]
    fn editor_mut_only_for_text_fields() {
        let mut app = App::new(None);
        assert!(app.editor_mut(Focus::Input).is_some());
        assert!(app.editor_mut(Focus::Advanced).is_none());
    }

    #[test]
    fn rejects_stdio_dash() {
        assert!(validate_input("-").is_err());
    }

    #[test]
    fn rejects_missing_file() {
        assert!(validate_input("/no/such/symcrypt/path/xyz").is_err());
    }

    #[test]
    fn accepts_regular_file() {
        let f = temp_file();
        let p = f.path().to_str().unwrap().to_string();
        assert!(validate_input(&p).is_ok());
    }

    #[test]
    fn encrypt_prefill_follows_armor_extension() {
        let f = temp_file();
        let p = f.path().to_str().unwrap().to_string();
        let mut app = App::new(Some(p));
        assert!(app.output.text().ends_with(".symcrypt"));
        app.toggle(Focus::Armor);
        assert!(app.output.text().ends_with(".symcrypt.asc"));
    }

    #[test]
    fn dirty_output_is_not_overwritten_by_prefill() {
        let f = temp_file();
        let p = f.path().to_str().unwrap().to_string();
        let mut app = App::new(Some(p));
        app.output_dirty = true;
        app.output.set_text("custom.out");
        app.sync_paths();
        assert_eq!(app.output.text(), "custom.out");
    }
}
