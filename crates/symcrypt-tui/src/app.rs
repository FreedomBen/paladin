//! Application state for the symcrypt TUI. `event` mutates it; `ui` renders it.

use std::path::{Path, PathBuf};

use symcrypt_common as common;
use symcrypt_core as core;

use core::{CipherId, KdfId};

use crate::field::Editor;
use crate::options::{self, KdfKnobs};

/// Selectable ciphers, in display order.
const CIPHERS: [CipherId; 2] = [CipherId::Aes256Gcm, CipherId::ChaCha20Poly1305];
/// Selectable KDFs, in display order.
const KDFS: [KdfId; 3] = [KdfId::Argon2id, KdfId::Scrypt, KdfId::Pbkdf2];

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
    Cipher,
    Kdf,
    KnobMem,
    KnobTime,
    KnobPar,
    KnobLogN,
    KnobR,
    KnobP,
    KnobIter,
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
            Focus::Input
                | Focus::Output
                | Focus::Password
                | Focus::Confirm
                | Focus::Keyfile
                | Focus::KnobMem
                | Focus::KnobTime
                | Focus::KnobPar
                | Focus::KnobLogN
                | Focus::KnobR
                | Focus::KnobP
                | Focus::KnobIter
        )
    }

    /// Is this one of the KDF cost-knob fields?
    pub fn is_knob(self) -> bool {
        matches!(
            self,
            Focus::KnobMem
                | Focus::KnobTime
                | Focus::KnobPar
                | Focus::KnobLogN
                | Focus::KnobR
                | Focus::KnobP
                | Focus::KnobIter
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

    // Advanced selectors.
    pub cipher: CipherId,
    pub kdf: KdfId,

    // KDF cost knobs (only the selected KDF's are shown).
    pub argon2_memory: Editor,
    pub argon2_time: Editor,
    pub argon2_parallelism: Editor,
    pub scrypt_log_n: Editor,
    pub scrypt_r: Editor,
    pub scrypt_p: Editor,
    pub pbkdf2_iterations: Editor,

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
        let k = KdfKnobs::defaults();
        let mut app = Self {
            mode: Mode::Encrypt,
            should_quit: false,
            input,
            output: Editor::new(),
            password: Editor::masked(),
            confirm: Editor::masked(),
            keyfile: Editor::new(),
            cipher: CipherId::Aes256Gcm,
            kdf: KdfId::Argon2id,
            argon2_memory: Editor::with_text(k.argon2_memory_kib),
            argon2_time: Editor::with_text(k.argon2_time_cost),
            argon2_parallelism: Editor::with_text(k.argon2_parallelism),
            scrypt_log_n: Editor::with_text(k.scrypt_log_n),
            scrypt_r: Editor::with_text(k.scrypt_r),
            scrypt_p: Editor::with_text(k.scrypt_p),
            pbkdf2_iterations: Editor::with_text(k.pbkdf2_iterations),
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

    /// The KDF knob fields visible for the currently selected KDF.
    fn kdf_knob_focuses(&self) -> Vec<Focus> {
        match self.kdf {
            KdfId::Argon2id => vec![Focus::KnobMem, Focus::KnobTime, Focus::KnobPar],
            KdfId::Scrypt => vec![Focus::KnobLogN, Focus::KnobR, Focus::KnobP],
            KdfId::Pbkdf2 => vec![Focus::KnobIter],
        }
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
                    r.push(Focus::Cipher);
                    r.push(Focus::Kdf);
                    r.extend(self.kdf_knob_focuses());
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

    /// Cycle the cipher selector.
    pub fn cycle_cipher(&mut self, forward: bool) {
        self.cipher = cycle(&CIPHERS, self.cipher, forward);
        self.validate_options();
    }

    /// Cycle the KDF selector (changing which knob fields are shown).
    pub fn cycle_kdf(&mut self, forward: bool) {
        self.kdf = cycle(&KDFS, self.kdf, forward);
        self.clamp_focus();
        self.validate_options();
    }

    /// Mutable editor behind a text-field focus, if `focus` names one.
    pub fn editor_mut(&mut self, focus: Focus) -> Option<&mut Editor> {
        match focus {
            Focus::Input => Some(&mut self.input),
            Focus::Output => Some(&mut self.output),
            Focus::Password => Some(&mut self.password),
            Focus::Confirm => Some(&mut self.confirm),
            Focus::Keyfile => Some(&mut self.keyfile),
            Focus::KnobMem => Some(&mut self.argon2_memory),
            Focus::KnobTime => Some(&mut self.argon2_time),
            Focus::KnobPar => Some(&mut self.argon2_parallelism),
            Focus::KnobLogN => Some(&mut self.scrypt_log_n),
            Focus::KnobR => Some(&mut self.scrypt_r),
            Focus::KnobP => Some(&mut self.scrypt_p),
            Focus::KnobIter => Some(&mut self.pbkdf2_iterations),
            _ => None,
        }
    }

    /// Toggle the checkbox / expander named by `focus`, applying side effects:
    /// showing the password unmasks both password fields; keyfile-only opens the
    /// advanced pane and clears any typed password; armor re-derives the output
    /// extension; `--name` re-validates the options.
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
            Focus::Name => {
                self.name = !self.name;
                self.validate_options();
            }
            Focus::Armor => {
                self.armor = !self.armor;
                self.sync_paths();
            }
            Focus::Remove => self.remove_input = !self.remove_input,
            Focus::Overwrite => self.overwrite = !self.overwrite,
            _ => {}
        }
    }

    /// Snapshot the knob editors into the pure [`KdfKnobs`] for validation.
    pub fn knobs(&self) -> KdfKnobs {
        KdfKnobs {
            argon2_memory_kib: self.argon2_memory.text().to_owned(),
            argon2_time_cost: self.argon2_time.text().to_owned(),
            argon2_parallelism: self.argon2_parallelism.text().to_owned(),
            scrypt_log_n: self.scrypt_log_n.text().to_owned(),
            scrypt_r: self.scrypt_r.text().to_owned(),
            scrypt_p: self.scrypt_p.text().to_owned(),
            pbkdf2_iterations: self.pbkdf2_iterations.text().to_owned(),
        }
    }

    /// Validate the encrypt options (cipher/KDF/knobs/name) for inline feedback.
    /// No-op outside Encrypt mode. Sets `field_error` on failure, clears on pass.
    pub fn validate_options(&mut self) {
        if self.mode != Mode::Encrypt {
            return;
        }
        let name = if self.name {
            match basename(self.input.text()) {
                Some(b) => Some(b),
                None => {
                    self.field_error = Some("cannot determine a basename for --name".to_string());
                    return;
                }
            }
        } else {
            None
        };
        match options::build_encrypt_options(
            self.cipher,
            self.kdf,
            &self.knobs(),
            self.armor,
            name.as_deref(),
        ) {
            Ok(_) => self.field_error = None,
            Err(msg) => self.field_error = Some(msg),
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

/// Cycle through `items` from `current`, forward or backward (wrapping).
fn cycle<T: Copy + PartialEq>(items: &[T], current: T, forward: bool) -> T {
    let n = items.len();
    let i = items.iter().position(|&x| x == current).unwrap_or(0);
    if forward {
        items[(i + 1) % n]
    } else {
        items[(i + n - 1) % n]
    }
}

/// The UTF-8 basename of a path string, if it has one.
fn basename(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_owned())
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
        assert!(app.ring().contains(&Focus::Cipher));
    }

    #[test]
    fn advanced_shows_only_selected_kdf_knobs() {
        let mut app = App::new(None);
        app.advanced = true;
        assert!(app.ring().contains(&Focus::KnobMem)); // argon2 default
        app.cycle_kdf(true); // -> scrypt
        assert!(app.ring().contains(&Focus::KnobLogN));
        assert!(!app.ring().contains(&Focus::KnobMem));
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
    fn cycle_cipher_round_trips() {
        let mut app = App::new(None);
        assert_eq!(app.cipher, CipherId::Aes256Gcm);
        app.cycle_cipher(true);
        assert_eq!(app.cipher, CipherId::ChaCha20Poly1305);
        app.cycle_cipher(true);
        assert_eq!(app.cipher, CipherId::Aes256Gcm); // wraps
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
        assert!(app.editor_mut(Focus::KnobMem).is_some());
        assert!(app.editor_mut(Focus::Advanced).is_none());
    }

    #[test]
    fn validate_options_flags_bad_knob() {
        let mut app = App::new(None);
        app.argon2_memory.set_text("1"); // below range
        app.validate_options();
        assert!(app.field_error.is_some());
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
