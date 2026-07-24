//! `Mode` (Encrypt/Decrypt/Info/Verify/Edit) and per-mode field-visibility
//! rules.
//!
//! This module is pure logic: no GTK, no crypto, no I/O. It encodes which UI
//! controls each mode shows (DESIGN §8.2, `docs/IMPLEMENTATION_PLAN_04_GTK.md`
//! §5–6) plus a few semantic helpers that later modules (`options.rs`,
//! `task.rs`, the relm4 component) consume to stay consistent with the CLI.

/// The five operations the GTK front-end exposes, one per `ViewSwitcher` tab.
///
/// The first four mirror the core operations: `Encrypt`/`Decrypt` round-trip a
/// file, `Info` runs `inspect` (no password), and `Verify` decrypts-and-discards
/// to check integrity. `Edit` (DESIGN §8.4) decrypts a small text file into an
/// in-memory editor window; its output handling lives in that window, not in
/// the main form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Encrypt a plaintext file into a self-describing container.
    Encrypt,
    /// Decrypt a container back to plaintext.
    Decrypt,
    /// Inspect a container's header without a password.
    Info,
    /// Decrypt-and-discard to confirm a container is intact.
    Verify,
    /// Decrypt a small text file into an in-memory editor window (DESIGN §8.4).
    Edit,
}

/// A UI control whose visibility depends on the active [`Mode`].
///
/// Each variant maps to one widget/row in the relm4 `view!`; [`Mode::shows`]
/// answers whether that control is present for a given mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The input file path chooser (always shown).
    Input,
    /// The (editable, prefilled) output file path chooser.
    Output,
    /// The password entry.
    Password,
    /// The confirm-password entry (Encrypt only).
    ConfirmPassword,
    /// The keyfile-only toggle (the `--no-password` equivalent).
    KeyfileOnly,
    /// The keyfile chooser row.
    Keyfile,
    /// The cipher selector (Encrypt only).
    Cipher,
    /// The KDF selector (Encrypt only).
    Kdf,
    /// The per-KDF cost knobs (Encrypt only).
    KdfKnobs,
    /// The `--name` toggle that embeds the input basename (Encrypt only).
    Name,
    /// The ASCII-armor toggle (Encrypt only).
    Armor,
    /// The remove-input-after-success toggle.
    RemoveInput,
    /// The overwrite-approval control (the `-f`/`--force` equivalent).
    OverwriteApproval,
    /// The read-only header results pane (Info only).
    InfoResults,
}

impl Field {
    /// Every [`Field`], for exhaustive iteration in tests and UI building.
    pub const ALL: [Field; 14] = [
        Field::Input,
        Field::Output,
        Field::Password,
        Field::ConfirmPassword,
        Field::KeyfileOnly,
        Field::Keyfile,
        Field::Cipher,
        Field::Kdf,
        Field::KdfKnobs,
        Field::Name,
        Field::Armor,
        Field::RemoveInput,
        Field::OverwriteApproval,
        Field::InfoResults,
    ];
}

impl Mode {
    /// The five modes in `ViewSwitcher` tab order (DESIGN §8.2).
    pub fn all() -> [Mode; 5] {
        [
            Mode::Encrypt,
            Mode::Decrypt,
            Mode::Info,
            Mode::Verify,
            Mode::Edit,
        ]
    }

    /// The tab label shown in the `ViewSwitcher`.
    pub fn title(self) -> &'static str {
        match self {
            Mode::Encrypt => "Encrypt",
            Mode::Decrypt => "Decrypt",
            Mode::Info => "Info",
            Mode::Verify => "Verify",
            Mode::Edit => "Edit",
        }
    }

    /// The action-button label. Every mode's button repeats its tab title
    /// except Edit, whose action opens the editor window rather than "editing"
    /// in place (DESIGN §8.4).
    pub fn action_label(self) -> &'static str {
        match self {
            Mode::Edit => "Open",
            other => other.title(),
        }
    }

    /// Whether `field`'s control is visible in this mode (DESIGN §8.2, §8.4).
    pub fn shows(self, field: Field) -> bool {
        match field {
            // The input path is the one control common to every mode.
            Field::Input => true,
            // Only operations that write a file expose an output path. Edit
            // saves from its own window, so the main form shows none.
            Field::Output => self.needs_output(),
            // Password mirrors "this mode consumes a secret".
            Field::Password => self.needs_secret(),
            // Confirming the password only makes sense when setting it.
            Field::ConfirmPassword => self == Mode::Encrypt,
            // Keyfile (and its "only" toggle) accompany every secret-using mode.
            Field::KeyfileOnly | Field::Keyfile => self.needs_secret(),
            // Cipher/KDF/knobs/name/armor are chosen only when creating a file.
            Field::Cipher | Field::Kdf | Field::KdfKnobs | Field::Name | Field::Armor => {
                self == Mode::Encrypt
            }
            // Remove-input and overwrite approval apply to file-producing modes.
            Field::RemoveInput | Field::OverwriteApproval => self.needs_output(),
            // The header results pane is unique to Info.
            Field::InfoResults => self == Mode::Info,
        }
    }

    /// Whether this mode requires a password/keyfile. True for Encrypt,
    /// Decrypt, Verify, and Edit; false for Info (`inspect` reads only the
    /// plaintext header).
    pub fn needs_secret(self) -> bool {
        matches!(
            self,
            Mode::Encrypt | Mode::Decrypt | Mode::Verify | Mode::Edit
        )
    }

    /// Whether this mode writes an output file from the main form (Encrypt and
    /// Decrypt). Edit writes files too, but from its editor window (DESIGN
    /// §8.4), so the main form treats it as output-less.
    pub fn needs_output(self) -> bool {
        matches!(self, Mode::Encrypt | Mode::Decrypt)
    }

    /// Whether this mode runs its crypto on a background worker. True for
    /// Encrypt, Decrypt, Verify, and Edit (decrypt-to-memory); Info's
    /// `inspect` runs inline.
    pub fn runs_on_worker(self) -> bool {
        matches!(
            self,
            Mode::Encrypt | Mode::Decrypt | Mode::Verify | Mode::Edit
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected `shows` result for a (mode, field) pair, from the DESIGN §8.2
    /// matrix. Returns `None` for cells we assert via the table below so a typo
    /// in either place is caught.
    fn matrix(mode: Mode, field: Field) -> bool {
        use Field::*;
        use Mode::*;
        match field {
            Input => true,
            Output => matches!(mode, Encrypt | Decrypt),
            Password => matches!(mode, Encrypt | Decrypt | Verify | Edit),
            ConfirmPassword => matches!(mode, Encrypt),
            KeyfileOnly => matches!(mode, Encrypt | Decrypt | Verify | Edit),
            Keyfile => matches!(mode, Encrypt | Decrypt | Verify | Edit),
            Cipher => matches!(mode, Encrypt),
            Kdf => matches!(mode, Encrypt),
            KdfKnobs => matches!(mode, Encrypt),
            Name => matches!(mode, Encrypt),
            Armor => matches!(mode, Encrypt),
            RemoveInput => matches!(mode, Encrypt | Decrypt),
            OverwriteApproval => matches!(mode, Encrypt | Decrypt),
            InfoResults => matches!(mode, Info),
        }
    }

    #[test]
    fn shows_matches_full_matrix() {
        for mode in Mode::all() {
            for field in Field::ALL {
                assert_eq!(
                    mode.shows(field),
                    matrix(mode, field),
                    "shows mismatch for {mode:?} / {field:?}"
                );
            }
        }
    }

    #[test]
    fn input_always_visible() {
        for mode in Mode::all() {
            assert!(mode.shows(Field::Input), "{mode:?} must show Input");
        }
    }

    #[test]
    fn encrypt_only_fields() {
        let encrypt_only = [
            Field::ConfirmPassword,
            Field::Cipher,
            Field::Kdf,
            Field::KdfKnobs,
            Field::Name,
            Field::Armor,
        ];
        for field in encrypt_only {
            assert!(Mode::Encrypt.shows(field), "Encrypt must show {field:?}");
            for mode in [Mode::Decrypt, Mode::Info, Mode::Verify, Mode::Edit] {
                assert!(!mode.shows(field), "{mode:?} must hide {field:?}");
            }
        }
    }

    #[test]
    fn info_results_pane_is_info_only() {
        assert!(Mode::Info.shows(Field::InfoResults));
        for mode in [Mode::Encrypt, Mode::Decrypt, Mode::Verify, Mode::Edit] {
            assert!(!mode.shows(Field::InfoResults));
        }
    }

    #[test]
    fn edit_shows_only_input_and_secret_rows() {
        // DESIGN §8.4: the Edit form is input + password + keyfile rows; no
        // output row, no confirm row, no Advanced section, no Info pane.
        for field in Field::ALL {
            let expected = matches!(
                field,
                Field::Input | Field::Password | Field::KeyfileOnly | Field::Keyfile
            );
            assert_eq!(
                Mode::Edit.shows(field),
                expected,
                "Edit visibility wrong for {field:?}"
            );
        }
    }

    #[test]
    fn info_shows_only_input_and_results() {
        for field in Field::ALL {
            let expected = matches!(field, Field::Input | Field::InfoResults);
            assert_eq!(
                Mode::Info.shows(field),
                expected,
                "Info visibility wrong for {field:?}"
            );
        }
    }

    #[test]
    fn needs_secret_per_mode() {
        assert!(Mode::Encrypt.needs_secret());
        assert!(Mode::Decrypt.needs_secret());
        assert!(Mode::Verify.needs_secret());
        assert!(Mode::Edit.needs_secret());
        assert!(!Mode::Info.needs_secret());
    }

    #[test]
    fn needs_output_per_mode() {
        assert!(Mode::Encrypt.needs_output());
        assert!(Mode::Decrypt.needs_output());
        assert!(!Mode::Info.needs_output());
        assert!(!Mode::Verify.needs_output());
        // Edit saves from its own window, never from the main form.
        assert!(!Mode::Edit.needs_output());
    }

    #[test]
    fn runs_on_worker_per_mode() {
        assert!(Mode::Encrypt.runs_on_worker());
        assert!(Mode::Decrypt.runs_on_worker());
        assert!(Mode::Verify.runs_on_worker());
        assert!(Mode::Edit.runs_on_worker());
        assert!(!Mode::Info.runs_on_worker());
    }

    #[test]
    fn password_visibility_equals_needs_secret() {
        for mode in Mode::all() {
            assert_eq!(
                mode.shows(Field::Password),
                mode.needs_secret(),
                "Password/needs_secret invariant broken for {mode:?}"
            );
        }
    }

    #[test]
    fn output_visibility_equals_needs_output() {
        for mode in Mode::all() {
            assert_eq!(
                mode.shows(Field::Output),
                mode.needs_output(),
                "Output/needs_output invariant broken for {mode:?}"
            );
        }
    }

    #[test]
    fn keyfile_rows_track_needs_secret() {
        for mode in Mode::all() {
            assert_eq!(mode.shows(Field::Keyfile), mode.needs_secret());
            assert_eq!(mode.shows(Field::KeyfileOnly), mode.needs_secret());
        }
    }

    #[test]
    fn all_order_is_view_switcher_order() {
        assert_eq!(
            Mode::all(),
            [
                Mode::Encrypt,
                Mode::Decrypt,
                Mode::Info,
                Mode::Verify,
                Mode::Edit
            ]
        );
    }

    #[test]
    fn titles_are_tab_labels() {
        assert_eq!(Mode::Encrypt.title(), "Encrypt");
        assert_eq!(Mode::Decrypt.title(), "Decrypt");
        assert_eq!(Mode::Info.title(), "Info");
        assert_eq!(Mode::Verify.title(), "Verify");
        assert_eq!(Mode::Edit.title(), "Edit");
    }

    #[test]
    fn action_label_is_title_except_edit_opens() {
        for mode in Mode::all() {
            let expected = if mode == Mode::Edit {
                "Open"
            } else {
                mode.title()
            };
            assert_eq!(mode.action_label(), expected, "{mode:?}");
        }
    }

    #[test]
    fn field_all_has_no_duplicates() {
        for (i, a) in Field::ALL.iter().enumerate() {
            for b in &Field::ALL[i + 1..] {
                assert_ne!(a, b, "duplicate field in Field::ALL: {a:?}");
            }
        }
    }
}
