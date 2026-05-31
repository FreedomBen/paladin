//! Map `symcrypt_core::SymError` to user-facing toast/dialog text.
//!
//! This module is pure logic: no GTK, no crypto, no I/O. The relm4 component
//! calls [`user_message`] to render a [`SymError`] in a toast or error dialog,
//! and [`is_user_cancel`] to distinguish a deliberate cancel (rendered as a
//! neutral "canceled" state, not an error) from a real failure.
//!
//! The wording is deliberately GUI-appropriate (full sentences) rather than the
//! terse lower-case `Display` strings the core emits. Critically, the [`Auth`]
//! message conflates "wrong password" and "corrupted/tampered file" into a
//! single condition (DESIGN §4.4): the two are cryptographically
//! indistinguishable, so the text must never claim to know which one occurred.
//!
//! [`Auth`]: SymError::Auth

use symcrypt_core::SymError;

/// A clear, sentence-style message describing `err`, suitable for a libadwaita
/// toast or error dialog body.
///
/// `SymError` is `#[non_exhaustive]`; any future variant falls through to a
/// generic message so this never fails to render.
pub fn user_message(err: &SymError) -> String {
    match err {
        // DESIGN §4.4: a failed auth tag is a single condition. The message
        // names BOTH possible causes and never reveals which one happened.
        SymError::Auth => {
            "Wrong password, or the file is corrupted or has been tampered with.".to_string()
        }
        SymError::BadMagic => "This is not a symcrypt file.".to_string(),
        SymError::UnsupportedVersion(v) => format!("Unsupported symcrypt file version ({v:#04x})."),
        SymError::UnknownCipher(id) => {
            format!("This file uses a cipher this version doesn't support (id {id:#04x}).")
        }
        SymError::UnknownKdf(id) => format!(
            "This file uses a key-derivation function this version doesn't support (id {id:#04x})."
        ),
        SymError::ReservedFlags(f) => {
            format!(
                "This file sets reserved header flags ({f:#04x}) this version doesn't understand."
            )
        }
        SymError::MalformedHeader(s) => format!("The file header is malformed: {s}."),
        SymError::InvalidOptions(s) => format!("Invalid options: {s}."),
        SymError::InputTooLarge => "The input is too large (exceeds the 64 GiB limit).".to_string(),
        SymError::Canceled => "Operation canceled.".to_string(),
        SymError::Io(e) => format!("I/O error: {e}."),
        // Future, currently-unknown variants.
        _ => "An unexpected error occurred.".to_string(),
    }
}

/// Whether `err` represents a user-initiated cancellation rather than a failure.
///
/// True only for [`SymError::Canceled`]. The relm4 app uses this to render a
/// neutral "canceled" state instead of an error dialog.
pub fn is_user_cancel(err: &SymError) -> bool {
    matches!(err, SymError::Canceled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// A representative `SymError` of every named variant, used to assert
    /// `user_message` is total and never empty.
    fn sample_errors() -> Vec<SymError> {
        vec![
            SymError::Auth,
            SymError::BadMagic,
            SymError::UnsupportedVersion(0x99),
            SymError::UnknownCipher(0x07),
            SymError::UnknownKdf(0x42),
            SymError::ReservedFlags(0xfc),
            SymError::MalformedHeader("salt_len out of range"),
            SymError::InvalidOptions("empty secret"),
            SymError::InputTooLarge,
            SymError::Canceled,
            SymError::Io(io::Error::other("boom")),
        ]
    }

    #[test]
    fn every_variant_has_a_non_empty_message() {
        for err in sample_errors() {
            assert!(!user_message(&err).is_empty(), "empty message for {err:?}");
        }
    }

    #[test]
    fn auth_message_is_exact() {
        assert_eq!(
            user_message(&SymError::Auth),
            "Wrong password, or the file is corrupted or has been tampered with."
        );
    }

    #[test]
    fn auth_names_both_causes_without_leaking_which() {
        // DESIGN §4.4: must mention BOTH a wrong password AND
        // corruption/tampering, and must not leak a specific format cause.
        let msg = user_message(&SymError::Auth).to_lowercase();
        assert!(
            msg.contains("password"),
            "auth message must mention password"
        );
        assert!(
            msg.contains("corrupt") || msg.contains("tamper"),
            "auth message must mention corruption/tampering"
        );
        // It must not single out a specific cause that would reveal the format.
        assert!(
            !msg.contains("version"),
            "auth message must not leak 'version'"
        );
        assert!(
            !msg.contains("cipher"),
            "auth message must not leak 'cipher'"
        );
    }

    #[test]
    fn bad_magic_message_is_exact() {
        assert_eq!(
            user_message(&SymError::BadMagic),
            "This is not a symcrypt file."
        );
    }

    #[test]
    fn unsupported_version_includes_hex() {
        let msg = user_message(&SymError::UnsupportedVersion(0x99));
        assert!(msg.contains("0x99"), "missing hex version in {msg:?}");
    }

    #[test]
    fn unknown_cipher_includes_hex() {
        let msg = user_message(&SymError::UnknownCipher(0x07));
        assert!(msg.contains("0x07"), "missing hex cipher id in {msg:?}");
        assert!(msg.to_lowercase().contains("cipher"));
    }

    #[test]
    fn unknown_kdf_includes_hex() {
        let msg = user_message(&SymError::UnknownKdf(0x42));
        assert!(msg.contains("0x42"), "missing hex kdf id in {msg:?}");
        assert!(msg.to_lowercase().contains("key-derivation"));
    }

    #[test]
    fn reserved_flags_includes_hex() {
        let msg = user_message(&SymError::ReservedFlags(0xfc));
        assert!(msg.contains("0xfc"), "missing hex flags in {msg:?}");
    }

    #[test]
    fn malformed_header_carries_inner_reason() {
        let msg = user_message(&SymError::MalformedHeader("salt_len out of range"));
        assert!(
            msg.contains("salt_len out of range"),
            "missing inner reason in {msg:?}"
        );
    }

    #[test]
    fn invalid_options_carries_inner_reason() {
        let msg = user_message(&SymError::InvalidOptions("empty secret"));
        assert!(
            msg.contains("empty secret"),
            "missing inner reason in {msg:?}"
        );
    }

    #[test]
    fn input_too_large_mentions_the_limit() {
        let msg = user_message(&SymError::InputTooLarge);
        assert!(msg.contains("64 GiB"), "missing size limit in {msg:?}");
    }

    #[test]
    fn canceled_message_is_exact() {
        assert_eq!(user_message(&SymError::Canceled), "Operation canceled.");
    }

    #[test]
    fn io_message_carries_inner_error() {
        let msg = user_message(&SymError::Io(io::Error::other("boom")));
        assert!(msg.contains("boom"), "missing inner io text in {msg:?}");
    }

    #[test]
    fn is_user_cancel_only_true_for_canceled() {
        assert!(is_user_cancel(&SymError::Canceled));
        assert!(!is_user_cancel(&SymError::Auth));
        assert!(!is_user_cancel(&SymError::BadMagic));
        assert!(!is_user_cancel(&SymError::UnsupportedVersion(0x02)));
        assert!(!is_user_cancel(&SymError::UnknownCipher(0x09)));
        assert!(!is_user_cancel(&SymError::UnknownKdf(0x09)));
        assert!(!is_user_cancel(&SymError::ReservedFlags(0xfc)));
        assert!(!is_user_cancel(&SymError::MalformedHeader("x")));
        assert!(!is_user_cancel(&SymError::InvalidOptions("x")));
        assert!(!is_user_cancel(&SymError::InputTooLarge));
        assert!(!is_user_cancel(&SymError::Io(io::Error::other("boom"))));
    }
}
