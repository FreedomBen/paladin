//! Map `paladin_core::PalError` to user-facing toast/dialog text.
//!
//! This module is pure logic: no GTK, no crypto, no I/O. The relm4 component
//! calls [`user_message`] to render a [`PalError`] in a toast or error dialog,
//! and [`is_user_cancel`] to distinguish a deliberate cancel (rendered as a
//! neutral "canceled" state, not an error) from a real failure.
//!
//! The wording is deliberately GUI-appropriate (full sentences) rather than the
//! terse lower-case `Display` strings the core emits. Critically, the [`Auth`]
//! message conflates "wrong password" and "corrupted/tampered file" into a
//! single condition (DESIGN §4.4): the two are cryptographically
//! indistinguishable, so the text must never claim to know which one occurred.
//!
//! [`Auth`]: PalError::Auth

use paladin_core::PalError;

/// A clear, sentence-style message describing `err`, suitable for a libadwaita
/// toast or error dialog body.
///
/// `PalError` is `#[non_exhaustive]`; any future variant falls through to a
/// generic message so this never fails to render.
pub fn user_message(err: &PalError) -> String {
    match err {
        // DESIGN §4.4: a failed auth tag is a single condition. The message
        // names BOTH possible causes and never reveals which one happened.
        PalError::Auth => {
            "Wrong password, or the file is corrupted or has been tampered with.".to_string()
        }
        PalError::BadMagic => "This is not a recognized paladin or AES Crypt file.".to_string(),
        PalError::UnsupportedVersion(v) => format!("Unsupported paladin file version ({v:#04x})."),
        PalError::UnsupportedAesCryptVersion(v) => {
            format!("Unsupported AES Crypt file version ({v:#04x}).")
        }
        PalError::UnknownCipher(id) => {
            format!("This file uses a cipher this version doesn't support (id {id:#04x}).")
        }
        PalError::UnknownKdf(id) => format!(
            "This file uses a key-derivation function this version doesn't support (id {id:#04x})."
        ),
        PalError::ReservedFlags(f) => {
            format!(
                "This file sets reserved header flags ({f:#04x}) this version doesn't understand."
            )
        }
        PalError::MalformedHeader(s) => format!("The file header is malformed: {s}."),
        PalError::InvalidOptions(s) => format!("Invalid options: {s}."),
        PalError::InputTooLarge => "The input is too large (exceeds the 64 GiB limit).".to_string(),
        PalError::Canceled => "Operation canceled.".to_string(),
        PalError::Io(e) => format!("I/O error: {e}."),
        // Future, currently-unknown variants.
        _ => "An unexpected error occurred.".to_string(),
    }
}

/// Whether `err` represents a user-initiated cancellation rather than a failure.
///
/// True only for [`PalError::Canceled`]. The relm4 app uses this to render a
/// neutral "canceled" state instead of an error dialog.
pub fn is_user_cancel(err: &PalError) -> bool {
    matches!(err, PalError::Canceled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// A representative `PalError` of every named variant, used to assert
    /// `user_message` is total and never empty.
    fn sample_errors() -> Vec<PalError> {
        vec![
            PalError::Auth,
            PalError::BadMagic,
            PalError::UnsupportedVersion(0x99),
            PalError::UnsupportedAesCryptVersion(0x03),
            PalError::UnknownCipher(0x07),
            PalError::UnknownKdf(0x42),
            PalError::ReservedFlags(0xfc),
            PalError::MalformedHeader("salt_len out of range"),
            PalError::InvalidOptions("empty secret"),
            PalError::InputTooLarge,
            PalError::Canceled,
            PalError::Io(io::Error::other("boom")),
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
            user_message(&PalError::Auth),
            "Wrong password, or the file is corrupted or has been tampered with."
        );
    }

    #[test]
    fn auth_names_both_causes_without_leaking_which() {
        // DESIGN §4.4: must mention BOTH a wrong password AND
        // corruption/tampering, and must not leak a specific format cause.
        let msg = user_message(&PalError::Auth).to_lowercase();
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
            user_message(&PalError::BadMagic),
            "This is not a recognized paladin or AES Crypt file."
        );
    }

    #[test]
    fn unsupported_version_includes_hex() {
        let msg = user_message(&PalError::UnsupportedVersion(0x99));
        assert!(msg.contains("0x99"), "missing hex version in {msg:?}");
    }

    #[test]
    fn unsupported_aescrypt_version_includes_hex_and_names_aes_crypt() {
        let msg = user_message(&PalError::UnsupportedAesCryptVersion(0x03));
        assert!(msg.contains("0x03"), "missing hex version in {msg:?}");
        assert!(
            msg.contains("AES Crypt"),
            "should name AES Crypt in {msg:?}"
        );
    }

    #[test]
    fn unknown_cipher_includes_hex() {
        let msg = user_message(&PalError::UnknownCipher(0x07));
        assert!(msg.contains("0x07"), "missing hex cipher id in {msg:?}");
        assert!(msg.to_lowercase().contains("cipher"));
    }

    #[test]
    fn unknown_kdf_includes_hex() {
        let msg = user_message(&PalError::UnknownKdf(0x42));
        assert!(msg.contains("0x42"), "missing hex kdf id in {msg:?}");
        assert!(msg.to_lowercase().contains("key-derivation"));
    }

    #[test]
    fn reserved_flags_includes_hex() {
        let msg = user_message(&PalError::ReservedFlags(0xfc));
        assert!(msg.contains("0xfc"), "missing hex flags in {msg:?}");
    }

    #[test]
    fn malformed_header_carries_inner_reason() {
        let msg = user_message(&PalError::MalformedHeader("salt_len out of range"));
        assert!(
            msg.contains("salt_len out of range"),
            "missing inner reason in {msg:?}"
        );
    }

    #[test]
    fn invalid_options_carries_inner_reason() {
        let msg = user_message(&PalError::InvalidOptions("empty secret"));
        assert!(
            msg.contains("empty secret"),
            "missing inner reason in {msg:?}"
        );
    }

    #[test]
    fn input_too_large_mentions_the_limit() {
        let msg = user_message(&PalError::InputTooLarge);
        assert!(msg.contains("64 GiB"), "missing size limit in {msg:?}");
    }

    #[test]
    fn canceled_message_is_exact() {
        assert_eq!(user_message(&PalError::Canceled), "Operation canceled.");
    }

    #[test]
    fn io_message_carries_inner_error() {
        let msg = user_message(&PalError::Io(io::Error::other("boom")));
        assert!(msg.contains("boom"), "missing inner io text in {msg:?}");
    }

    #[test]
    fn is_user_cancel_only_true_for_canceled() {
        assert!(is_user_cancel(&PalError::Canceled));
        assert!(!is_user_cancel(&PalError::Auth));
        assert!(!is_user_cancel(&PalError::BadMagic));
        assert!(!is_user_cancel(&PalError::UnsupportedVersion(0x02)));
        assert!(!is_user_cancel(&PalError::UnsupportedAesCryptVersion(0x03)));
        assert!(!is_user_cancel(&PalError::UnknownCipher(0x09)));
        assert!(!is_user_cancel(&PalError::UnknownKdf(0x09)));
        assert!(!is_user_cancel(&PalError::ReservedFlags(0xfc)));
        assert!(!is_user_cancel(&PalError::MalformedHeader("x")));
        assert!(!is_user_cancel(&PalError::InvalidOptions("x")));
        assert!(!is_user_cancel(&PalError::InputTooLarge));
        assert!(!is_user_cancel(&PalError::Io(io::Error::other("boom"))));
    }
}
