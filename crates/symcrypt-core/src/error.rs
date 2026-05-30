//! Error type for `symcrypt-core`.
//!
//! Variants correspond one-to-one with the conditions DESIGN §6.6 enumerates.
//! The core never decides process exit codes; the `SymError` → exit-code mapping
//! lives in `symcrypt-common` so the CLI and TUI stay identical.

use std::io;
use thiserror::Error;

/// Convenience alias for results returned by the core.
pub type Result<T> = std::result::Result<T, SymError>;

/// Everything that can go wrong inside the core.
///
/// A failed authentication tag is reported as the single [`SymError::Auth`]
/// condition: wrong password and a corrupted/tampered/truncated file are
/// cryptographically indistinguishable with AEAD and are intentionally
/// conflated (DESIGN §4.4).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SymError {
    /// Authentication failed: wrong password, or a corrupted/tampered/truncated
    /// file. Maps to exit code 3. The two causes are not distinguished.
    #[error("authentication failed: wrong password or corrupted/tampered file")]
    Auth,

    /// The input does not begin with the ASCII `SYMCRYPT` magic. Exit code 4.
    #[error("not a symcrypt file (bad magic)")]
    BadMagic,

    /// The header `version` byte is not understood by this build. Exit code 4.
    #[error("unsupported symcrypt version: {0:#04x}")]
    UnsupportedVersion(u8),

    /// The header names a `cipher_id` this build does not implement. Exit code 4.
    #[error("unknown cipher id: {0:#04x}")]
    UnknownCipher(u8),

    /// The header names a `kdf_id` this build does not implement. Exit code 4.
    #[error("unknown kdf id: {0:#04x}")]
    UnknownKdf(u8),

    /// A reserved `flags` bit (bits 2..=7) was set. Exit code 4.
    #[error("reserved flags bit set: {0:#04x}")]
    ReservedFlags(u8),

    /// The header is structurally invalid rather than merely unrecognized: an
    /// out-of-range length or KDF cost, a non-UTF-8 stored name, corrupt ASCII
    /// armor, or end-of-input before the header completed. Exit code 4. The
    /// `&'static str` names the failed check for diagnostics.
    #[error("malformed header: {0}")]
    MalformedHeader(&'static str),

    /// A programmatically constructed `Secret` or `EncryptOptions` is invalid:
    /// an empty secret, a keyfile buffer outside 1 byte..=1 MiB, KDF params that
    /// do not match the selected KDF, an unsafe/over-long stored filename, or an
    /// out-of-range `chunk_size`. Exit code 2.
    #[error("invalid options: {0}")]
    InvalidOptions(&'static str),

    /// Plaintext exceeds the v1 64 GiB size cap or the 2³² chunk-count limit
    /// (DESIGN §4.3). Detected while streaming, before any file output is
    /// finalized. Exit code 1.
    #[error("input too large: exceeds the v1 64 GiB plaintext / chunk-count limit")]
    InputTooLarge,

    /// The operation was canceled through the progress callback returning
    /// `ControlFlow::Break`. Exit code 130.
    #[error("operation canceled")]
    Canceled,

    /// An I/O error from the caller-supplied `Read`/`Write`. Exit code 1.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Recover a [`SymError`] that the armor layer wrapped in an `io::Error` (via
/// `io::Error::other`) so it can surface through the `Read` interface with its
/// original variant and exit code. Returns the original `io::Error` untouched
/// when it does not carry a `SymError`.
pub(crate) fn recover_symerror(e: io::Error) -> std::result::Result<SymError, io::Error> {
    if e.get_ref().is_some_and(|inner| inner.is::<SymError>()) {
        Ok(*e.into_inner().unwrap().downcast::<SymError>().unwrap())
    } else {
        Err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_convert_via_from() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "boom");
        let err: SymError = io_err.into();
        assert!(matches!(err, SymError::Io(_)));
    }

    #[test]
    fn question_mark_operator_converts_io_errors() {
        fn fails() -> Result<()> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))?;
            Ok(())
        }
        assert!(matches!(fails(), Err(SymError::Io(_))));
    }

    #[test]
    fn auth_message_does_not_leak_which_cause() {
        // Wrong password and tampering must read the same (DESIGN §4.4).
        let msg = SymError::Auth.to_string();
        assert!(msg.contains("wrong password"));
        assert!(msg.contains("corrupted/tampered"));
    }

    #[test]
    fn malformed_and_invalid_carry_their_reason() {
        assert_eq!(
            SymError::MalformedHeader("salt_len out of range").to_string(),
            "malformed header: salt_len out of range"
        );
        assert_eq!(
            SymError::InvalidOptions("empty secret").to_string(),
            "invalid options: empty secret"
        );
    }

    #[test]
    fn unknown_ids_render_as_two_digit_hex() {
        assert_eq!(
            SymError::UnknownCipher(0x07).to_string(),
            "unknown cipher id: 0x07"
        );
        assert_eq!(
            SymError::UnsupportedVersion(0x99).to_string(),
            "unsupported symcrypt version: 0x99"
        );
    }

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<SymError>();
    }
}
