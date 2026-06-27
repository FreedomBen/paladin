//! The front-end-facing error type and the `PalError` → exit-code mapping
//! (DESIGN §6.6). The mapping lives here so the CLI and TUI never reclassify
//! core errors.

use std::io;

use paladin_core::PalError;

/// Success.
pub const EXIT_OK: i32 = 0;
/// General error (I/O, etc.).
pub const EXIT_GENERAL: i32 = 1;
/// Usage / argument error.
pub const EXIT_USAGE: i32 = 2;
/// Authentication failure (wrong password or tampered file).
pub const EXIT_AUTH: i32 = 3;
/// Unsupported, unknown, or malformed format/header.
pub const EXIT_FORMAT: i32 = 4;
/// Canceled by the user.
pub const EXIT_CANCELED: i32 = 130;

/// Map a core [`PalError`] to its process exit code (DESIGN §6.6). Front-ends do
/// not reclassify; they call this.
pub fn exit_code(err: &PalError) -> i32 {
    match err {
        PalError::Auth => EXIT_AUTH,
        PalError::BadMagic
        | PalError::UnsupportedVersion(_)
        | PalError::UnsupportedAesCryptVersion(_)
        | PalError::UnknownCipher(_)
        | PalError::UnknownKdf(_)
        | PalError::ReservedFlags(_)
        | PalError::MalformedHeader(_) => EXIT_FORMAT,
        PalError::InvalidOptions(_) => EXIT_USAGE,
        PalError::Canceled => EXIT_CANCELED,
        PalError::Io(_) | PalError::InputTooLarge => EXIT_GENERAL,
        // PalError is non_exhaustive; treat any future variant as general.
        _ => EXIT_GENERAL,
    }
}

/// A front-end error: a core error, a usage error caught before the core is
/// called, or an I/O error from the terminal glue. Its [`AppError::exit_code`]
/// gives the process exit status.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// An error returned by `paladin-core`.
    #[error("{0}")]
    Core(#[from] PalError),
    /// A usage/argument problem caught before the core (exit 2).
    #[error("{0}")]
    Usage(String),
    /// An I/O error from the glue itself (exit 1).
    #[error("{0}")]
    Io(#[from] io::Error),
}

impl AppError {
    /// Build a usage error.
    pub fn usage(msg: impl Into<String>) -> Self {
        AppError::Usage(msg.into())
    }

    /// The process exit code for this error (DESIGN §6.6).
    pub fn exit_code(&self) -> i32 {
        match self {
            AppError::Core(e) => exit_code(e),
            AppError::Usage(_) => EXIT_USAGE,
            AppError::Io(_) => EXIT_GENERAL,
        }
    }
}

/// Convenience alias for front-end results.
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_errors_map_to_their_exit_codes() {
        assert_eq!(exit_code(&PalError::Auth), 3);
        assert_eq!(exit_code(&PalError::BadMagic), 4);
        assert_eq!(exit_code(&PalError::UnsupportedVersion(2)), 4);
        assert_eq!(exit_code(&PalError::UnsupportedAesCryptVersion(4)), 4);
        assert_eq!(exit_code(&PalError::UnknownCipher(9)), 4);
        assert_eq!(exit_code(&PalError::UnknownKdf(9)), 4);
        assert_eq!(exit_code(&PalError::ReservedFlags(0xfc)), 4);
        assert_eq!(exit_code(&PalError::MalformedHeader("x")), 4);
        assert_eq!(exit_code(&PalError::InvalidOptions("x")), 2);
        assert_eq!(exit_code(&PalError::Canceled), 130);
        assert_eq!(exit_code(&PalError::InputTooLarge), 1);
        assert_eq!(exit_code(&PalError::Io(io::Error::other("boom"))), 1);
    }

    #[test]
    fn app_error_exit_codes_and_conversions() {
        let core: AppError = PalError::Auth.into();
        assert_eq!(core.exit_code(), 3);
        assert_eq!(AppError::usage("bad flag").exit_code(), 2);
        let io: AppError = io::Error::other("disk").into();
        assert_eq!(io.exit_code(), 1);
    }

    #[test]
    fn display_does_not_panic_and_includes_message() {
        assert!(AppError::usage("nope").to_string().contains("nope"));
        assert!(AppError::from(PalError::Auth)
            .to_string()
            .contains("wrong password"));
    }
}
