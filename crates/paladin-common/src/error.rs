//! The front-end-facing error type and the `SymError` → exit-code mapping
//! (DESIGN §6.6). The mapping lives here so the CLI and TUI never reclassify
//! core errors.

use std::io;

use paladin_core::SymError;

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

/// Map a core [`SymError`] to its process exit code (DESIGN §6.6). Front-ends do
/// not reclassify; they call this.
pub fn exit_code(err: &SymError) -> i32 {
    match err {
        SymError::Auth => EXIT_AUTH,
        SymError::BadMagic
        | SymError::UnsupportedVersion(_)
        | SymError::UnsupportedAesCryptVersion(_)
        | SymError::UnknownCipher(_)
        | SymError::UnknownKdf(_)
        | SymError::ReservedFlags(_)
        | SymError::MalformedHeader(_) => EXIT_FORMAT,
        SymError::InvalidOptions(_) => EXIT_USAGE,
        SymError::Canceled => EXIT_CANCELED,
        SymError::Io(_) | SymError::InputTooLarge => EXIT_GENERAL,
        // SymError is non_exhaustive; treat any future variant as general.
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
    Core(#[from] SymError),
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
        assert_eq!(exit_code(&SymError::Auth), 3);
        assert_eq!(exit_code(&SymError::BadMagic), 4);
        assert_eq!(exit_code(&SymError::UnsupportedVersion(2)), 4);
        assert_eq!(exit_code(&SymError::UnsupportedAesCryptVersion(4)), 4);
        assert_eq!(exit_code(&SymError::UnknownCipher(9)), 4);
        assert_eq!(exit_code(&SymError::UnknownKdf(9)), 4);
        assert_eq!(exit_code(&SymError::ReservedFlags(0xfc)), 4);
        assert_eq!(exit_code(&SymError::MalformedHeader("x")), 4);
        assert_eq!(exit_code(&SymError::InvalidOptions("x")), 2);
        assert_eq!(exit_code(&SymError::Canceled), 130);
        assert_eq!(exit_code(&SymError::InputTooLarge), 1);
        assert_eq!(exit_code(&SymError::Io(io::Error::other("boom"))), 1);
    }

    #[test]
    fn app_error_exit_codes_and_conversions() {
        let core: AppError = SymError::Auth.into();
        assert_eq!(core.exit_code(), 3);
        assert_eq!(AppError::usage("bad flag").exit_code(), 2);
        let io: AppError = io::Error::other("disk").into();
        assert_eq!(io.exit_code(), 1);
    }

    #[test]
    fn display_does_not_panic_and_includes_message() {
        assert!(AppError::usage("nope").to_string().contains("nope"));
        assert!(AppError::from(SymError::Auth)
            .to_string()
            .contains("wrong password"));
    }
}
