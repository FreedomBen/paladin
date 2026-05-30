//! `symcrypt-common` — terminal glue shared by the CLI and TUI front-ends:
//! path-or-stdin I/O, clobber checks, temp-file finalization, best-effort
//! remove, password-source resolution, and the error-to-exit-code mapping
//! (DESIGN §2.2, §6.4–§6.6). It depends only on `symcrypt-core` and std (plus
//! `thiserror`, `tempfile`, and `zeroize`); `symcrypt-gtk` deliberately does not
//! use it.

mod error;
mod fs;
mod password;

pub use error::{
    exit_code, AppError, AppResult, EXIT_AUTH, EXIT_CANCELED, EXIT_FORMAT, EXIT_GENERAL, EXIT_OK,
    EXIT_USAGE,
};
pub use fs::{
    best_effort_remove, is_same_file, is_stdio, open_input, open_output, require_regular_file,
    FileSink, OutputSink,
};
pub use password::{password_source_from_flags, read_keyfile, resolve_password, PasswordSource};
