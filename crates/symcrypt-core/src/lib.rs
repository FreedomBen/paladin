//! `symcrypt-core` — all crypto, file format, streaming, and pure helpers.
//!
//! This crate does all the work; the front-ends are thin views over it. It
//! never reads argv, never prompts, never touches the filesystem on its own,
//! never decides whether to overwrite, and never exits the process. See
//! `DESIGN.md` for the authoritative specification.

mod cipher;
mod error;
mod kdf;
mod secret;

pub use cipher::CipherId;
pub use error::{Result, SymError};
pub use kdf::{KdfId, KdfParams};
pub use secret::{Secret, KEYFILE_MAX_BYTES};
