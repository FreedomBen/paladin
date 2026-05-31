//! Mode dispatch + path/IO orchestration. Built out in plan §6/§8.

use crate::cli::{Cli, Mode};
use symcrypt_common::AppResult;

/// Validate, then run the selected mode. Returns an [`AppError`] whose
/// `exit_code()` the caller maps to the process exit status.
pub fn dispatch(cli: &Cli) -> AppResult<()> {
    crate::validate::validate(cli)?;
    match cli.mode() {
        Mode::Encrypt => todo!("encrypt handler (plan §8)"),
        Mode::Decrypt => todo!("decrypt handler (plan §8)"),
        Mode::Info => todo!("info handler (plan §9)"),
        Mode::Verify => todo!("verify handler (plan §8)"),
    }
}
