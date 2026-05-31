//! Semantic cross-flag validation (DESIGN §6.3). Implemented in plan §5 step 3.

use crate::cli::Cli;
use symcrypt_common::AppResult;

/// Reject flag combinations clap cannot express, with `AppError::usage`
/// (exit 2), before any work begins.
pub fn validate(_cli: &Cli) -> AppResult<()> {
    Ok(())
}
