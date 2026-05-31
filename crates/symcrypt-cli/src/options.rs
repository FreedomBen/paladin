//! Build `EncryptOptions` from parsed args (DESIGN §6.3, §12). Plan §5 step 4.
#![allow(dead_code)] // wired into run.rs in a later step

use crate::cli::Cli;
use symcrypt_common::AppResult;
use symcrypt_core::EncryptOptions;

/// Assemble `EncryptOptions` for an encrypt run: cipher/KDF parsed via core
/// `FromStr`, `KdfParams` from the §12 default with supplied knobs overridden,
/// armor from `-a`, and the stored basename when `--name` is set.
pub fn build_options(_cli: &Cli) -> AppResult<EncryptOptions> {
    todo!()
}
