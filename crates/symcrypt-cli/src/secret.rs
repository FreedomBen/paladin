//! Password resolution + interactive prompt → `Secret` (DESIGN §6.4). Plan §5
//! step 5.
#![allow(dead_code)] // wired into run.rs in a later step

use crate::cli::Cli;
use symcrypt_common::AppResult;
use symcrypt_core::Secret;

/// Resolve the secret: a non-interactive password source if given, else an
/// interactive no-echo prompt (confirmed twice when `confirm` is set, i.e. on
/// encrypt), combined with the keyfile when `-k` is present.
pub fn resolve_secret(_cli: &Cli, _confirm: bool) -> AppResult<Secret> {
    todo!()
}
