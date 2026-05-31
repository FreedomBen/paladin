//! Password resolution + interactive prompt → `Secret` (DESIGN §6.4).
//!
//! Non-interactive sources (`-p`, `--password-file`, `--password-env`,
//! `--no-password`) are resolved by `symcrypt-common`; when none is supplied we
//! prompt with no echo, confirming twice on encrypt. A keyfile, if given, is
//! always combined with the password source. The empty-source and
//! at-least-one-byte rules are enforced upstream (`symcrypt-common` /
//! `Secret::new`); this module just gathers bytes.

use crate::cli::Cli;
use std::ffi::OsString;
use symcrypt_common::{
    password_source_from_flags, read_keyfile, resolve_password, AppError, AppResult,
};
use symcrypt_core::Secret;
use zeroize::Zeroizing;

/// Build the zeroized [`Secret`] for the current invocation. `confirm` requests
/// the double-entry interactive prompt used on encrypt.
pub fn resolve_secret(cli: &Cli, confirm: bool) -> AppResult<Secret> {
    let inline = inline_password_bytes(&cli.password)?;
    let source = password_source_from_flags(
        inline,
        cli.password_file.clone(),
        cli.password_env.clone(),
        cli.no_password,
    )?;

    let password = match source {
        Some(src) => resolve_password(&src)?,
        None => prompt_password(confirm)?,
    };

    let keyfile = match &cli.keyfile {
        Some(path) => Some(read_keyfile(path)?),
        None => None,
    };

    Secret::new(&password, keyfile.as_ref().map(|k| k.as_slice())).map_err(AppError::from)
}

/// Convert an inline `-p` value to UTF-8 bytes; non-UTF-8 is a usage error
/// (DESIGN §6.4). Returns `None` when `-p` was not supplied.
fn inline_password_bytes(password: &Option<OsString>) -> AppResult<Option<Vec<u8>>> {
    match password {
        Some(os) => {
            let s = os
                .to_str()
                .ok_or_else(|| AppError::usage("--password must be valid UTF-8"))?;
            Ok(Some(s.as_bytes().to_vec()))
        }
        None => Ok(None),
    }
}

/// Prompt for a password with no echo. On `confirm` (encrypt), prompt twice and
/// require a match; an empty entry is rejected and re-asked (an empty password
/// is allowed only via `--no-password`).
fn prompt_password(confirm: bool) -> AppResult<Zeroizing<Vec<u8>>> {
    loop {
        let first = Zeroizing::new(rpassword::prompt_password("Password: ")?.into_bytes());
        if first.is_empty() {
            eprintln!("symcrypt: empty password; use --no-password with -k for keyfile-only mode");
            continue;
        }
        if confirm {
            let second =
                Zeroizing::new(rpassword::prompt_password("Confirm password: ")?.into_bytes());
            if first.as_slice() != second.as_slice() {
                eprintln!("symcrypt: passwords did not match; try again");
                continue;
            }
        }
        return Ok(first);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_utf8_password_becomes_bytes() {
        let pw = Some(OsString::from("händ"));
        assert_eq!(
            inline_password_bytes(&pw).unwrap(),
            Some("händ".as_bytes().to_vec())
        );
    }

    #[test]
    fn no_inline_password_is_none() {
        assert_eq!(inline_password_bytes(&None).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_inline_password_is_usage_error() {
        use std::os::unix::ffi::OsStringExt;
        let pw = Some(OsString::from_vec(vec![0x66, 0x6f, 0xff, 0x6f]));
        assert!(inline_password_bytes(&pw).is_err());
    }
}
