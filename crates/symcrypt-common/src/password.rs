//! Password and keyfile source resolution (DESIGN §6.4).
//!
//! Front-ends gather which flags were supplied; [`password_source_from_flags`]
//! enforces exclusivity, and [`resolve_password`] turns a non-interactive source
//! into bytes. The interactive prompt itself is front-end specific (the CLI uses
//! `rpassword`, the TUI/GTK their own masked fields), signalled by `None`.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use symcrypt_core::KEYFILE_MAX_BYTES;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::fs::{is_stdio, require_regular_file};

/// Maximum bytes read from a `--password-file` (DESIGN §6.4).
const PASSWORD_FILE_MAX: usize = 1024 * 1024;

/// A non-interactive password source (DESIGN §6.4).
#[derive(Debug, Clone)]
pub enum PasswordSource {
    /// Inline `-p` bytes (discouraged; DESIGN §11).
    Inline(Zeroizing<Vec<u8>>),
    /// `--password-file` path.
    File(PathBuf),
    /// `--password-env` variable name.
    Env(OsString),
    /// `--no-password`: an explicit empty password (keyfile-only).
    NoPassword,
}

/// Choose the password source from the supplied flags, enforcing exclusivity
/// (DESIGN §6.4): at most one of inline/file/env/no-password. `Ok(None)` means
/// none was given and the front-end should prompt interactively.
pub fn password_source_from_flags(
    inline: Option<Vec<u8>>,
    file: Option<PathBuf>,
    env: Option<OsString>,
    no_password: bool,
) -> AppResult<Option<PasswordSource>> {
    let count = u8::from(inline.is_some())
        + u8::from(file.is_some())
        + u8::from(env.is_some())
        + u8::from(no_password);
    if count > 1 {
        return Err(AppError::usage(
            "at most one of -p/--password, --password-file, --password-env, or --no-password may be given",
        ));
    }
    Ok(if let Some(b) = inline {
        Some(PasswordSource::Inline(Zeroizing::new(b)))
    } else if let Some(p) = file {
        Some(PasswordSource::File(p))
    } else if let Some(v) = env {
        Some(PasswordSource::Env(v))
    } else if no_password {
        Some(PasswordSource::NoPassword)
    } else {
        None
    })
}

/// Resolve a non-interactive source to password bytes (DESIGN §6.4). An empty
/// password is accepted only via [`PasswordSource::NoPassword`]; every other
/// source that yields no bytes is a usage error, so a misconfigured source can
/// never silently downgrade a password to keyfile-only.
pub fn resolve_password(source: &PasswordSource) -> AppResult<Zeroizing<Vec<u8>>> {
    match source {
        PasswordSource::Inline(bytes) => {
            if bytes.is_empty() {
                return Err(AppError::usage(
                    "empty password; use --no-password for keyfile-only mode",
                ));
            }
            Ok(bytes.clone())
        }
        PasswordSource::NoPassword => Ok(Zeroizing::new(Vec::new())),
        PasswordSource::Env(var) => {
            let value = std::env::var(var).map_err(|e| match e {
                std::env::VarError::NotPresent => {
                    AppError::usage(format!("environment variable {var:?} is not set"))
                }
                std::env::VarError::NotUnicode(_) => {
                    AppError::usage(format!("environment variable {var:?} is not valid UTF-8"))
                }
            })?;
            if value.is_empty() {
                return Err(AppError::usage(
                    "password environment variable is set but empty",
                ));
            }
            Ok(Zeroizing::new(value.into_bytes()))
        }
        PasswordSource::File(path) => {
            let mut bytes = read_capped(path, PASSWORD_FILE_MAX, "password file")?;
            trim_one_trailing_newline(&mut bytes);
            if bytes.is_empty() {
                return Err(AppError::usage(
                    "password file is empty or contains only a trailing newline",
                ));
            }
            Ok(bytes)
        }
    }
}

/// Read keyfile bytes (DESIGN §4.2, §6.4): an existing regular file of
/// 1 byte..=1 MiB. Empty and over-large keyfiles are usage errors.
pub fn read_keyfile(path: &Path) -> AppResult<Zeroizing<Vec<u8>>> {
    let bytes = read_capped(path, KEYFILE_MAX_BYTES, "keyfile")?;
    if bytes.is_empty() {
        return Err(AppError::usage("keyfile is empty"));
    }
    Ok(bytes)
}

/// Read up to `max` bytes from a regular file, erroring if it is larger. `-` is
/// rejected so stdin stays reserved for the main input stream (DESIGN §6.4).
fn read_capped(path: &Path, max: usize, what: &str) -> AppResult<Zeroizing<Vec<u8>>> {
    if is_stdio(path) {
        return Err(AppError::usage(format!(
            "{what} path may not be '-' (stdin is reserved for the main input)"
        )));
    }
    require_regular_file(path)?;
    let file = File::open(path).map_err(AppError::Io)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(AppError::Io)?;
    if bytes.len() > max {
        return Err(AppError::usage(format!("{what} exceeds the 1 MiB limit")));
    }
    Ok(bytes)
}

/// Remove exactly one trailing LF or CRLF, if present; no other trimming
/// (DESIGN §6.4).
fn trim_one_trailing_newline(buf: &mut Zeroizing<Vec<u8>>) {
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // Serializes the env-mutating tests against each other and the read-only
    // unset test, so concurrent libc setenv/getenv can never race in this binary.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn write_file(dir: &TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        File::create(&path).unwrap().write_all(contents).unwrap();
        path
    }

    #[test]
    fn from_flags_enforces_exclusivity() {
        assert!(
            password_source_from_flags(Some(b"x".to_vec()), None, None, false)
                .unwrap()
                .is_some()
        );
        assert!(password_source_from_flags(None, None, None, false)
            .unwrap()
            .is_none()); // prompt
                         // Two sources at once is a usage error.
        assert!(password_source_from_flags(
            Some(b"x".to_vec()),
            Some(PathBuf::from("f")),
            None,
            false
        )
        .is_err());
        assert!(password_source_from_flags(None, None, Some(OsString::from("V")), true).is_err());
    }

    #[test]
    fn inline_rejects_empty_and_keeps_bytes() {
        assert!(matches!(
            resolve_password(&PasswordSource::Inline(Zeroizing::new(Vec::new()))),
            Err(AppError::Usage(_))
        ));
        let r =
            resolve_password(&PasswordSource::Inline(Zeroizing::new(b"hunter2".to_vec()))).unwrap();
        assert_eq!(&*r, b"hunter2");
    }

    #[test]
    fn no_password_is_empty() {
        assert!(resolve_password(&PasswordSource::NoPassword)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn env_unset_is_a_usage_error() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let src = PasswordSource::Env(OsString::from("SYMCRYPT_TEST_DEFINITELY_UNSET_abc123"));
        assert!(matches!(resolve_password(&src), Err(AppError::Usage(_))));
    }

    #[test]
    fn password_file_trims_one_newline_and_rejects_empty() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "pw", b"secret\n");
        assert_eq!(
            &*resolve_password(&PasswordSource::File(p)).unwrap(),
            b"secret"
        );
        let crlf = write_file(&dir, "pw_crlf", b"secret\r\n");
        assert_eq!(
            &*resolve_password(&PasswordSource::File(crlf)).unwrap(),
            b"secret"
        );
        // Only one newline is stripped.
        let two = write_file(&dir, "pw2", b"secret\n\n");
        assert_eq!(
            &*resolve_password(&PasswordSource::File(two)).unwrap(),
            b"secret\n"
        );
        let empty = write_file(&dir, "empty", b"");
        assert!(matches!(
            resolve_password(&PasswordSource::File(empty)),
            Err(AppError::Usage(_))
        ));
        let newline_only = write_file(&dir, "nl", b"\n");
        assert!(matches!(
            resolve_password(&PasswordSource::File(newline_only)),
            Err(AppError::Usage(_))
        ));
    }

    #[test]
    fn password_file_rejects_dash_and_oversize() {
        assert!(matches!(
            resolve_password(&PasswordSource::File(PathBuf::from("-"))),
            Err(AppError::Usage(_))
        ));
        let dir = TempDir::new().unwrap();
        let big = write_file(&dir, "big", &vec![b'a'; PASSWORD_FILE_MAX + 1]);
        assert!(matches!(
            resolve_password(&PasswordSource::File(big)),
            Err(AppError::Usage(_))
        ));
    }

    #[test]
    fn keyfile_reads_bytes_and_enforces_bounds() {
        let dir = TempDir::new().unwrap();
        let kf = write_file(&dir, "key", b"\x00\x01\x02keymaterial");
        assert_eq!(&*read_keyfile(&kf).unwrap(), b"\x00\x01\x02keymaterial");

        let empty = write_file(&dir, "empty", b"");
        assert!(matches!(read_keyfile(&empty), Err(AppError::Usage(_))));

        let big = write_file(&dir, "big", &vec![0u8; KEYFILE_MAX_BYTES + 1]);
        assert!(matches!(read_keyfile(&big), Err(AppError::Usage(_))));

        assert!(matches!(
            read_keyfile(Path::new("-")),
            Err(AppError::Usage(_))
        ));
        assert!(matches!(read_keyfile(dir.path()), Err(AppError::Usage(_)))); // directory
    }

    #[test]
    fn env_set_returns_bytes_and_empty_is_rejected() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let name = "SYMCRYPT_TEST_ENV_SET_xyz789";
        std::env::set_var(name, "s3cret value");
        let src = PasswordSource::Env(OsString::from(name));
        assert_eq!(&*resolve_password(&src).unwrap(), b"s3cret value");
        // A set-but-empty variable is a usage error, never a silent downgrade.
        std::env::set_var(name, "");
        assert!(matches!(resolve_password(&src), Err(AppError::Usage(_))));
        std::env::remove_var(name);
    }

    #[test]
    fn from_flags_selects_correct_variant() {
        assert!(matches!(
            password_source_from_flags(Some(b"x".to_vec()), None, None, false).unwrap(),
            Some(PasswordSource::Inline(_))
        ));
        assert!(matches!(
            password_source_from_flags(None, Some(PathBuf::from("f")), None, false).unwrap(),
            Some(PasswordSource::File(_))
        ));
        assert!(matches!(
            password_source_from_flags(None, None, Some(OsString::from("V")), false).unwrap(),
            Some(PasswordSource::Env(_))
        ));
        assert!(matches!(
            password_source_from_flags(None, None, None, true).unwrap(),
            Some(PasswordSource::NoPassword)
        ));
    }

    #[test]
    fn file_and_keyfile_at_exact_size_limit_are_accepted() {
        let dir = TempDir::new().unwrap();
        // A password file of exactly the limit (no trailing newline) is kept whole.
        let pw = write_file(&dir, "pw_max", &vec![b'a'; PASSWORD_FILE_MAX]);
        assert_eq!(
            resolve_password(&PasswordSource::File(pw)).unwrap().len(),
            PASSWORD_FILE_MAX
        );
        // A keyfile of exactly the limit is accepted.
        let kf = write_file(&dir, "kf_max", &vec![0u8; KEYFILE_MAX_BYTES]);
        assert_eq!(read_keyfile(&kf).unwrap().len(), KEYFILE_MAX_BYTES);
    }

    #[test]
    fn password_file_keeps_content_without_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "pw_no_nl", b"secret");
        assert_eq!(
            &*resolve_password(&PasswordSource::File(p)).unwrap(),
            b"secret"
        );
    }
}
