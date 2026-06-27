//! Pure UI-state → `EncryptOptions`/secret-material logic: secret-policy
//! validation (DESIGN §6.4), KDF knob assembly with §5.4 range checks, and
//! `--name` basename derivation with §5.2 safety rules.
//!
//! This module is medium-independent: no GTK, no I/O, no crypto. It turns the
//! current widget state (raw spin-button values, the password/keyfile fields, a
//! chosen input path) into clean values the worker can hand straight to the
//! core, surfacing user-facing errors up front. The core re-validates these as
//! a backstop, so any rule here mirrors a core check rather than replacing it.

use std::fmt;
use std::path::Path;

use paladin_core::{CipherId, EncryptOptions, KdfId, KdfParams};

/// Maximum embedded-filename length in bytes (DESIGN §5.2).
const NAME_MAX_BYTES: usize = 255;

/// Argon2id `memory_kib` valid range, inclusive (DESIGN §5.4).
const ARGON2_MEMORY_KIB: std::ops::RangeInclusive<u32> = 8192..=1_048_576;
/// Argon2id `time_cost` valid range, inclusive.
const ARGON2_TIME_COST: std::ops::RangeInclusive<u32> = 1..=10;
/// Argon2id `parallelism` valid range, inclusive.
const ARGON2_PARALLELISM: std::ops::RangeInclusive<u32> = 1..=16;
/// scrypt `log_n` valid range, inclusive.
const SCRYPT_LOG_N: std::ops::RangeInclusive<u32> = 10..=20;
/// scrypt `r` valid range, inclusive.
const SCRYPT_R: std::ops::RangeInclusive<u32> = 1..=32;
/// scrypt `p` valid range, inclusive.
const SCRYPT_P: std::ops::RangeInclusive<u32> = 1..=16;
/// PBKDF2 `iterations` valid range, inclusive.
const PBKDF2_ITERATIONS: std::ops::RangeInclusive<u32> = 10_000..=10_000_000;
/// scrypt memory cap: `128 * N * r` must not exceed this many bytes (1 GiB).
const SCRYPT_MEMORY_CAP: u64 = 1 << 30;

// ---------------------------------------------------------------------------
// Secret policy (DESIGN §6.4)
// ---------------------------------------------------------------------------

/// A violation of the UI secret-entry policy (DESIGN §6.4).
///
/// This is the fast, front-end check before the worker calls
/// `Secret::new`, which independently re-validates keyfile size and the like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    /// The confirm-password field does not match the password (Encrypt only).
    ConfirmMismatch,
    /// Keyfile-only mode was selected but no keyfile was provided.
    KeyfileOnlyNeedsKeyfile,
    /// A password is required (not in keyfile-only mode) but the field is empty.
    EmptyPassword,
    /// Neither a password nor a keyfile was supplied.
    EmptySecret,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            SecretError::ConfirmMismatch => "The passwords do not match.",
            SecretError::KeyfileOnlyNeedsKeyfile => {
                "Keyfile-only mode requires a keyfile to be selected."
            }
            SecretError::EmptyPassword => "A password is required.",
            SecretError::EmptySecret => "Enter a password or select a keyfile.",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SecretError {}

/// Validate the secret-entry fields against the UI policy (DESIGN §6.4).
///
/// `confirm` is `Some(..)` only in Encrypt mode (where a confirm field exists)
/// and `None` for Decrypt/Verify. An empty password is accepted *only* in
/// keyfile-only mode. The worker calls `Secret::new(password, keyfile)`
/// afterward, which re-checks keyfile size and other invariants.
pub fn validate_secret(
    password: &[u8],
    confirm: Option<&[u8]>,
    keyfile: Option<&[u8]>,
    keyfile_only: bool,
) -> Result<(), SecretError> {
    if let Some(confirm) = confirm {
        if confirm != password {
            return Err(SecretError::ConfirmMismatch);
        }
    }

    if keyfile_only {
        if keyfile.is_none() {
            return Err(SecretError::KeyfileOnlyNeedsKeyfile);
        }
    } else if password.is_empty() {
        return Err(SecretError::EmptyPassword);
    }

    // Defensive catch-all: nothing to derive a key from at all.
    if password.is_empty() && keyfile.is_none() {
        return Err(SecretError::EmptySecret);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// KDF knobs + ranges (DESIGN §5.4)
// ---------------------------------------------------------------------------

/// The current per-KDF cost-knob values from the spin buttons.
///
/// All KDFs' knobs are held together so the relm4 component can keep one
/// struct; [`build_kdf_params`] reads only the fields the chosen KDF uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnobInput {
    /// Argon2id memory cost, in KiB.
    pub argon2_memory_kib: u32,
    /// Argon2id time cost (number of passes).
    pub argon2_time_cost: u32,
    /// Argon2id parallelism (lanes).
    pub argon2_parallelism: u32,
    /// scrypt log₂(N) cost parameter.
    pub scrypt_log_n: u32,
    /// scrypt block-size parameter `r`.
    pub scrypt_r: u32,
    /// scrypt parallelization parameter `p`.
    pub scrypt_p: u32,
    /// PBKDF2-HMAC-SHA256 iteration count.
    pub pbkdf2_iterations: u32,
}

impl Default for KnobInput {
    fn default() -> Self {
        let KdfParams::Argon2id {
            memory_kib: argon2_memory_kib,
            time_cost: argon2_time_cost,
            parallelism: argon2_parallelism,
        } = KdfParams::default_for(KdfId::Argon2id)
        else {
            unreachable!("default_for(Argon2id) is the Argon2id variant")
        };
        let KdfParams::Scrypt {
            log_n: scrypt_log_n,
            r: scrypt_r,
            p: scrypt_p,
        } = KdfParams::default_for(KdfId::Scrypt)
        else {
            unreachable!("default_for(Scrypt) is the Scrypt variant")
        };
        let KdfParams::Pbkdf2 {
            iterations: pbkdf2_iterations,
        } = KdfParams::default_for(KdfId::Pbkdf2)
        else {
            unreachable!("default_for(Pbkdf2) is the Pbkdf2 variant")
        };
        Self {
            argon2_memory_kib,
            argon2_time_cost,
            argon2_parallelism,
            scrypt_log_n,
            scrypt_r,
            scrypt_p,
            pbkdf2_iterations,
        }
    }
}

/// A KDF knob that fell outside its DESIGN §5.4 range.
///
/// Each variant names the offending knob and carries no extra data; its
/// `Display` text states the valid inclusive range so the UI can surface it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnobError {
    /// Argon2id `memory_kib` out of range.
    Argon2Memory,
    /// Argon2id `time_cost` out of range.
    Argon2TimeCost,
    /// Argon2id `parallelism` out of range.
    Argon2Parallelism,
    /// scrypt `log_n` out of range.
    ScryptLogN,
    /// scrypt `r` out of range.
    ScryptR,
    /// scrypt `p` out of range.
    ScryptP,
    /// scrypt `128 * N * r` exceeds the 1 GiB memory cap.
    ScryptMemoryCap,
    /// PBKDF2 `iterations` out of range.
    Pbkdf2Iterations,
}

impl fmt::Display for KnobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            KnobError::Argon2Memory => "Argon2id memory must be between 8192 and 1048576 KiB.",
            KnobError::Argon2TimeCost => "Argon2id time cost must be between 1 and 10.",
            KnobError::Argon2Parallelism => "Argon2id parallelism must be between 1 and 16.",
            KnobError::ScryptLogN => "scrypt log_n must be between 10 and 20.",
            KnobError::ScryptR => "scrypt r must be between 1 and 32.",
            KnobError::ScryptP => "scrypt p must be between 1 and 16.",
            KnobError::ScryptMemoryCap => {
                "scrypt parameters exceed the 1 GiB memory cap (128 * N * r must be <= 1 GiB)."
            }
            KnobError::Pbkdf2Iterations => "PBKDF2 iterations must be between 10000 and 10000000.",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for KnobError {}

/// Build the chosen KDF's [`KdfParams`] from the spin-button [`KnobInput`],
/// validating each knob against its DESIGN §5.4 range.
///
/// Only the selected KDF's fields are read; the others are ignored. scrypt also
/// enforces the `128 * N * r <= 1 GiB` memory cap (computed in `u64`).
pub fn build_kdf_params(kdf: KdfId, knobs: &KnobInput) -> Result<KdfParams, KnobError> {
    match kdf {
        KdfId::Argon2id => {
            if !ARGON2_MEMORY_KIB.contains(&knobs.argon2_memory_kib) {
                return Err(KnobError::Argon2Memory);
            }
            if !ARGON2_TIME_COST.contains(&knobs.argon2_time_cost) {
                return Err(KnobError::Argon2TimeCost);
            }
            if !ARGON2_PARALLELISM.contains(&knobs.argon2_parallelism) {
                return Err(KnobError::Argon2Parallelism);
            }
            Ok(KdfParams::Argon2id {
                memory_kib: knobs.argon2_memory_kib,
                time_cost: knobs.argon2_time_cost,
                parallelism: knobs.argon2_parallelism,
            })
        }
        KdfId::Scrypt => {
            if !SCRYPT_LOG_N.contains(&knobs.scrypt_log_n) {
                return Err(KnobError::ScryptLogN);
            }
            if !SCRYPT_R.contains(&knobs.scrypt_r) {
                return Err(KnobError::ScryptR);
            }
            if !SCRYPT_P.contains(&knobs.scrypt_p) {
                return Err(KnobError::ScryptP);
            }
            // log_n is validated <= 20, so 1 << log_n cannot overflow u64.
            let mem = 128u64 * (1u64 << knobs.scrypt_log_n) * u64::from(knobs.scrypt_r);
            if mem > SCRYPT_MEMORY_CAP {
                return Err(KnobError::ScryptMemoryCap);
            }
            Ok(KdfParams::Scrypt {
                log_n: knobs.scrypt_log_n,
                r: knobs.scrypt_r,
                p: knobs.scrypt_p,
            })
        }
        KdfId::Pbkdf2 => {
            if !PBKDF2_ITERATIONS.contains(&knobs.pbkdf2_iterations) {
                return Err(KnobError::Pbkdf2Iterations);
            }
            Ok(KdfParams::Pbkdf2 {
                iterations: knobs.pbkdf2_iterations,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// `--name` basename derivation (DESIGN §5.2)
// ---------------------------------------------------------------------------

/// Why an input path could not yield a safe embedded filename (DESIGN §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// The path has no final path component to use as a name.
    NoBasename,
    /// The basename is not valid UTF-8 and cannot be embedded as a string.
    NotUtf8,
    /// The basename is unsafe to embed (`.`/`..`, a separator, or a control).
    Unsafe(&'static str),
    /// The basename is longer than 255 bytes.
    TooLong,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::NoBasename => f.write_str("The input path has no filename to embed."),
            NameError::NotUtf8 => {
                f.write_str("The filename is not valid UTF-8 and cannot be embedded.")
            }
            NameError::Unsafe(reason) => {
                write!(f, "The filename cannot be embedded: {reason}.")
            }
            NameError::TooLong => {
                write!(
                    f,
                    "The filename is too long to embed (max {NAME_MAX_BYTES} bytes)."
                )
            }
        }
    }
}

impl std::error::Error for NameError {}

/// Derive a safe embedded filename from `input`'s final component (DESIGN §5.2).
///
/// Rejects a missing/empty basename, non-UTF-8 bytes, `.`/`..`, any
/// path separator (`/`, `\`, `:`) or control character (which `char::is_control`
/// covers: NUL, C0, DEL, and C1), and names longer than 255 bytes.
pub fn derive_name(input: &Path) -> Result<String, NameError> {
    let basename = input.file_name().ok_or(NameError::NoBasename)?;
    let name = basename.to_str().ok_or(NameError::NotUtf8)?;

    if name.is_empty() {
        return Err(NameError::NoBasename);
    }
    if name == "." || name == ".." {
        return Err(NameError::Unsafe("\".\" and \"..\" are not allowed"));
    }
    if name
        .chars()
        .any(|c| matches!(c, '/' | '\\' | ':') || c.is_control())
    {
        return Err(NameError::Unsafe(
            "it contains a path separator or control character",
        ));
    }
    if name.len() > NAME_MAX_BYTES {
        return Err(NameError::TooLong);
    }

    Ok(name.to_owned())
}

// ---------------------------------------------------------------------------
// Assemble EncryptOptions
// ---------------------------------------------------------------------------

/// An error assembling [`EncryptOptions`] from UI state: a bad KDF knob or an
/// unembeddable filename. Delegates its `Display` to the inner error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionsError {
    /// A KDF cost knob was out of range.
    Knob(KnobError),
    /// The `--name` basename could not be derived.
    Name(NameError),
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionsError::Knob(e) => fmt::Display::fmt(e, f),
            OptionsError::Name(e) => fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for OptionsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OptionsError::Knob(e) => Some(e),
            OptionsError::Name(e) => Some(e),
        }
    }
}

impl From<KnobError> for OptionsError {
    fn from(e: KnobError) -> Self {
        OptionsError::Knob(e)
    }
}

impl From<NameError> for OptionsError {
    fn from(e: NameError) -> Self {
        OptionsError::Name(e)
    }
}

/// Assemble [`EncryptOptions`] from the current Encrypt-form state.
///
/// Validates and selects the KDF params, derives the embedded filename when
/// `name_enabled`, and fixes `chunk_size` at the v1 value of 65536 (not
/// user-settable here).
pub fn build_encrypt_options(
    input: &Path,
    cipher: CipherId,
    kdf: KdfId,
    knobs: &KnobInput,
    name_enabled: bool,
    armor: bool,
) -> Result<EncryptOptions, OptionsError> {
    let kdf_params = build_kdf_params(kdf, knobs)?;
    let filename = if name_enabled {
        Some(derive_name(input)?)
    } else {
        None
    };
    Ok(EncryptOptions {
        cipher,
        kdf,
        kdf_params,
        chunk_size: 65536,
        filename,
        armor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    /// Build a [`KnobInput`] from the defaults with a single field tweaked,
    /// keeping each test's intent to one line.
    fn knobs(mutate: impl FnOnce(&mut KnobInput)) -> KnobInput {
        let mut k = KnobInput::default();
        mutate(&mut k);
        k
    }

    // ----- Secret policy -------------------------------------------------

    #[test]
    fn secret_confirm_mismatch_is_rejected() {
        let err = validate_secret(b"hunter2", Some(b"hunter3"), None, false).unwrap_err();
        assert_eq!(err, SecretError::ConfirmMismatch);
    }

    #[test]
    fn secret_confirm_match_non_empty_no_keyfile_ok() {
        assert!(validate_secret(b"hunter2", Some(b"hunter2"), None, false).is_ok());
    }

    #[test]
    fn secret_empty_password_not_keyfile_only_is_rejected() {
        let err = validate_secret(b"", Some(b""), None, false).unwrap_err();
        assert_eq!(err, SecretError::EmptyPassword);
    }

    #[test]
    fn secret_keyfile_only_without_keyfile_is_rejected() {
        let err = validate_secret(b"", None, None, true).unwrap_err();
        assert_eq!(err, SecretError::KeyfileOnlyNeedsKeyfile);
    }

    #[test]
    fn secret_keyfile_only_with_keyfile_empty_password_ok() {
        assert!(validate_secret(b"", None, Some(b"keybytes"), true).is_ok());
    }

    #[test]
    fn secret_keyfile_only_with_keyfile_and_password_ok() {
        assert!(validate_secret(b"pw", None, Some(b"keybytes"), true).is_ok());
    }

    #[test]
    fn secret_empty_password_no_keyfile_not_keyfile_only_is_error() {
        // No confirm field here (Decrypt-shaped call) still rejects empties.
        let err = validate_secret(b"", None, None, false).unwrap_err();
        assert_eq!(err, SecretError::EmptyPassword);
    }

    #[test]
    fn secret_decrypt_verify_non_empty_ok() {
        // Decrypt/Verify: confirm is None.
        assert!(validate_secret(b"hunter2", None, None, false).is_ok());
    }

    #[test]
    fn secret_decrypt_verify_empty_without_keyfile_is_error() {
        let err = validate_secret(b"", None, None, false).unwrap_err();
        assert_eq!(err, SecretError::EmptyPassword);
    }

    #[test]
    fn secret_confirm_checked_before_keyfile_only() {
        // Mismatch wins even in keyfile-only mode.
        let err = validate_secret(b"a", Some(b"b"), Some(b"k"), true).unwrap_err();
        assert_eq!(err, SecretError::ConfirmMismatch);
    }

    #[test]
    fn secret_error_display_and_trait_object() {
        // Each message is a clear, user-facing sentence; usable as dyn Error.
        for e in [
            SecretError::ConfirmMismatch,
            SecretError::KeyfileOnlyNeedsKeyfile,
            SecretError::EmptyPassword,
            SecretError::EmptySecret,
        ] {
            let s = e.to_string();
            assert!(!s.is_empty());
            let _dyn: &dyn std::error::Error = &e;
        }
    }

    // ----- KDF knobs -----------------------------------------------------

    #[test]
    fn knob_defaults_match_core_defaults() {
        let knobs = KnobInput::default();
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs).unwrap(),
            KdfParams::default_for(KdfId::Argon2id)
        );
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs).unwrap(),
            KdfParams::default_for(KdfId::Scrypt)
        );
        assert_eq!(
            build_kdf_params(KdfId::Pbkdf2, &knobs).unwrap(),
            KdfParams::default_for(KdfId::Pbkdf2)
        );
    }

    #[test]
    fn knob_argon2_memory_below_min_and_above_max() {
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs(|k| k.argon2_memory_kib = 8191)).unwrap_err(),
            KnobError::Argon2Memory
        );
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs(|k| k.argon2_memory_kib = 1_048_577))
                .unwrap_err(),
            KnobError::Argon2Memory
        );
    }

    #[test]
    fn knob_argon2_memory_bounds_inclusive() {
        assert!(build_kdf_params(KdfId::Argon2id, &knobs(|k| k.argon2_memory_kib = 8192)).is_ok());
        assert!(
            build_kdf_params(KdfId::Argon2id, &knobs(|k| k.argon2_memory_kib = 1_048_576)).is_ok()
        );
    }

    #[test]
    fn knob_argon2_time_cost_out_of_range() {
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs(|k| k.argon2_time_cost = 0)).unwrap_err(),
            KnobError::Argon2TimeCost
        );
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs(|k| k.argon2_time_cost = 11)).unwrap_err(),
            KnobError::Argon2TimeCost
        );
    }

    #[test]
    fn knob_argon2_parallelism_out_of_range() {
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs(|k| k.argon2_parallelism = 0)).unwrap_err(),
            KnobError::Argon2Parallelism
        );
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs(|k| k.argon2_parallelism = 17)).unwrap_err(),
            KnobError::Argon2Parallelism
        );
    }

    #[test]
    fn knob_scrypt_log_n_out_of_range() {
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs(|k| k.scrypt_log_n = 9)).unwrap_err(),
            KnobError::ScryptLogN
        );
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs(|k| k.scrypt_log_n = 21)).unwrap_err(),
            KnobError::ScryptLogN
        );
    }

    #[test]
    fn knob_scrypt_r_out_of_range() {
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs(|k| k.scrypt_r = 0)).unwrap_err(),
            KnobError::ScryptR
        );
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs(|k| k.scrypt_r = 33)).unwrap_err(),
            KnobError::ScryptR
        );
    }

    #[test]
    fn knob_scrypt_p_out_of_range() {
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs(|k| k.scrypt_p = 0)).unwrap_err(),
            KnobError::ScryptP
        );
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs(|k| k.scrypt_p = 17)).unwrap_err(),
            KnobError::ScryptP
        );
    }

    #[test]
    fn knob_scrypt_memory_cap_rejected() {
        // log_n=20, r=32 => 128 * 2^20 * 32 = 4 GiB, over the 1 GiB cap.
        let knobs = knobs(|k| {
            k.scrypt_log_n = 20;
            k.scrypt_r = 32;
        });
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs).unwrap_err(),
            KnobError::ScryptMemoryCap
        );
    }

    #[test]
    fn knob_scrypt_memory_cap_boundary_allowed() {
        // log_n=20, r=8 => 128 * 2^20 * 8 = exactly 1 GiB: allowed.
        let knobs = knobs(|k| {
            k.scrypt_log_n = 20;
            k.scrypt_r = 8;
        });
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs).unwrap(),
            KdfParams::Scrypt {
                log_n: 20,
                r: 8,
                p: 1
            }
        );
    }

    #[test]
    fn knob_pbkdf2_iterations_out_of_range() {
        assert_eq!(
            build_kdf_params(KdfId::Pbkdf2, &knobs(|k| k.pbkdf2_iterations = 9_999)).unwrap_err(),
            KnobError::Pbkdf2Iterations
        );
        assert_eq!(
            build_kdf_params(KdfId::Pbkdf2, &knobs(|k| k.pbkdf2_iterations = 10_000_001))
                .unwrap_err(),
            KnobError::Pbkdf2Iterations
        );
    }

    #[test]
    fn knob_pbkdf2_iterations_bounds_inclusive() {
        assert!(build_kdf_params(KdfId::Pbkdf2, &knobs(|k| k.pbkdf2_iterations = 10_000)).is_ok());
        assert!(
            build_kdf_params(KdfId::Pbkdf2, &knobs(|k| k.pbkdf2_iterations = 10_000_000)).is_ok()
        );
    }

    #[test]
    fn knob_build_scrypt_ignores_other_kdf_fields() {
        // Garbage argon/pbkdf2 fields must not affect a Scrypt build.
        let knobs = KnobInput {
            argon2_memory_kib: 0,
            argon2_time_cost: 0,
            argon2_parallelism: 0,
            scrypt_log_n: 15,
            scrypt_r: 8,
            scrypt_p: 1,
            pbkdf2_iterations: 0,
        };
        assert_eq!(
            build_kdf_params(KdfId::Scrypt, &knobs).unwrap(),
            KdfParams::Scrypt {
                log_n: 15,
                r: 8,
                p: 1
            }
        );
    }

    #[test]
    fn knob_build_argon2_ignores_other_kdf_fields() {
        let knobs = KnobInput {
            argon2_memory_kib: 65536,
            argon2_time_cost: 3,
            argon2_parallelism: 1,
            scrypt_log_n: 0,
            scrypt_r: 0,
            scrypt_p: 0,
            pbkdf2_iterations: 0,
        };
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs).unwrap(),
            KdfParams::Argon2id {
                memory_kib: 65536,
                time_cost: 3,
                parallelism: 1
            }
        );
    }

    #[test]
    fn knob_build_pbkdf2_ignores_other_kdf_fields() {
        let knobs = KnobInput {
            argon2_memory_kib: 0,
            argon2_time_cost: 0,
            argon2_parallelism: 0,
            scrypt_log_n: 0,
            scrypt_r: 0,
            scrypt_p: 0,
            pbkdf2_iterations: 600_000,
        };
        assert_eq!(
            build_kdf_params(KdfId::Pbkdf2, &knobs).unwrap(),
            KdfParams::Pbkdf2 {
                iterations: 600_000
            }
        );
    }

    #[test]
    fn knob_error_messages_name_range() {
        assert!(KnobError::Argon2Memory
            .to_string()
            .contains("8192 and 1048576"));
        assert!(KnobError::ScryptMemoryCap.to_string().contains("1 GiB"));
        assert!(KnobError::Pbkdf2Iterations
            .to_string()
            .contains("10000 and 10000000"));
        let _dyn: &dyn std::error::Error = &KnobError::ScryptR;
    }

    // ----- Name derivation ----------------------------------------------

    #[test]
    fn name_simple_path() {
        assert_eq!(
            derive_name(Path::new("/tmp/notes.txt")).unwrap(),
            "notes.txt"
        );
    }

    #[test]
    fn name_non_utf8_basename_is_not_utf8() {
        // Build a path whose final component is invalid UTF-8.
        let bad = PathBuf::from(OsStr::from_bytes(b"/tmp/\xff\x01.bin"));
        assert_eq!(derive_name(&bad).unwrap_err(), NameError::NotUtf8);
    }

    #[test]
    fn name_255_bytes_ok_256_too_long() {
        let ok: String = "a".repeat(255);
        assert_eq!(derive_name(Path::new(&format!("/tmp/{ok}"))).unwrap(), ok);
        let too_long: String = "a".repeat(256);
        assert_eq!(
            derive_name(Path::new(&format!("/tmp/{too_long}"))).unwrap_err(),
            NameError::TooLong
        );
    }

    #[test]
    fn name_with_colon_is_unsafe() {
        assert!(matches!(
            derive_name(Path::new("/tmp/a:b")).unwrap_err(),
            NameError::Unsafe(_)
        ));
    }

    #[test]
    fn name_with_backslash_is_unsafe() {
        // file_name() keeps a backslash as part of the component on unix.
        let p = PathBuf::from(OsStr::from_bytes(b"/tmp/a\\b"));
        assert!(matches!(derive_name(&p).unwrap_err(), NameError::Unsafe(_)));
    }

    #[test]
    fn name_with_control_char_is_unsafe() {
        let p = PathBuf::from(OsStr::from_bytes(b"/tmp/a\tb"));
        assert!(matches!(derive_name(&p).unwrap_err(), NameError::Unsafe(_)));
    }

    #[test]
    fn name_with_nul_is_unsafe() {
        let p = PathBuf::from(OsStr::from_bytes(b"/tmp/a\0b"));
        assert!(matches!(derive_name(&p).unwrap_err(), NameError::Unsafe(_)));
    }

    #[test]
    fn name_dot_and_dotdot_rejected() {
        assert!(matches!(
            derive_name(Path::new(".")).unwrap_err(),
            NameError::Unsafe(_) | NameError::NoBasename
        ));
        // Path::file_name() returns None for "..", surfaced as NoBasename.
        assert!(matches!(
            derive_name(Path::new("..")).unwrap_err(),
            NameError::Unsafe(_) | NameError::NoBasename
        ));
    }

    #[test]
    fn name_dotdot_component_rejected() {
        // A trailing ".." inside a longer path: file_name() yields None,
        // so this is NoBasename; either way it is rejected.
        assert!(derive_name(Path::new("/tmp/..")).is_err());
    }

    #[test]
    fn name_root_has_no_basename() {
        assert_eq!(
            derive_name(Path::new("/")).unwrap_err(),
            NameError::NoBasename
        );
    }

    #[test]
    fn name_error_display_and_trait_object() {
        for e in [
            NameError::NoBasename,
            NameError::NotUtf8,
            NameError::Unsafe("reason"),
            NameError::TooLong,
        ] {
            assert!(!e.to_string().is_empty());
            let _dyn: &dyn std::error::Error = &e;
        }
    }

    // ----- build_encrypt_options ----------------------------------------

    #[test]
    fn options_defaults_land_correctly() {
        let opts = build_encrypt_options(
            Path::new("/tmp/notes.txt"),
            CipherId::Aes256Gcm,
            KdfId::Argon2id,
            &KnobInput::default(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(opts.cipher, CipherId::Aes256Gcm);
        assert_eq!(opts.kdf, KdfId::Argon2id);
        assert_eq!(opts.kdf_params, KdfParams::default_for(KdfId::Argon2id));
        assert_eq!(opts.chunk_size, 65536);
        assert!(!opts.armor);
        assert_eq!(opts.filename, None);
    }

    #[test]
    fn options_name_enabled_sets_filename() {
        let opts = build_encrypt_options(
            Path::new("/tmp/notes.txt"),
            CipherId::ChaCha20Poly1305,
            KdfId::Pbkdf2,
            &KnobInput::default(),
            true,
            true,
        )
        .unwrap();
        assert_eq!(opts.filename.as_deref(), Some("notes.txt"));
        assert_eq!(opts.cipher, CipherId::ChaCha20Poly1305);
        assert!(opts.armor);
    }

    #[test]
    fn options_name_disabled_no_filename() {
        let opts = build_encrypt_options(
            Path::new("/tmp/notes.txt"),
            CipherId::Aes256Gcm,
            KdfId::Argon2id,
            &KnobInput::default(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(opts.filename, None);
    }

    #[test]
    fn options_out_of_range_knob_is_knob_error() {
        let err = build_encrypt_options(
            Path::new("/tmp/notes.txt"),
            CipherId::Aes256Gcm,
            KdfId::Argon2id,
            &knobs(|k| k.argon2_memory_kib = 1),
            false,
            false,
        )
        .unwrap_err();
        assert_eq!(err, OptionsError::Knob(KnobError::Argon2Memory));
        // Display delegates to the inner knob error.
        assert_eq!(err.to_string(), KnobError::Argon2Memory.to_string());
    }

    #[test]
    fn options_bad_name_with_name_enabled_is_name_error() {
        let err = build_encrypt_options(
            Path::new("/tmp/a:b"),
            CipherId::Aes256Gcm,
            KdfId::Argon2id,
            &KnobInput::default(),
            true,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, OptionsError::Name(NameError::Unsafe(_))));
    }

    #[test]
    fn options_error_is_trait_object_with_source() {
        let err = OptionsError::Knob(KnobError::ScryptR);
        let _dyn: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_some());
    }

    // ----- Cipher/KDF selector vocabulary -------------------------------

    #[test]
    fn cipher_id_round_trips_through_string() {
        for c in [CipherId::Aes256Gcm, CipherId::ChaCha20Poly1305] {
            let parsed: CipherId = c.to_string().parse().unwrap();
            assert_eq!(parsed, c);
        }
    }

    #[test]
    fn kdf_id_round_trips_through_string() {
        for k in [KdfId::Argon2id, KdfId::Scrypt, KdfId::Pbkdf2] {
            let parsed: KdfId = k.to_string().parse().unwrap();
            assert_eq!(parsed, k);
        }
    }
}
