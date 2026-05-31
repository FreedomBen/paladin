//! Pure UI-state → core-options mapping: KDF cost-knob parsing/validation,
//! stored-name checks (DESIGN §5.2), and `EncryptOptions` assembly. No I/O and
//! no rendering, so every rule here is unit-tested in isolation. The core
//! re-validates everything; these checks exist for fast inline feedback and to
//! keep the exact wording identical to the CLI.

use std::ops::RangeInclusive;

use symcrypt_core as core;

use core::{CipherId, EncryptOptions, KdfId, KdfParams};

// §5.4 ranges, mirrored from core. Kept in sync with `symcrypt-core::kdf`.
const ARGON2_MEMORY_KIB: RangeInclusive<u32> = 8192..=1_048_576;
const ARGON2_TIME: RangeInclusive<u32> = 1..=10;
const ARGON2_PARALLELISM: RangeInclusive<u32> = 1..=16;
const SCRYPT_LOG_N: RangeInclusive<u32> = 10..=20;
const SCRYPT_R: RangeInclusive<u32> = 1..=32;
const SCRYPT_P: RangeInclusive<u32> = 1..=16;
const SCRYPT_MAX_MEM_BYTES: u64 = 1 << 30; // 1 GiB
const PBKDF2_ITERATIONS: RangeInclusive<u32> = 10_000..=10_000_000;

/// Largest stored-name length in bytes (DESIGN §5.2).
const NAME_MAX_BYTES: usize = 255;

/// Cost-knob strings as edited in the UI; only the selected KDF's are read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfKnobs {
    pub argon2_memory_kib: String,
    pub argon2_time_cost: String,
    pub argon2_parallelism: String,
    pub scrypt_log_n: String,
    pub scrypt_r: String,
    pub scrypt_p: String,
    pub pbkdf2_iterations: String,
}

impl KdfKnobs {
    /// Knob strings prefilled from the core §12 defaults for every KDF.
    pub fn defaults() -> Self {
        let (memory_kib, time_cost, parallelism) = match KdfParams::default_for(KdfId::Argon2id) {
            KdfParams::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
            } => (memory_kib, time_cost, parallelism),
            _ => unreachable!("default_for(Argon2id) is Argon2id"),
        };
        let (log_n, r, p) = match KdfParams::default_for(KdfId::Scrypt) {
            KdfParams::Scrypt { log_n, r, p } => (log_n, r, p),
            _ => unreachable!("default_for(Scrypt) is Scrypt"),
        };
        let iterations = match KdfParams::default_for(KdfId::Pbkdf2) {
            KdfParams::Pbkdf2 { iterations } => iterations,
            _ => unreachable!("default_for(Pbkdf2) is Pbkdf2"),
        };
        Self {
            argon2_memory_kib: memory_kib.to_string(),
            argon2_time_cost: time_cost.to_string(),
            argon2_parallelism: parallelism.to_string(),
            scrypt_log_n: log_n.to_string(),
            scrypt_r: r.to_string(),
            scrypt_p: p.to_string(),
            pbkdf2_iterations: iterations.to_string(),
        }
    }
}

fn parse_u32(s: &str, what: &str) -> Result<u32, String> {
    s.trim()
        .parse::<u32>()
        .map_err(|_| format!("{what} must be a whole number"))
}

fn in_range(value: u32, range: &RangeInclusive<u32>, msg: &str) -> Result<u32, String> {
    if range.contains(&value) {
        Ok(value)
    } else {
        Err(msg.to_string())
    }
}

/// Parse and range-check the selected KDF's knobs into a `KdfParams`.
pub fn build_kdf_params(kdf: KdfId, knobs: &KdfKnobs) -> Result<KdfParams, String> {
    match kdf {
        KdfId::Argon2id => {
            let memory_kib = in_range(
                parse_u32(&knobs.argon2_memory_kib, "argon2id memory")?,
                &ARGON2_MEMORY_KIB,
                "argon2id memory out of range (8192..=1048576 KiB)",
            )?;
            let time_cost = in_range(
                parse_u32(&knobs.argon2_time_cost, "argon2id time cost")?,
                &ARGON2_TIME,
                "argon2id time cost out of range (1..=10)",
            )?;
            let parallelism = in_range(
                parse_u32(&knobs.argon2_parallelism, "argon2id parallelism")?,
                &ARGON2_PARALLELISM,
                "argon2id parallelism out of range (1..=16)",
            )?;
            Ok(KdfParams::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
            })
        }
        KdfId::Scrypt => {
            let log_n = in_range(
                parse_u32(&knobs.scrypt_log_n, "scrypt log_n")?,
                &SCRYPT_LOG_N,
                "scrypt log_n out of range (10..=20)",
            )?;
            let r = in_range(
                parse_u32(&knobs.scrypt_r, "scrypt r")?,
                &SCRYPT_R,
                "scrypt r out of range (1..=32)",
            )?;
            let p = in_range(
                parse_u32(&knobs.scrypt_p, "scrypt p")?,
                &SCRYPT_P,
                "scrypt p out of range (1..=16)",
            )?;
            let mem = 128u64 * (1u64 << log_n) * r as u64;
            if mem > SCRYPT_MAX_MEM_BYTES {
                return Err("scrypt memory (128*N*r) exceeds 1 GiB".to_string());
            }
            Ok(KdfParams::Scrypt { log_n, r, p })
        }
        KdfId::Pbkdf2 => {
            let iterations = in_range(
                parse_u32(&knobs.pbkdf2_iterations, "pbkdf2 iterations")?,
                &PBKDF2_ITERATIONS,
                "pbkdf2 iterations out of range (10000..=10000000)",
            )?;
            Ok(KdfParams::Pbkdf2 { iterations })
        }
    }
}

/// Validate a stored-name basename per DESIGN §5.2. Input is already UTF-8 (it
/// comes from a `String`); this checks length, separators, and control chars.
pub fn validate_name(name: &str) -> Result<(), String> {
    let len = name.len();
    if len == 0 || len > NAME_MAX_BYTES {
        return Err("stored name must be 1..=255 bytes".to_string());
    }
    if name == "." || name == ".." {
        return Err("stored name must not be '.' or '..'".to_string());
    }
    for c in name.chars() {
        if matches!(c, '/' | '\\' | ':') {
            return Err("stored name must not contain '/', '\\', or ':'".to_string());
        }
        if c.is_control() {
            return Err("stored name must not contain control characters".to_string());
        }
    }
    Ok(())
}

/// Assemble `EncryptOptions` from the UI selections. `name` is the basename to
/// store when `--name` is enabled (validated here); `chunk_size` stays at the
/// core default (64 KiB) since it is not user-settable in v1.
pub fn build_encrypt_options(
    cipher: CipherId,
    kdf: KdfId,
    knobs: &KdfKnobs,
    armor: bool,
    name: Option<&str>,
) -> Result<EncryptOptions, String> {
    let kdf_params = build_kdf_params(kdf, knobs)?;
    let filename = match name {
        Some(n) => {
            validate_name(n)?;
            Some(n.to_owned())
        }
        None => None,
    };
    Ok(EncryptOptions {
        cipher,
        kdf,
        kdf_params,
        filename,
        armor,
        ..EncryptOptions::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_in_range_for_every_kdf() {
        let knobs = KdfKnobs::defaults();
        for kdf in [KdfId::Argon2id, KdfId::Scrypt, KdfId::Pbkdf2] {
            assert!(build_kdf_params(kdf, &knobs).is_ok(), "{kdf} defaults");
        }
    }

    #[test]
    fn argon2_defaults_map_to_expected_params() {
        let knobs = KdfKnobs::defaults();
        assert_eq!(
            build_kdf_params(KdfId::Argon2id, &knobs).unwrap(),
            KdfParams::default_for(KdfId::Argon2id)
        );
    }

    #[test]
    fn argon2_memory_below_range_is_rejected() {
        let mut knobs = KdfKnobs::defaults();
        knobs.argon2_memory_kib = "8191".to_string();
        let err = build_kdf_params(KdfId::Argon2id, &knobs).unwrap_err();
        assert!(err.contains("8192..=1048576"), "{err}");
    }

    #[test]
    fn argon2_non_numeric_is_rejected() {
        let mut knobs = KdfKnobs::defaults();
        knobs.argon2_time_cost = "abc".to_string();
        let err = build_kdf_params(KdfId::Argon2id, &knobs).unwrap_err();
        assert!(err.contains("whole number"), "{err}");
    }

    #[test]
    fn scrypt_log_n_above_range_is_rejected() {
        let mut knobs = KdfKnobs::defaults();
        knobs.scrypt_log_n = "21".to_string();
        assert!(build_kdf_params(KdfId::Scrypt, &knobs).is_err());
    }

    #[test]
    fn scrypt_memory_cap_is_enforced() {
        // log_n=20, r=32 → 128 * 2^20 * 32 = 4 GiB > 1 GiB.
        let mut knobs = KdfKnobs::defaults();
        knobs.scrypt_log_n = "20".to_string();
        knobs.scrypt_r = "32".to_string();
        knobs.scrypt_p = "1".to_string();
        let err = build_kdf_params(KdfId::Scrypt, &knobs).unwrap_err();
        assert!(err.contains("1 GiB"), "{err}");
    }

    #[test]
    fn scrypt_one_gib_boundary_is_allowed() {
        // log_n=20, r=8 → 128 * 2^20 * 8 = exactly 1 GiB.
        let mut knobs = KdfKnobs::defaults();
        knobs.scrypt_log_n = "20".to_string();
        knobs.scrypt_r = "8".to_string();
        knobs.scrypt_p = "1".to_string();
        assert!(build_kdf_params(KdfId::Scrypt, &knobs).is_ok());
    }

    #[test]
    fn pbkdf2_iterations_bounds() {
        let mut knobs = KdfKnobs::defaults();
        knobs.pbkdf2_iterations = "9999".to_string();
        assert!(build_kdf_params(KdfId::Pbkdf2, &knobs).is_err());
        knobs.pbkdf2_iterations = "10000".to_string();
        assert!(build_kdf_params(KdfId::Pbkdf2, &knobs).is_ok());
    }

    #[test]
    fn valid_names_pass() {
        assert!(validate_name("report.txt").is_ok());
        assert!(validate_name("café.pdf").is_ok()); // multibyte UTF-8
    }

    #[test]
    fn empty_and_overlong_names_rejected() {
        assert!(validate_name("").is_err());
        let long = "a".repeat(256);
        assert!(validate_name(&long).is_err());
    }

    #[test]
    fn names_with_separators_or_dots_rejected() {
        for bad in ["a/b", "a\\b", "a:b", ".", ".."] {
            assert!(validate_name(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn names_with_control_chars_rejected() {
        assert!(validate_name("a\u{0001}b").is_err());
        assert!(validate_name("a\u{007f}b").is_err());
    }

    #[test]
    fn build_options_maps_selections_and_defaults_chunk_size() {
        let knobs = KdfKnobs::defaults();
        let opts = build_encrypt_options(
            CipherId::ChaCha20Poly1305,
            KdfId::Scrypt,
            &knobs,
            true,
            Some("file.txt"),
        )
        .unwrap();
        assert_eq!(opts.cipher, CipherId::ChaCha20Poly1305);
        assert_eq!(opts.kdf, KdfId::Scrypt);
        assert!(opts.armor);
        assert_eq!(opts.filename.as_deref(), Some("file.txt"));
        assert_eq!(opts.chunk_size, EncryptOptions::default().chunk_size);
    }

    #[test]
    fn build_options_rejects_bad_name() {
        let knobs = KdfKnobs::defaults();
        let err = build_encrypt_options(
            CipherId::Aes256Gcm,
            KdfId::Argon2id,
            &knobs,
            false,
            Some("a/b"),
        )
        .unwrap_err();
        assert!(err.contains("'/'"), "{err}");
    }
}
