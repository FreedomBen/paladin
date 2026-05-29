//! KDF identity, parameter encoding, defaults, and key derivation
//! (DESIGN §4.2, §5.4, §12).
//!
//! The §5.4 cost ranges are validated by [`KdfParams::validate`], which returns
//! the failing check's name. The *caller* chooses the error variant: a header
//! read maps it to [`SymError::MalformedHeader`] (exit 4); user-supplied
//! encryption knobs map it to [`SymError::InvalidOptions`] (exit 2). All
//! validation happens before any allocation or key derivation.

use std::fmt;
use std::io;
use std::str::FromStr;

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, SymError};

// --- §5.4 cost ranges (KDF portion) ---
const ARGON2_MEMORY_KIB: std::ops::RangeInclusive<u32> = 8192..=1_048_576;
const ARGON2_TIME: std::ops::RangeInclusive<u32> = 1..=10;
const ARGON2_PARALLELISM: std::ops::RangeInclusive<u32> = 1..=16;
const SCRYPT_LOG_N: std::ops::RangeInclusive<u32> = 10..=20;
const SCRYPT_R: std::ops::RangeInclusive<u32> = 1..=32;
const SCRYPT_P: std::ops::RangeInclusive<u32> = 1..=16;
const SCRYPT_MAX_MEM_BYTES: u64 = 1 << 30; // 1 GiB
const PBKDF2_ITERATIONS: std::ops::RangeInclusive<u32> = 10_000..=10_000_000;

/// The derived AEAD key length: 256-bit (DESIGN §4.1).
const KEY_LEN: usize = 32;

/// KDF selector. The default for new files is [`KdfId::Argon2id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfId {
    /// Argon2id, memory-hard (id `0x01`).
    Argon2id,
    /// scrypt, memory-hard (id `0x02`).
    Scrypt,
    /// PBKDF2-HMAC-SHA256, iteration-hard compatibility option (id `0x03`).
    Pbkdf2,
}

impl KdfId {
    /// The canonical lowercase name (DESIGN §6.3). No aliases, no case folding.
    pub fn as_str(self) -> &'static str {
        match self {
            KdfId::Argon2id => "argon2id",
            KdfId::Scrypt => "scrypt",
            KdfId::Pbkdf2 => "pbkdf2",
        }
    }

    /// On-disk `kdf_id` byte (DESIGN §5.3).
    // Wired up by header.rs in a later core task.
    #[allow(dead_code)]
    pub(crate) fn id(self) -> u8 {
        match self {
            KdfId::Argon2id => 0x01,
            KdfId::Scrypt => 0x02,
            KdfId::Pbkdf2 => 0x03,
        }
    }

    /// Parse a `kdf_id` byte read from a header. An unrecognized id is
    /// [`SymError::UnknownKdf`] (exit 4), never a guess.
    // Wired up by header.rs in a later core task.
    #[allow(dead_code)]
    pub(crate) fn from_id(id: u8) -> Result<Self> {
        match id {
            0x01 => Ok(KdfId::Argon2id),
            0x02 => Ok(KdfId::Scrypt),
            0x03 => Ok(KdfId::Pbkdf2),
            other => Err(SymError::UnknownKdf(other)),
        }
    }
}

impl fmt::Display for KdfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KdfId {
    type Err = SymError;

    /// Exact, lowercase match only (DESIGN §6.3). An unknown name is a usage
    /// error ([`SymError::InvalidOptions`], exit 2).
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "argon2id" => Ok(KdfId::Argon2id),
            "scrypt" => Ok(KdfId::Scrypt),
            "pbkdf2" => Ok(KdfId::Pbkdf2),
            _ => Err(SymError::InvalidOptions(
                "unknown kdf (expected argon2id, scrypt, or pbkdf2)",
            )),
        }
    }
}

/// KDF cost parameters. The variant must match the selected [`KdfId`]; the three
/// stored words map to the `kdf_p*` header fields per DESIGN §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfParams {
    /// Argon2id: memory cost (KiB), time cost (passes), parallelism (lanes).
    Argon2id {
        memory_kib: u32,
        time_cost: u32,
        parallelism: u32,
    },
    /// scrypt: log₂(N), block-size `r`, parallelization `p`.
    Scrypt { log_n: u32, r: u32, p: u32 },
    /// PBKDF2-HMAC-SHA256: iteration count (reserved words are always 0).
    Pbkdf2 { iterations: u32 },
}

impl KdfParams {
    /// The secure default parameters for `kdf` (DESIGN §12). Front-ends use this
    /// for any cost knob the user did not override.
    pub fn default_for(kdf: KdfId) -> Self {
        match kdf {
            KdfId::Argon2id => KdfParams::Argon2id {
                memory_kib: 65536,
                time_cost: 3,
                parallelism: 1,
            },
            KdfId::Scrypt => KdfParams::Scrypt {
                log_n: 15,
                r: 8,
                p: 1,
            },
            KdfId::Pbkdf2 => KdfParams::Pbkdf2 {
                iterations: 600_000,
            },
        }
    }

    /// The [`KdfId`] this parameter variant belongs to.
    pub(crate) fn kdf_id(&self) -> KdfId {
        match self {
            KdfParams::Argon2id { .. } => KdfId::Argon2id,
            KdfParams::Scrypt { .. } => KdfId::Scrypt,
            KdfParams::Pbkdf2 { .. } => KdfId::Pbkdf2,
        }
    }

    /// Encode as the three `kdf_p*` header words (DESIGN §5.4). PBKDF2's reserved
    /// words are 0.
    // Wired up by header.rs in a later core task.
    #[allow(dead_code)]
    pub(crate) fn to_words(self) -> (u32, u32, u32) {
        match self {
            KdfParams::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
            } => (memory_kib, time_cost, parallelism),
            KdfParams::Scrypt { log_n, r, p } => (log_n, r, p),
            KdfParams::Pbkdf2 { iterations } => (iterations, 0, 0),
        }
    }

    /// Decode the `kdf_id` + three `kdf_p*` words from a header into validated
    /// parameters. Enforces PBKDF2's reserved-zero rule and all §5.4 ranges,
    /// returning the failing check's name so the caller can map it to
    /// `MalformedHeader`. Validation precedes any key derivation.
    // Wired up by header.rs in a later core task.
    #[allow(dead_code)]
    pub(crate) fn from_words(
        kdf: KdfId,
        p1: u32,
        p2: u32,
        p3: u32,
    ) -> std::result::Result<Self, &'static str> {
        let params = match kdf {
            KdfId::Argon2id => KdfParams::Argon2id {
                memory_kib: p1,
                time_cost: p2,
                parallelism: p3,
            },
            KdfId::Scrypt => KdfParams::Scrypt {
                log_n: p1,
                r: p2,
                p: p3,
            },
            KdfId::Pbkdf2 => {
                if p2 != 0 || p3 != 0 {
                    return Err("pbkdf2 reserved words must be zero");
                }
                KdfParams::Pbkdf2 { iterations: p1 }
            }
        };
        params.validate()?;
        Ok(params)
    }

    /// Validate the cost parameters against the §5.4 ranges, returning the
    /// failing check's name. The caller maps it to `MalformedHeader` (header
    /// read) or `InvalidOptions` (user-supplied) per DESIGN §5.4.
    // Wired up by header.rs / the encrypt path in a later core task.
    #[allow(dead_code)]
    pub(crate) fn validate(&self) -> std::result::Result<(), &'static str> {
        match *self {
            KdfParams::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
            } => {
                if !ARGON2_MEMORY_KIB.contains(&memory_kib) {
                    return Err("argon2id memory out of range (8192..=1048576 KiB)");
                }
                if !ARGON2_TIME.contains(&time_cost) {
                    return Err("argon2id time cost out of range (1..=10)");
                }
                if !ARGON2_PARALLELISM.contains(&parallelism) {
                    return Err("argon2id parallelism out of range (1..=16)");
                }
            }
            KdfParams::Scrypt { log_n, r, p } => {
                if !SCRYPT_LOG_N.contains(&log_n) {
                    return Err("scrypt log_n out of range (10..=20)");
                }
                if !SCRYPT_R.contains(&r) {
                    return Err("scrypt r out of range (1..=32)");
                }
                if !SCRYPT_P.contains(&p) {
                    return Err("scrypt p out of range (1..=16)");
                }
                // 128 * N * r must fit the 1 GiB cap. log_n is validated <= 20
                // above, so the shift and products stay well within u64.
                let mem = 128u64 * (1u64 << log_n) * u64::from(r);
                if mem > SCRYPT_MAX_MEM_BYTES {
                    return Err("scrypt memory (128*N*r) exceeds 1 GiB");
                }
            }
            KdfParams::Pbkdf2 { iterations } => {
                if !PBKDF2_ITERATIONS.contains(&iterations) {
                    return Err("pbkdf2 iterations out of range (10000..=10000000)");
                }
            }
        }
        Ok(())
    }

    /// Derive the 32-byte AEAD key from the domain-separated secret input and
    /// the per-file salt (DESIGN §4.2). The key is returned in a [`Zeroizing`]
    /// buffer wiped on drop.
    ///
    /// Precondition: `self` has already passed [`validate`](Self::validate); the
    /// flows validate before deriving. A theoretical resource/param failure on
    /// validated input is mapped to a general error (exit 1) rather than
    /// panicking, since the core never exits the process.
    // Wired up by stream.rs in a later core task.
    #[allow(dead_code)]
    pub(crate) fn derive_key(
        &self,
        secret_input: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        match *self {
            KdfParams::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
            } => {
                let params = Argon2Params::new(memory_kib, time_cost, parallelism, Some(KEY_LEN))
                    .map_err(|_| kdf_failure())?;
                let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                argon
                    .hash_password_into(secret_input, salt, key.as_mut_slice())
                    .map_err(|_| kdf_failure())?;
            }
            KdfParams::Scrypt { log_n, r, p } => {
                // scrypt 0.12 Params::new takes (log_n, r, p); the derived
                // length comes from the output buffer passed to scrypt().
                let params = ScryptParams::new(log_n as u8, r, p).map_err(|_| kdf_failure())?;
                scrypt(secret_input, salt, &params, key.as_mut_slice())
                    .map_err(|_| kdf_failure())?;
            }
            KdfParams::Pbkdf2 { iterations } => {
                pbkdf2_hmac::<Sha256>(secret_input, salt, iterations, key.as_mut_slice());
            }
        }
        Ok(key)
    }
}

/// A KDF resource/parameter failure on already-validated input (e.g. memory
/// exhaustion). Mapped to a general error so the variant set stays as DESIGN
/// §6.6 specifies.
fn kdf_failure() -> SymError {
    SymError::Io(io::Error::other(
        "key derivation failed (resource exhaustion or invalid parameters)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_ids() -> [KdfId; 3] {
        [KdfId::Argon2id, KdfId::Scrypt, KdfId::Pbkdf2]
    }

    /// Fast, in-range parameters for derivation tests.
    fn cheap(kdf: KdfId) -> KdfParams {
        match kdf {
            KdfId::Argon2id => KdfParams::Argon2id {
                memory_kib: 8192,
                time_cost: 1,
                parallelism: 1,
            },
            KdfId::Scrypt => KdfParams::Scrypt {
                log_n: 10,
                r: 1,
                p: 1,
            },
            KdfId::Pbkdf2 => KdfParams::Pbkdf2 { iterations: 10_000 },
        }
    }

    #[test]
    fn name_round_trip_and_alias_case_rejection() {
        for id in all_ids() {
            assert_eq!(id.as_str().parse::<KdfId>().unwrap(), id);
            assert_eq!(id.to_string(), id.as_str());
        }
        for bad in [
            "Argon2id", "ARGON2ID", "argon2", "argon2i", "scrypt ", "pbkdf", "",
        ] {
            assert!(bad.parse::<KdfId>().is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn id_byte_round_trip_and_unknown_rejected() {
        assert_eq!(KdfId::Argon2id.id(), 0x01);
        assert_eq!(KdfId::Scrypt.id(), 0x02);
        assert_eq!(KdfId::Pbkdf2.id(), 0x03);
        for id in all_ids() {
            assert_eq!(KdfId::from_id(id.id()).unwrap(), id);
        }
        for unknown in [0x00, 0x04, 0xff] {
            assert!(matches!(
                KdfId::from_id(unknown),
                Err(SymError::UnknownKdf(_))
            ));
        }
    }

    #[test]
    fn defaults_match_design_section_12() {
        assert_eq!(
            KdfParams::default_for(KdfId::Argon2id),
            KdfParams::Argon2id {
                memory_kib: 65536,
                time_cost: 3,
                parallelism: 1
            }
        );
        assert_eq!(
            KdfParams::default_for(KdfId::Scrypt),
            KdfParams::Scrypt {
                log_n: 15,
                r: 8,
                p: 1
            }
        );
        assert_eq!(
            KdfParams::default_for(KdfId::Pbkdf2),
            KdfParams::Pbkdf2 {
                iterations: 600_000
            }
        );
        // The defaults must themselves be valid and match their KdfId.
        for id in all_ids() {
            let d = KdfParams::default_for(id);
            assert!(d.validate().is_ok());
            assert_eq!(d.kdf_id(), id);
        }
    }

    #[test]
    fn words_round_trip_for_each_kdf() {
        for id in all_ids() {
            let p = KdfParams::default_for(id);
            let (a, b, c) = p.to_words();
            assert_eq!(KdfParams::from_words(id, a, b, c).unwrap(), p);
        }
        // PBKDF2 encodes reserved words as zero.
        assert_eq!(
            KdfParams::Pbkdf2 {
                iterations: 600_000
            }
            .to_words(),
            (600_000, 0, 0)
        );
    }

    #[test]
    fn from_words_rejects_pbkdf2_nonzero_reserved() {
        assert!(KdfParams::from_words(KdfId::Pbkdf2, 600_000, 1, 0).is_err());
        assert!(KdfParams::from_words(KdfId::Pbkdf2, 600_000, 0, 7).is_err());
        assert!(KdfParams::from_words(KdfId::Pbkdf2, 600_000, 0, 0).is_ok());
    }

    #[test]
    fn validate_enforces_argon2_ranges() {
        let ok = KdfParams::Argon2id {
            memory_kib: 8192,
            time_cost: 1,
            parallelism: 1,
        };
        assert!(ok.validate().is_ok());
        // Boundaries just outside the range.
        for bad in [
            KdfParams::Argon2id {
                memory_kib: 8191,
                time_cost: 1,
                parallelism: 1,
            },
            KdfParams::Argon2id {
                memory_kib: 1_048_577,
                time_cost: 1,
                parallelism: 1,
            },
            KdfParams::Argon2id {
                memory_kib: 8192,
                time_cost: 0,
                parallelism: 1,
            },
            KdfParams::Argon2id {
                memory_kib: 8192,
                time_cost: 11,
                parallelism: 1,
            },
            KdfParams::Argon2id {
                memory_kib: 8192,
                time_cost: 1,
                parallelism: 0,
            },
            KdfParams::Argon2id {
                memory_kib: 8192,
                time_cost: 1,
                parallelism: 17,
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn validate_enforces_scrypt_ranges_and_memory_cap() {
        assert!(KdfParams::Scrypt {
            log_n: 10,
            r: 1,
            p: 1
        }
        .validate()
        .is_ok());
        // log_n=20, r=8 => 128 * 2^20 * 8 = exactly 1 GiB: allowed.
        assert!(KdfParams::Scrypt {
            log_n: 20,
            r: 8,
            p: 1
        }
        .validate()
        .is_ok());
        // log_n=20, r=32 => 4 GiB: over the cap even though r is in range.
        assert!(KdfParams::Scrypt {
            log_n: 20,
            r: 32,
            p: 1
        }
        .validate()
        .is_err());
        for bad in [
            KdfParams::Scrypt {
                log_n: 9,
                r: 1,
                p: 1,
            },
            KdfParams::Scrypt {
                log_n: 21,
                r: 1,
                p: 1,
            },
            KdfParams::Scrypt {
                log_n: 10,
                r: 0,
                p: 1,
            },
            KdfParams::Scrypt {
                log_n: 10,
                r: 33,
                p: 1,
            },
            KdfParams::Scrypt {
                log_n: 10,
                r: 1,
                p: 0,
            },
            KdfParams::Scrypt {
                log_n: 10,
                r: 1,
                p: 17,
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn validate_enforces_pbkdf2_iterations() {
        assert!(KdfParams::Pbkdf2 { iterations: 10_000 }.validate().is_ok());
        assert!(KdfParams::Pbkdf2 {
            iterations: 10_000_000
        }
        .validate()
        .is_ok());
        assert!(KdfParams::Pbkdf2 { iterations: 9_999 }.validate().is_err());
        assert!(KdfParams::Pbkdf2 {
            iterations: 10_000_001
        }
        .validate()
        .is_err());
    }

    #[test]
    fn derive_key_is_deterministic_and_32_bytes() {
        let secret = b"domain-separated-secret-input";
        let salt = [1u8; 16];
        for id in all_ids() {
            let p = cheap(id);
            let k1 = p.derive_key(secret, &salt).unwrap();
            let k2 = p.derive_key(secret, &salt).unwrap();
            assert_eq!(k1.len(), 32);
            assert_eq!(&*k1, &*k2, "deterministic for {id}");
        }
    }

    #[test]
    fn derive_key_is_sensitive_to_inputs() {
        let secret = b"secret-input";
        let salt = [1u8; 16];
        for id in all_ids() {
            let p = cheap(id);
            let base = p.derive_key(secret, &salt).unwrap();

            let other_salt = p.derive_key(secret, &[2u8; 16]).unwrap();
            assert_ne!(&*base, &*other_salt, "salt changes key for {id}");

            let other_secret = p.derive_key(b"different-input", &salt).unwrap();
            assert_ne!(&*base, &*other_secret, "secret changes key for {id}");
        }

        // Different cost parameters yield a different key.
        let a = KdfParams::Argon2id {
            memory_kib: 8192,
            time_cost: 1,
            parallelism: 1,
        }
        .derive_key(secret, &salt)
        .unwrap();
        let b = KdfParams::Argon2id {
            memory_kib: 8192,
            time_cost: 2,
            parallelism: 1,
        }
        .derive_key(secret, &salt)
        .unwrap();
        assert_ne!(&*a, &*b, "time cost changes key");
    }

    #[test]
    fn different_kdfs_yield_different_keys() {
        let secret = b"secret-input";
        let salt = [9u8; 16];
        let argon = cheap(KdfId::Argon2id).derive_key(secret, &salt).unwrap();
        let scry = cheap(KdfId::Scrypt).derive_key(secret, &salt).unwrap();
        let pbk = cheap(KdfId::Pbkdf2).derive_key(secret, &salt).unwrap();
        assert_ne!(&*argon, &*scry);
        assert_ne!(&*argon, &*pbk);
        assert_ne!(&*scry, &*pbk);
    }
}
