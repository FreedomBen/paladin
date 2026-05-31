//! Build `EncryptOptions` from parsed args (DESIGN §6.3, §12). Plan §5 step 4.

use crate::cli::Cli;
use symcrypt_common::{AppError, AppResult};
use symcrypt_core::{EncryptOptions, KdfId, KdfParams};

/// Assemble `EncryptOptions` for an encrypt run: cipher/KDF parsed via core
/// `FromStr`, `KdfParams` from the §12 default with supplied knobs overridden,
/// armor from `-a`, and the stored basename when `--name` is set.
///
/// Only called in encrypt mode; assumes cross-flag validation already passed
/// (so knob↔KDF consistency is not re-checked here). Cost values are passed
/// through verbatim — the core does the range-checking.
pub fn build_options(cli: &Cli) -> AppResult<EncryptOptions> {
    let mut opts = EncryptOptions::default();

    // Cipher: parse the supplied name, or keep the default (AES-256-GCM).
    if let Some(cipher) = &cli.cipher {
        opts.cipher = cipher.parse()?;
    }

    // KDF: parse the supplied name, or default to Argon2id.
    opts.kdf = match &cli.kdf {
        Some(kdf) => kdf.parse()?,
        None => KdfId::Argon2id,
    };

    // KDF params: start from the §12 default for the selected KDF and override
    // only the knobs belonging to it.
    opts.kdf_params = kdf_params(opts.kdf, cli);

    opts.armor = cli.armor;

    // Stored filename: only when --name is set, and only the basename.
    if cli.name {
        let basename = cli
            .file
            .file_name()
            .ok_or_else(|| AppError::usage("cannot determine a basename for --name"))?
            .to_str()
            .ok_or_else(|| AppError::usage("stored filename must be valid UTF-8"))?
            .to_owned();
        opts.filename = Some(basename);
    }

    Ok(opts)
}

/// Take the §12 default params for `kdf` and override each knob with the CLI
/// value when present, leaving the default in place otherwise. Reading the
/// defaults from `default_for` keeps §12 as the single source of truth.
fn kdf_params(kdf: KdfId, cli: &Cli) -> KdfParams {
    match KdfParams::default_for(kdf) {
        KdfParams::Argon2id {
            memory_kib,
            time_cost,
            parallelism,
        } => KdfParams::Argon2id {
            memory_kib: cli.argon2_memory.unwrap_or(memory_kib),
            time_cost: cli.argon2_time.unwrap_or(time_cost),
            parallelism: cli.argon2_parallelism.unwrap_or(parallelism),
        },
        KdfParams::Scrypt { log_n, r, p } => KdfParams::Scrypt {
            log_n: cli.scrypt_log_n.unwrap_or(log_n),
            r: cli.scrypt_r.unwrap_or(r),
            p: cli.scrypt_p.unwrap_or(p),
        },
        KdfParams::Pbkdf2 { iterations } => KdfParams::Pbkdf2 {
            iterations: cli.pbkdf2_iterations.unwrap_or(iterations),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;
    use symcrypt_core::CipherId;

    /// Parse a `Cli` for an encrypt run with the given extra args before the file.
    fn cli(args: &[&str]) -> Cli {
        let mut argv = vec!["symcrypt", "-e"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).unwrap()
    }

    #[test]
    fn default_encrypt_uses_documented_defaults() {
        let opts = build_options(&cli(&["file"])).unwrap();
        assert_eq!(opts.cipher, CipherId::Aes256Gcm);
        assert_eq!(opts.kdf, KdfId::Argon2id);
        assert_eq!(opts.chunk_size, 65536);
        assert_eq!(opts.filename, None);
        assert!(!opts.armor);
        match opts.kdf_params {
            KdfParams::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
            } => {
                assert_eq!(memory_kib, 65536);
                assert_eq!(time_cost, 3);
                assert_eq!(parallelism, 1);
            }
            other => panic!("expected Argon2id params, got {other:?}"),
        }
    }

    #[test]
    fn cipher_chacha_is_selected() {
        let opts = build_options(&cli(&["-c", "chacha20-poly1305", "file"])).unwrap();
        assert_eq!(opts.cipher, CipherId::ChaCha20Poly1305);
    }

    #[test]
    fn scrypt_uses_its_defaults() {
        let opts = build_options(&cli(&["--kdf", "scrypt", "file"])).unwrap();
        assert_eq!(opts.kdf, KdfId::Scrypt);
        match opts.kdf_params {
            KdfParams::Scrypt { log_n, r, p } => {
                assert_eq!(log_n, 15);
                assert_eq!(r, 8);
                assert_eq!(p, 1);
            }
            other => panic!("expected Scrypt params, got {other:?}"),
        }
    }

    #[test]
    fn scrypt_overrides_are_applied() {
        let opts = build_options(&cli(&[
            "--kdf",
            "scrypt",
            "--scrypt-log-n",
            "14",
            "--scrypt-r",
            "4",
            "--scrypt-p",
            "2",
            "file",
        ]))
        .unwrap();
        match opts.kdf_params {
            KdfParams::Scrypt { log_n, r, p } => {
                assert_eq!(log_n, 14);
                assert_eq!(r, 4);
                assert_eq!(p, 2);
            }
            other => panic!("expected Scrypt params, got {other:?}"),
        }
    }

    #[test]
    fn pbkdf2_overrides_iterations() {
        let opts = build_options(&cli(&[
            "--kdf",
            "pbkdf2",
            "--pbkdf2-iterations",
            "250000",
            "file",
        ]))
        .unwrap();
        assert_eq!(opts.kdf, KdfId::Pbkdf2);
        match opts.kdf_params {
            KdfParams::Pbkdf2 { iterations } => assert_eq!(iterations, 250000),
            other => panic!("expected Pbkdf2 params, got {other:?}"),
        }
    }

    #[test]
    fn argon2_overrides_are_applied() {
        let opts = build_options(&cli(&[
            "--kdf",
            "argon2id",
            "--argon2-memory",
            "1024",
            "--argon2-time",
            "2",
            "--argon2-parallelism",
            "4",
            "file",
        ]))
        .unwrap();
        match opts.kdf_params {
            KdfParams::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
            } => {
                assert_eq!(memory_kib, 1024);
                assert_eq!(time_cost, 2);
                assert_eq!(parallelism, 4);
            }
            other => panic!("expected Argon2id params, got {other:?}"),
        }
    }

    #[test]
    fn unknown_cipher_is_rejected() {
        assert!(build_options(&cli(&["-c", "bogus", "file"])).is_err());
    }

    #[test]
    fn unknown_kdf_is_rejected() {
        assert!(build_options(&cli(&["--kdf", "bogus", "file"])).is_err());
    }

    #[test]
    fn name_stores_basename_for_plain_file() {
        let opts = build_options(&cli(&["--name", "report.pdf"])).unwrap();
        assert_eq!(opts.filename.as_deref(), Some("report.pdf"));
    }

    #[test]
    fn name_stores_only_basename_for_nested_path() {
        let opts = build_options(&cli(&["--name", "subdir/report.pdf"])).unwrap();
        assert_eq!(opts.filename.as_deref(), Some("report.pdf"));
    }

    #[test]
    fn armor_flag_sets_armor() {
        let opts = build_options(&cli(&["-a", "file"])).unwrap();
        assert!(opts.armor);
    }
}
