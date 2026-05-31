//! Semantic cross-flag validation (DESIGN §6.3). Implemented in plan §5 step 3.
//!
//! clap enforces the syntax of individual flags and the single-mode group, but
//! it cannot express rules that span several flags or depend on the chosen
//! mode. This module rejects such bad combinations up front with
//! [`AppError::usage`] (exit code 2) before any cryptographic work begins.

use crate::cli::{Cli, Mode};
use symcrypt_common::{is_stdio, AppError, AppResult};

/// Reject flag combinations clap cannot express, with `AppError::usage`
/// (exit 2), before any work begins.
pub fn validate(cli: &Cli) -> AppResult<()> {
    let mode = cli.mode();

    // 1) Mode applicability: a flag given for a mode it does not apply to.
    validate_mode_applicability(cli, mode)?;

    // 2) A KDF cost knob requires its matching `--kdf` (a knob never implies a KDF).
    validate_kdf_knobs(cli)?;

    // 3) `--no-password` only makes sense alongside a keyfile.
    if cli.no_password && cli.keyfile.is_none() {
        return Err(AppError::usage(
            "--no-password requires a keyfile; pass -k/--keyfile",
        ));
    }

    // 4) stdin restrictions: features that need a real filesystem path.
    if cli.name && is_stdio(&cli.file) {
        return Err(AppError::usage(
            "--name cannot be used when reading from stdin ('-'); the original filename is unavailable",
        ));
    }
    if cli.remove && is_stdio(&cli.file) {
        return Err(AppError::usage(
            "--remove cannot be used when reading from stdin ('-'); there is no input file to remove",
        ));
    }

    // 5) Mutually exclusive verbosity / progress flags.
    if cli.quiet && cli.verbose {
        return Err(AppError::usage(
            "--quiet and --verbose are mutually exclusive",
        ));
    }
    if cli.progress && cli.quiet {
        return Err(AppError::usage(
            "--progress and --quiet are mutually exclusive",
        ));
    }

    Ok(())
}

/// Enforce per-mode flag applicability (DESIGN §6.3 "Applies to").
fn validate_mode_applicability(cli: &Cli, mode: Mode) -> AppResult<()> {
    let is_encrypt = matches!(mode, Mode::Encrypt);
    let is_info = matches!(mode, Mode::Info);
    // Encrypt/Decrypt only.
    let is_enc_or_dec = matches!(mode, Mode::Encrypt | Mode::Decrypt);

    // `-o/--output`: Encrypt/Decrypt only.
    if cli.output.is_some() && !is_enc_or_dec {
        return Err(AppError::usage(
            "-o/--output applies only to encrypt and decrypt",
        ));
    }

    // Secret flags: Encrypt/Decrypt/Verify (everything but Info).
    if is_info
        && (cli.password.is_some()
            || cli.password_file.is_some()
            || cli.password_env.is_some()
            || cli.no_password
            || cli.keyfile.is_some())
    {
        return Err(AppError::usage(
            "password and keyfile options do not apply to --info",
        ));
    }

    // Encrypt-only options: cipher, kdf, all KDF knobs, armor, name.
    if !is_encrypt
        && (cli.cipher.is_some()
            || cli.kdf.is_some()
            || cli.argon2_memory.is_some()
            || cli.argon2_time.is_some()
            || cli.argon2_parallelism.is_some()
            || cli.scrypt_log_n.is_some()
            || cli.scrypt_r.is_some()
            || cli.scrypt_p.is_some()
            || cli.pbkdf2_iterations.is_some()
            || cli.armor
            || cli.name)
    {
        return Err(AppError::usage(
            "cipher, KDF, armor, and --name options apply only to encrypt",
        ));
    }

    // `-f/--force` and `--remove`: Encrypt/Decrypt only.
    if cli.force && !is_enc_or_dec {
        return Err(AppError::usage(
            "-f/--force applies only to encrypt and decrypt",
        ));
    }
    if cli.remove && !is_enc_or_dec {
        return Err(AppError::usage(
            "--remove applies only to encrypt and decrypt",
        ));
    }

    // Progress flags: Encrypt/Decrypt/Verify (everything but Info).
    if is_info && (cli.progress || cli.no_progress) {
        return Err(AppError::usage("progress options do not apply to --info"));
    }

    Ok(())
}

/// Each KDF cost knob requires the matching `--kdf` to be selected.
fn validate_kdf_knobs(cli: &Cli) -> AppResult<()> {
    let kdf = cli.kdf.as_deref();
    // argon2id is the default KDF, so it counts as selected when `--kdf` is absent.
    let argon2_selected = matches!(kdf, None | Some("argon2id"));
    let scrypt_selected = matches!(kdf, Some("scrypt"));
    let pbkdf2_selected = matches!(kdf, Some("pbkdf2"));

    if !argon2_selected
        && (cli.argon2_memory.is_some()
            || cli.argon2_time.is_some()
            || cli.argon2_parallelism.is_some())
    {
        return Err(AppError::usage(
            "Argon2 cost options require --kdf argon2id",
        ));
    }

    if !scrypt_selected
        && (cli.scrypt_log_n.is_some() || cli.scrypt_r.is_some() || cli.scrypt_p.is_some())
    {
        return Err(AppError::usage("scrypt cost options require --kdf scrypt"));
    }

    if !pbkdf2_selected && cli.pbkdf2_iterations.is_some() {
        return Err(AppError::usage("--pbkdf2-iterations requires --kdf pbkdf2"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    /// Parse a `Cli` from the given args plus a trailing positional file.
    /// `args` must include a mode flag so clap's single-mode group is satisfied.
    fn parse(args: &[&str]) -> Cli {
        let mut argv = vec!["symcrypt"];
        argv.extend_from_slice(args);
        argv.push("file");
        Cli::try_parse_from(argv).unwrap()
    }

    /// Like [`parse`] but uses `-` as the positional file to exercise stdin rules.
    fn parse_stdin(args: &[&str]) -> Cli {
        let mut argv = vec!["symcrypt"];
        argv.extend_from_slice(args);
        argv.push("-");
        Cli::try_parse_from(argv).unwrap()
    }

    // ----- valid baseline invocations for each mode -----

    #[test]
    fn valid_encrypt() {
        assert!(validate(&parse(&["-e"])).is_ok());
    }

    #[test]
    fn valid_decrypt() {
        assert!(validate(&parse(&["-d"])).is_ok());
    }

    #[test]
    fn valid_info() {
        assert!(validate(&parse(&["--info"])).is_ok());
    }

    #[test]
    fn valid_verify() {
        assert!(validate(&parse(&["--verify"])).is_ok());
    }

    // ----- rule 1: mode applicability -----

    #[test]
    fn output_rejected_in_info() {
        assert!(validate(&parse(&["--info", "-o", "out"])).is_err());
    }

    #[test]
    fn output_rejected_in_verify() {
        assert!(validate(&parse(&["--verify", "-o", "out"])).is_err());
    }

    #[test]
    fn output_allowed_in_encrypt_and_decrypt() {
        assert!(validate(&parse(&["-e", "-o", "out"])).is_ok());
        assert!(validate(&parse(&["-d", "-o", "out"])).is_ok());
    }

    #[test]
    fn password_rejected_in_info() {
        assert!(validate(&parse(&["--info", "--password", "pw"])).is_err());
    }

    #[test]
    fn password_file_rejected_in_info() {
        assert!(validate(&parse(&["--info", "--password-file", "pf"])).is_err());
    }

    #[test]
    fn password_env_rejected_in_info() {
        assert!(validate(&parse(&["--info", "--password-env", "PW"])).is_err());
    }

    #[test]
    fn no_password_rejected_in_info() {
        // --no-password needs -k, but the Info-mode check fires first regardless.
        assert!(validate(&parse(&["--info", "--no-password", "-k", "kf"])).is_err());
    }

    #[test]
    fn keyfile_rejected_in_info() {
        assert!(validate(&parse(&["--info", "-k", "kf"])).is_err());
    }

    #[test]
    fn secret_allowed_in_verify() {
        assert!(validate(&parse(&["--verify", "--password", "pw"])).is_ok());
    }

    #[test]
    fn cipher_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--cipher", "aes-256-gcm"])).is_err());
    }

    #[test]
    fn kdf_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--kdf", "argon2id"])).is_err());
    }

    #[test]
    fn argon2_memory_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--argon2-memory", "65536"])).is_err());
    }

    #[test]
    fn argon2_time_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--argon2-time", "3"])).is_err());
    }

    #[test]
    fn argon2_parallelism_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--argon2-parallelism", "4"])).is_err());
    }

    #[test]
    fn scrypt_log_n_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--scrypt-log-n", "15"])).is_err());
    }

    #[test]
    fn scrypt_r_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--scrypt-r", "8"])).is_err());
    }

    #[test]
    fn scrypt_p_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--scrypt-p", "1"])).is_err());
    }

    #[test]
    fn pbkdf2_iterations_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--pbkdf2-iterations", "600000"])).is_err());
    }

    #[test]
    fn armor_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--armor"])).is_err());
    }

    #[test]
    fn name_rejected_outside_encrypt() {
        assert!(validate(&parse(&["-d", "--name"])).is_err());
    }

    #[test]
    fn force_rejected_in_info() {
        assert!(validate(&parse(&["--info", "-f"])).is_err());
    }

    #[test]
    fn force_rejected_in_verify() {
        assert!(validate(&parse(&["--verify", "-f"])).is_err());
    }

    #[test]
    fn force_allowed_in_decrypt() {
        assert!(validate(&parse(&["-d", "-f"])).is_ok());
    }

    #[test]
    fn remove_rejected_in_info() {
        assert!(validate(&parse(&["--info", "--remove"])).is_err());
    }

    #[test]
    fn remove_rejected_in_verify() {
        assert!(validate(&parse(&["--verify", "--remove"])).is_err());
    }

    #[test]
    fn progress_rejected_in_info() {
        assert!(validate(&parse(&["--info", "--progress"])).is_err());
    }

    #[test]
    fn no_progress_rejected_in_info() {
        assert!(validate(&parse(&["--info", "--no-progress"])).is_err());
    }

    #[test]
    fn progress_allowed_in_verify() {
        assert!(validate(&parse(&["--verify", "--progress"])).is_ok());
    }

    // ----- rule 2: KDF knob requires matching --kdf -----

    #[test]
    fn argon2_knob_with_default_kdf_ok() {
        // argon2id is the default, so its knobs are valid without --kdf on encrypt.
        assert!(validate(&parse(&["-e", "--argon2-memory", "65536"])).is_ok());
    }

    #[test]
    fn argon2_knob_with_explicit_argon2id_ok() {
        assert!(validate(&parse(&["-e", "--kdf", "argon2id", "--argon2-time", "3"])).is_ok());
    }

    #[test]
    fn argon2_knob_with_scrypt_rejected() {
        assert!(validate(&parse(&[
            "-e",
            "--kdf",
            "scrypt",
            "--argon2-memory",
            "65536"
        ]))
        .is_err());
    }

    #[test]
    fn argon2_knob_with_pbkdf2_rejected() {
        assert!(validate(&parse(&["-e", "--kdf", "pbkdf2", "--argon2-time", "3"])).is_err());
    }

    #[test]
    fn scrypt_knob_with_scrypt_ok() {
        assert!(validate(&parse(&["-e", "--kdf", "scrypt", "--scrypt-log-n", "15"])).is_ok());
    }

    #[test]
    fn scrypt_knob_with_default_kdf_rejected() {
        // default KDF is argon2id, so scrypt knobs are invalid.
        assert!(validate(&parse(&["-e", "--scrypt-log-n", "15"])).is_err());
    }

    #[test]
    fn scrypt_knob_with_argon2id_rejected() {
        assert!(validate(&parse(&["-e", "--kdf", "argon2id", "--scrypt-r", "8"])).is_err());
    }

    #[test]
    fn pbkdf2_knob_with_pbkdf2_ok() {
        assert!(validate(&parse(&[
            "-e",
            "--kdf",
            "pbkdf2",
            "--pbkdf2-iterations",
            "600000"
        ]))
        .is_ok());
    }

    #[test]
    fn pbkdf2_knob_with_default_kdf_rejected() {
        assert!(validate(&parse(&["-e", "--pbkdf2-iterations", "600000"])).is_err());
    }

    #[test]
    fn pbkdf2_knob_with_scrypt_rejected() {
        assert!(validate(&parse(&[
            "-e",
            "--kdf",
            "scrypt",
            "--pbkdf2-iterations",
            "600000"
        ]))
        .is_err());
    }

    // ----- rule 3: --no-password requires -k -----

    #[test]
    fn no_password_without_keyfile_rejected() {
        let err = validate(&parse(&["-e", "--no-password"])).unwrap_err();
        assert!(err.to_string().contains("keyfile"));
    }

    #[test]
    fn no_password_with_keyfile_ok() {
        assert!(validate(&parse(&["-e", "--no-password", "-k", "kf"])).is_ok());
    }

    // ----- rule 4: stdin restrictions -----

    #[test]
    fn name_with_stdin_rejected() {
        assert!(validate(&parse_stdin(&["-e", "--name"])).is_err());
    }

    #[test]
    fn remove_with_stdin_rejected() {
        assert!(validate(&parse_stdin(&["-e", "--remove"])).is_err());
    }

    #[test]
    fn encrypt_from_stdin_ok() {
        assert!(validate(&parse_stdin(&["-e"])).is_ok());
    }

    // ----- rule 5: conflicting verbosity / progress -----

    #[test]
    fn quiet_and_verbose_rejected() {
        assert!(validate(&parse(&["-e", "-q", "-v"])).is_err());
    }

    #[test]
    fn progress_and_quiet_rejected() {
        assert!(validate(&parse(&["-e", "--progress", "-q"])).is_err());
    }

    #[test]
    fn no_progress_and_quiet_allowed() {
        assert!(validate(&parse(&["-e", "--no-progress", "-q"])).is_ok());
    }
}
