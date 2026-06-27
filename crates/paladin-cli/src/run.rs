//! Mode dispatch + path/IO orchestration (DESIGN §6.5, plan §6 & §8).
//!
//! Each handler resolves paths (and, for decrypt without `-o`, peeks the header
//! for the stored name) *before* prompting, opens the streams, runs the core
//! operation against a temp-file-backed [`OutputSink`], and finalizes only on
//! success. On any error the sink drops — removing the temporary — and
//! `--remove` is skipped.

use crate::cli::{Cli, Mode};
use crate::{info, options, progress, secret};
use paladin_common::{best_effort_remove, is_stdio, open_input, open_output, AppError, AppResult};
use paladin_core as core;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Validate, then run the selected mode. Returns an [`AppError`] whose
/// `exit_code()` the caller maps to the process exit status.
pub fn dispatch(cli: &Cli, cancel: Arc<AtomicBool>) -> AppResult<()> {
    crate::validate::validate(cli)?;
    match cli.mode() {
        Mode::Encrypt => run_encrypt(cli, &cancel),
        Mode::Decrypt => run_decrypt(cli, &cancel),
        Mode::Verify => run_verify(cli, &cancel),
        Mode::Info => run_info(cli),
    }
}

/// Open the main input and read its length (for the progress total); stdin has
/// no known length.
fn open_main_input(path: &Path) -> AppResult<(Box<dyn Read>, Option<u64>)> {
    let reader = open_input(path)?;
    let len = if is_stdio(path) {
        None
    } else {
        std::fs::metadata(path).ok().map(|m| m.len())
    };
    Ok((reader, len))
}

/// Encrypt `<FILE>` → output (DESIGN §6.5).
fn run_encrypt(cli: &Cli, cancel: &Arc<AtomicBool>) -> AppResult<()> {
    let input_path = cli.file.as_path();
    let opts = options::build_options(cli)?;

    let target = match &cli.output {
        Some(out) => out.clone(),
        None if is_stdio(input_path) => {
            return Err(AppError::usage(
                "encrypting from stdin requires -o/--output",
            ));
        }
        None => core::default_encrypt_output(input_path, opts.armor),
    };

    let (mut input, input_len) = open_main_input(input_path)?;
    let mut sink = open_output(&target, cli.force, Some(input_path))?;
    // Paths are validated; prompting now won't be wasted by a clobber refusal.
    let sct = secret::resolve_secret(cli, true)?;

    if cli.verbose {
        eprintln!(
            "paladin: encrypt {} -> {}",
            input_path.display(),
            target.display()
        );
        eprintln!(
            "paladin: cipher={} kdf={} {} keyfile={}",
            opts.cipher,
            opts.kdf,
            info::format_kdf_params(&opts.kdf_params),
            cli.keyfile.is_some()
        );
    }

    let bar = progress::make_bar(progress::want_progress(cli), input_len);
    let mut cb = progress::callback(bar.clone(), Arc::clone(cancel));
    core::encrypt(
        &mut *input,
        sink.as_write(),
        &sct,
        &opts,
        input_len,
        &mut cb,
    )?;
    finish_bar(&bar);
    sink.commit()?;

    maybe_remove_input(cli, input_path);
    if cli.verbose {
        eprintln!("paladin: wrote {}", target.display());
    }
    Ok(())
}

/// Decrypt `<FILE>` → output (DESIGN §6.5). Without `-o` the stored/derived name
/// requires peeking the header first; the same peek detects an AES Crypt input so
/// the `.aes` suffix is stripped and a keyfile/`--no-password` secret is rejected
/// with a clear message before prompting (PLAN_05 §6).
fn run_decrypt(cli: &Cli, cancel: &Arc<AtomicBool>) -> AppResult<()> {
    let input_path = cli.file.as_path();

    let target = match &cli.output {
        Some(out) => {
            // -o given: no name peek is needed, but still pre-reject a
            // keyfile/no-password secret against an AES Crypt input.
            precheck_aescrypt_keyfile(cli, input_path)?;
            out.clone()
        }
        None if is_stdio(input_path) => {
            return Err(AppError::usage(
                "decrypting from stdin requires -o/--output",
            ));
        }
        None => {
            // Peek the (unauthenticated) metadata to derive the default name and
            // detect the format, then re-open for the actual decrypt pass.
            let mut peek = open_input(input_path)?;
            let meta = core::inspect(&mut *peek)?;
            if keyfile_or_no_password(cli) && matches!(meta, core::Metadata::AesCrypt(_)) {
                return Err(aescrypt_keyfile_usage());
            }
            match meta {
                core::Metadata::Paladin(h) => core::default_decrypt_output(input_path, &h),
                core::Metadata::AesCrypt(_) => core::default_aescrypt_output(input_path),
            }
        }
    };

    let (mut input, input_len) = open_main_input(input_path)?;
    let mut sink = open_output(&target, cli.force, Some(input_path))?;
    let sct = secret::resolve_secret(cli, false)?;

    if cli.verbose {
        eprintln!(
            "paladin: decrypt {} -> {}",
            input_path.display(),
            target.display()
        );
    }

    let bar = progress::make_bar(progress::want_progress(cli), input_len);
    let mut cb = progress::callback(bar.clone(), Arc::clone(cancel));
    core::decrypt(&mut *input, sink.as_write(), &sct, input_len, &mut cb)?;
    finish_bar(&bar);
    sink.commit()?;

    maybe_remove_input(cli, input_path);
    if cli.verbose {
        eprintln!("paladin: wrote {}", target.display());
    }
    Ok(())
}

/// Verify integrity + secret by decrypting and discarding (DESIGN §6.2). No
/// output is written; success is exit 0, a bad tag maps to exit 3.
fn run_verify(cli: &Cli, cancel: &Arc<AtomicBool>) -> AppResult<()> {
    let input_path = cli.file.as_path();
    // Pre-reject a keyfile/no-password secret against an AES Crypt input before
    // prompting or reading the keyfile (PLAN_05 §6).
    precheck_aescrypt_keyfile(cli, input_path)?;
    let (mut input, input_len) = open_main_input(input_path)?;
    let sct = secret::resolve_secret(cli, false)?;

    let bar = progress::make_bar(progress::want_progress(cli), input_len);
    let mut cb = progress::callback(bar.clone(), Arc::clone(cancel));
    core::verify(&mut *input, &sct, input_len, &mut cb)?;
    finish_bar(&bar);

    if cli.verbose {
        eprintln!("paladin: integrity verified for {}", input_path.display());
    }
    Ok(())
}

/// Print unauthenticated header metadata (DESIGN §6.2). No password, no output
/// file; the block goes to stdout and is not suppressed by `--quiet`.
fn run_info(cli: &Cli) -> AppResult<()> {
    let mut input = open_input(cli.file.as_path())?;
    let meta = core::inspect(&mut *input)?;
    print!("{}", info::format_info(&meta));
    Ok(())
}

/// Whether the user supplied a keyfile or `--no-password` — a secret shape an
/// AES Crypt input cannot use (it has no paladin-style keyfile component).
fn keyfile_or_no_password(cli: &Cli) -> bool {
    cli.keyfile.is_some() || cli.no_password
}

/// The usage error for a keyfile/`--no-password` secret against a `.aes` file.
fn aescrypt_keyfile_usage() -> AppError {
    AppError::usage(
        "AES Crypt files don't use paladin keyfiles; use a UTF-8 --password-file for a compatible AES Crypt key file",
    )
}

/// Pre-reject a keyfile/`--no-password` secret against a non-stdin AES Crypt
/// input, before prompting or reading the keyfile (PLAN_05 §6). Stdin cannot be
/// pre-inspected without buffering, so it keeps the core `InvalidOptions`
/// backstop. A non-keyfile/non-`--no-password` invocation needs no pre-check.
fn precheck_aescrypt_keyfile(cli: &Cli, input_path: &Path) -> AppResult<()> {
    if is_stdio(input_path) || !keyfile_or_no_password(cli) {
        return Ok(());
    }
    let mut peek = open_input(input_path)?;
    if matches!(core::inspect(&mut *peek)?, core::Metadata::AesCrypt(_)) {
        return Err(aescrypt_keyfile_usage());
    }
    Ok(())
}

/// Clear the progress bar after a successful streaming pass.
fn finish_bar(bar: &Option<indicatif::ProgressBar>) {
    if let Some(bar) = bar {
        bar.finish_and_clear();
    }
}

/// Honor `--remove`: best-effort delete the input after a finalized output. A
/// deletion failure warns on stderr but still exits 0 (DESIGN §6.5). Never
/// attempted for stdin (already rejected in validation).
fn maybe_remove_input(cli: &Cli, input: &Path) {
    if !cli.remove || is_stdio(input) {
        return;
    }
    match best_effort_remove(input) {
        Ok(()) => {
            if cli.verbose {
                eprintln!("paladin: removed input {}", input.display());
            }
        }
        Err(e) => eprintln!(
            "paladin: warning: could not remove input {}: {e}",
            input.display()
        ),
    }
}
