//! Mode dispatch + path/IO orchestration (DESIGN §6.5, plan §6 & §8).
//!
//! Each handler resolves paths (and, for decrypt without `-o`, peeks the header
//! for the stored name) *before* prompting, opens the streams, runs the core
//! operation against a temp-file-backed [`OutputSink`], and finalizes only on
//! success. On any error the sink drops — removing the temporary — and
//! `--remove` is skipped.

use crate::cli::{Cli, Mode};
use crate::{info, options, progress, secret};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use symcrypt_common::{best_effort_remove, is_stdio, open_input, open_output, AppError, AppResult};
use symcrypt_core as core;

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
            "symcrypt: encrypt {} -> {}",
            input_path.display(),
            target.display()
        );
        eprintln!(
            "symcrypt: cipher={} kdf={} {} keyfile={}",
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
        eprintln!("symcrypt: wrote {}", target.display());
    }
    Ok(())
}

/// Decrypt `<FILE>` → output (DESIGN §6.5). Without `-o` the stored/derived name
/// requires peeking the header first.
fn run_decrypt(cli: &Cli, cancel: &Arc<AtomicBool>) -> AppResult<()> {
    let input_path = cli.file.as_path();

    let target = match &cli.output {
        Some(out) => out.clone(),
        None if is_stdio(input_path) => {
            return Err(AppError::usage(
                "decrypting from stdin requires -o/--output",
            ));
        }
        None => {
            // Peek the (unauthenticated) header to derive the default name, then
            // re-open for the actual decrypt pass.
            let mut peek = open_input(input_path)?;
            let header = core::inspect(&mut *peek)?;
            core::default_decrypt_output(input_path, &header)
        }
    };

    let (mut input, input_len) = open_main_input(input_path)?;
    let mut sink = open_output(&target, cli.force, Some(input_path))?;
    let sct = secret::resolve_secret(cli, false)?;

    if cli.verbose {
        eprintln!(
            "symcrypt: decrypt {} -> {}",
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
        eprintln!("symcrypt: wrote {}", target.display());
    }
    Ok(())
}

/// Verify integrity + secret by decrypting and discarding (DESIGN §6.2). No
/// output is written; success is exit 0, a bad tag maps to exit 3.
fn run_verify(cli: &Cli, cancel: &Arc<AtomicBool>) -> AppResult<()> {
    let input_path = cli.file.as_path();
    let (mut input, input_len) = open_main_input(input_path)?;
    let sct = secret::resolve_secret(cli, false)?;

    let bar = progress::make_bar(progress::want_progress(cli), input_len);
    let mut cb = progress::callback(bar.clone(), Arc::clone(cancel));
    core::verify(&mut *input, &sct, input_len, &mut cb)?;
    finish_bar(&bar);

    if cli.verbose {
        eprintln!("symcrypt: integrity verified for {}", input_path.display());
    }
    Ok(())
}

/// Print unauthenticated header metadata (DESIGN §6.2). No password, no output
/// file; the block goes to stdout and is not suppressed by `--quiet`.
fn run_info(cli: &Cli) -> AppResult<()> {
    let mut input = open_input(cli.file.as_path())?;
    let header = core::inspect(&mut *input)?;
    print!("{}", info::format_info(&header));
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
                eprintln!("symcrypt: removed input {}", input.display());
            }
        }
        Err(e) => eprintln!(
            "symcrypt: warning: could not remove input {}: {e}",
            input.display()
        ),
    }
}
