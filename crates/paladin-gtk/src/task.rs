//! Off-thread crypto runner: orchestrate open → temp output → core call →
//! commit/rollback, owning the cancel flag and progress throttling. The runner
//! itself is synchronous and testable; the relm4 `Command` that runs it on a
//! worker lives in the app component.
//!
//! Per DESIGN §2.2/§8, this module is medium-independent: no `gtk`/`adw`/`relm4`.
//! It reuses the crate's [`fsio`] file glue (sibling-temp finalization, atomic
//! rename, best-effort remove) so a failed or canceled run never leaves a
//! partial output — the uncommitted [`fsio::OutputFile`] removes its temp on
//! drop.

use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use paladin_core::{decrypt, encrypt, verify, EncryptOptions, PalError, Progress, Secret};

use crate::fsio::{self, FsError};
use crate::mode::Mode;

/// Forwards progress to the UI only when its integer percent bucket changes, so
/// the core's per-chunk (64 KiB) reports do not flood the worker→UI channel.
///
/// The bucket is `done * 100 / total` clamped to `0..=100`; when `total` is
/// `None` (size unknown) every report is forwarded.
pub struct ProgressThrottle {
    /// The last percent bucket that was emitted, or `None` before the first.
    last: Option<u8>,
}

impl ProgressThrottle {
    /// A throttle that has emitted nothing yet.
    pub fn new() -> Self {
        Self { last: None }
    }

    /// Whether `p` should be forwarded to the UI. Returns `true` when the
    /// integer percent bucket differs from the last emitted one (updating the
    /// stored bucket), or always when `p.total` is `None`.
    pub fn should_emit(&mut self, p: Progress) -> bool {
        let bucket = match p.total {
            // `checked_div` is `None` exactly when `t == 0`: an empty input is
            // complete, so that maps to bucket 100.
            Some(t) => p
                .done
                .saturating_mul(100)
                .checked_div(t)
                .map_or(100, |b| b as u8),
            None => return true,
        };
        if self.last == Some(bucket) {
            false
        } else {
            self.last = Some(bucket);
            true
        }
    }
}

impl Default for ProgressThrottle {
    fn default() -> Self {
        Self::new()
    }
}

/// One crypto operation to run on the worker. `Info` is handled inline by the
/// app (see [`Mode::runs_on_worker`]) and is never built into a `Job`.
pub struct Job {
    /// Which operation to run: `Encrypt`, `Decrypt`, or `Verify`.
    pub mode: Mode,
    /// The existing regular file to read from.
    pub input: PathBuf,
    /// Where to write the result: `Some` for `Encrypt`/`Decrypt`, `None` for
    /// `Verify` (which produces no output).
    pub output: Option<PathBuf>,
    /// The password/keyfile secret (zeroized on drop).
    pub secret: Secret,
    /// Encryption options; used by `Encrypt`, ignored by `Decrypt`/`Verify`.
    pub options: EncryptOptions,
    /// Whether overwriting an existing output file is approved.
    pub overwrite_approved: bool,
    /// Whether to delete the input after a successful operation.
    pub remove_input: bool,
}

/// A successful run. `remove_warning` is `Some(msg)` when the operation
/// succeeded but the requested input removal failed; the output is kept.
pub struct RunSuccess {
    /// A non-fatal warning if `remove_input` was requested but failed.
    pub remove_warning: Option<String>,
}

/// A failed run. Kept as two distinct arms so the app can branch:
/// [`RunError::Core`] is rendered to the user, while
/// [`RunError::Fs`]`(`[`FsError::OutputExists`]`)` pops an overwrite dialog.
#[derive(Debug)]
pub enum RunError {
    /// A filesystem/glue error (missing input, same-file, output-exists, …).
    Fs(FsError),
    /// A core crypto error (`Auth`, `Canceled`, unsupported format, …).
    Core(PalError),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Fs(e) => write!(f, "{e}"),
            RunError::Core(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RunError::Fs(e) => Some(e),
            RunError::Core(e) => Some(e),
        }
    }
}

impl From<FsError> for RunError {
    fn from(e: FsError) -> Self {
        RunError::Fs(e)
    }
}

impl From<PalError> for RunError {
    fn from(e: PalError) -> Self {
        RunError::Core(e)
    }
}

/// Run one [`Job`] synchronously to completion or first error.
///
/// Steps: verify the input is a regular file, open it, open a sibling-temp
/// output (for `Encrypt`/`Decrypt`), and drive the matching core operation with
/// a progress callback that (a) cancels via `cancel` and (b) forwards throttled
/// progress to `on_progress`. On core success the output is committed and, if
/// requested, the input is best-effort removed; on any error the uncommitted
/// output is dropped (its temp removed), leaving no partial file.
///
/// `cancel` is observed cooperatively: when set, the next progress report
/// returns [`ControlFlow::Break`], which the core maps to [`PalError::Canceled`].
/// Because the core reports progress once immediately after key derivation
/// (before writing output), a pre-set flag cancels even tiny inputs without
/// producing output.
pub fn run_job<P: FnMut(Progress)>(
    job: Job,
    cancel: &AtomicBool,
    mut on_progress: P,
) -> Result<RunSuccess, RunError> {
    fsio::require_regular_file(&job.input)?;

    let input_len = std::fs::metadata(&job.input).ok().map(|m| m.len());
    let file = File::open(&job.input).map_err(|e| RunError::Fs(FsError::Io(e)))?;
    let mut reader = BufReader::new(file);

    // One throttle shared across every report for this run. The closure borrows
    // `cancel`, the throttle, and `on_progress` — all distinct from `out`, so
    // the simultaneous `&mut` borrows of `out` and `cb` in the core call are
    // independent.
    let mut throttle = ProgressThrottle::new();
    let mut cb = |p: Progress| {
        if cancel.load(Ordering::Relaxed) {
            return ControlFlow::Break(());
        }
        if throttle.should_emit(p) {
            on_progress(p);
        }
        ControlFlow::Continue(())
    };

    match job.mode {
        Mode::Encrypt | Mode::Decrypt => {
            // These modes write output; `output` must be present.
            let target = job
                .output
                .as_deref()
                .expect("Encrypt/Decrypt jobs carry an output path");
            let mut out = fsio::open_output(target, Some(&job.input), job.overwrite_approved)?;

            let core_result = if job.mode == Mode::Encrypt {
                encrypt(
                    &mut reader,
                    out.as_write(),
                    &job.secret,
                    &job.options,
                    input_len,
                    &mut cb,
                )
            } else {
                decrypt(&mut reader, out.as_write(), &job.secret, input_len, &mut cb)
            };

            // On error, return before committing so `out` drops and its temp is
            // removed (no partial output for a wrong password or a cancel).
            core_result.map_err(RunError::Core)?;
            out.commit()?;
        }
        Mode::Verify => {
            verify(&mut reader, &job.secret, input_len, &mut cb).map_err(RunError::Core)?;
        }
        Mode::Info => {
            // Info runs inline via `inspect` and is excluded by
            // `Mode::runs_on_worker`; it should never reach the worker runner.
            debug_assert!(false, "Info is never a worker Job");
            return Err(RunError::Core(PalError::Canceled));
        }
    }

    // Operation succeeded. Optionally remove the input; a failure here is a
    // non-fatal warning since the output is already written.
    let remove_warning = if job.remove_input {
        match fsio::best_effort_remove(&job.input) {
            Ok(()) => None,
            Err(e) => Some(format!("could not remove input file: {e}")),
        }
    } else {
        None
    };

    Ok(RunSuccess { remove_warning })
}

#[cfg(test)]
mod tests {
    use super::*;
    use paladin_core::{CipherId, KdfId, KdfParams};
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    // --- helpers --------------------------------------------------------------

    /// A fresh secret with the test password (`Secret` is not `Clone`).
    fn secret() -> Secret {
        Secret::new(b"pw", None).unwrap()
    }

    /// A wrong-password secret.
    fn wrong_secret() -> Secret {
        Secret::new(b"wrong", None).unwrap()
    }

    /// Cheap Argon2id options so KDF cost does not slow the tests.
    fn cheap_opts() -> EncryptOptions {
        EncryptOptions {
            cipher: CipherId::Aes256Gcm,
            kdf: KdfId::Argon2id,
            kdf_params: KdfParams::Argon2id {
                memory_kib: 8192,
                time_cost: 1,
                parallelism: 1,
            },
            chunk_size: 65536,
            filename: None,
            armor: false,
        }
    }

    fn write_file(path: &Path, contents: &[u8]) {
        let mut f = File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    /// A no-op progress sink.
    fn noop(_p: Progress) {}

    fn encrypt_job(input: PathBuf, output: PathBuf) -> Job {
        Job {
            mode: Mode::Encrypt,
            input,
            output: Some(output),
            secret: secret(),
            options: cheap_opts(),
            overwrite_approved: false,
            remove_input: false,
        }
    }

    fn decrypt_job(input: PathBuf, output: PathBuf, sct: Secret) -> Job {
        Job {
            mode: Mode::Decrypt,
            input,
            output: Some(output),
            secret: sct,
            options: cheap_opts(),
            overwrite_approved: false,
            remove_input: false,
        }
    }

    /// Encrypt `plaintext` from a temp input to a temp output, returning
    /// (tempdir, input_path, output_path). The dir keeps both alive.
    fn make_ciphertext(plaintext: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain");
        let output = dir.path().join("plain.paladin");
        write_file(&input, plaintext);
        let cancel = AtomicBool::new(false);
        let res = run_job(encrypt_job(input.clone(), output.clone()), &cancel, noop);
        assert!(res.is_ok(), "setup encrypt failed: {:?}", res.err());
        (dir, input, output)
    }

    // --- ProgressThrottle -----------------------------------------------------

    #[test]
    fn throttle_emits_at_most_101_times_over_full_range() {
        let mut t = ProgressThrottle::new();
        let total = 1000u64;
        let mut emitted = 0usize;
        // Monotonically increasing done from 0..=total.
        for done in 0..=total {
            if t.should_emit(Progress {
                done,
                total: Some(total),
            }) {
                emitted += 1;
            }
        }
        // Buckets 0..=100 is 101 distinct values.
        assert!(emitted <= 101, "emitted {emitted} times, expected <= 101");
        assert_eq!(
            emitted, 101,
            "every bucket 0..=100 should emit exactly once"
        );
    }

    #[test]
    fn throttle_emits_on_each_bucket_change() {
        let mut t = ProgressThrottle::new();
        // total = 100 so done == percent bucket.
        assert!(t.should_emit(Progress {
            done: 0,
            total: Some(100)
        })); // bucket 0
        assert!(t.should_emit(Progress {
            done: 1,
            total: Some(100)
        })); // bucket 1
        assert!(t.should_emit(Progress {
            done: 2,
            total: Some(100)
        })); // bucket 2
    }

    #[test]
    fn throttle_suppresses_repeated_same_bucket() {
        let mut t = ProgressThrottle::new();
        let total = 1000u64;
        // done 0..=4 all map to bucket 0 (done*100/1000 == 0 for done <= 4).
        assert!(t.should_emit(Progress {
            done: 0,
            total: Some(total)
        }));
        for done in 1..=4 {
            assert!(
                !t.should_emit(Progress {
                    done,
                    total: Some(total)
                }),
                "done={done} should stay in bucket 0 and be suppressed"
            );
        }
    }

    #[test]
    fn throttle_zero_total_is_bucket_100() {
        let mut t = ProgressThrottle::new();
        assert!(t.should_emit(Progress {
            done: 0,
            total: Some(0)
        }));
        assert!(!t.should_emit(Progress {
            done: 0,
            total: Some(0)
        }));
    }

    #[test]
    fn throttle_none_total_always_emits() {
        let mut t = ProgressThrottle::new();
        for done in 0..5 {
            assert!(
                t.should_emit(Progress { done, total: None }),
                "None total must always emit (done={done})"
            );
        }
    }

    #[test]
    fn throttle_default_equals_new() {
        let mut a = ProgressThrottle::new();
        let mut b = ProgressThrottle::default();
        let p = Progress {
            done: 50,
            total: Some(100),
        };
        assert_eq!(a.should_emit(p), b.should_emit(p));
    }

    // --- RunError -------------------------------------------------------------

    #[test]
    fn run_error_display_delegates() {
        let fs = RunError::Fs(FsError::SameFileAsInput);
        assert_eq!(fs.to_string(), FsError::SameFileAsInput.to_string());
        let core = RunError::Core(PalError::Auth);
        assert_eq!(core.to_string(), PalError::Auth.to_string());
    }

    #[test]
    fn run_error_from_conversions() {
        let fs: RunError = FsError::SameFileAsInput.into();
        assert!(matches!(fs, RunError::Fs(_)));
        let core: RunError = PalError::Canceled.into();
        assert!(matches!(core, RunError::Core(_)));
    }

    // --- round trip -----------------------------------------------------------

    #[test]
    fn round_trip_encrypt_then_decrypt() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.txt");
        let ciphertext = dir.path().join("plain.txt.paladin");
        let recovered = dir.path().join("recovered.txt");
        let data = b"the quick brown fox jumps over the lazy dog";
        write_file(&input, data);

        let cancel = AtomicBool::new(false);
        let enc = run_job(
            encrypt_job(input.clone(), ciphertext.clone()),
            &cancel,
            noop,
        );
        assert!(enc.is_ok());
        assert!(ciphertext.exists(), "ciphertext should exist");

        let dec = run_job(
            decrypt_job(ciphertext.clone(), recovered.clone(), secret()),
            &cancel,
            noop,
        );
        assert!(dec.is_ok());
        assert_eq!(fs::read(&recovered).unwrap(), data);
    }

    #[test]
    fn round_trip_progress_is_forwarded_and_throttled() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain");
        let output = dir.path().join("out");
        // Large enough to span several chunks → several progress reports.
        let data = vec![7u8; 200 * 1024];
        write_file(&input, &data);

        let cancel = AtomicBool::new(false);
        let mut seen: Vec<Progress> = Vec::new();
        let res = run_job(encrypt_job(input.clone(), output.clone()), &cancel, |p| {
            seen.push(p)
        });
        assert!(res.is_ok());
        assert!(!seen.is_empty(), "progress should be forwarded");
        // Throttled: never more than 101 forwarded callbacks.
        assert!(seen.len() <= 101);
    }

    // --- remove_input ---------------------------------------------------------

    #[test]
    fn remove_input_deletes_input_on_success() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain");
        let output = dir.path().join("out");
        write_file(&input, b"secret data");

        let mut job = encrypt_job(input.clone(), output.clone());
        job.remove_input = true;
        let cancel = AtomicBool::new(false);
        let res = run_job(job, &cancel, noop).unwrap();

        assert!(res.remove_warning.is_none(), "no warning on clean removal");
        assert!(!input.exists(), "input should be removed");
        assert!(output.exists(), "output should remain");
    }

    // --- wrong password -------------------------------------------------------

    #[test]
    fn wrong_password_decrypt_is_auth_error_and_rolls_back() {
        let (dir, _input, ciphertext) = make_ciphertext(b"top secret");
        let recovered = dir.path().join("recovered");

        let cancel = AtomicBool::new(false);
        let res = run_job(
            decrypt_job(ciphertext, recovered.clone(), wrong_secret()),
            &cancel,
            noop,
        );
        assert!(matches!(res, Err(RunError::Core(PalError::Auth))));
        assert!(!recovered.exists(), "no output on auth failure");
    }

    // --- verify ---------------------------------------------------------------

    #[test]
    fn verify_correct_password_succeeds() {
        let (_dir, _input, ciphertext) = make_ciphertext(b"verify me");
        let cancel = AtomicBool::new(false);
        let job = Job {
            mode: Mode::Verify,
            input: ciphertext,
            output: None,
            secret: secret(),
            options: cheap_opts(),
            overwrite_approved: false,
            remove_input: false,
        };
        assert!(run_job(job, &cancel, noop).is_ok());
    }

    #[test]
    fn verify_wrong_password_is_auth_error() {
        let (_dir, _input, ciphertext) = make_ciphertext(b"verify me");
        let cancel = AtomicBool::new(false);
        let job = Job {
            mode: Mode::Verify,
            input: ciphertext,
            output: None,
            secret: wrong_secret(),
            options: cheap_opts(),
            overwrite_approved: false,
            remove_input: false,
        };
        assert!(matches!(
            run_job(job, &cancel, noop),
            Err(RunError::Core(PalError::Auth))
        ));
    }

    // --- cancellation ---------------------------------------------------------

    // The core reports progress once at done=0 immediately after key derivation
    // and before writing any output (see stream::encrypt). A flag pre-set to
    // `true` therefore returns Break on that first report, canceling even a tiny
    // input deterministically and leaving no output file.
    #[test]
    fn preset_cancel_aborts_before_output() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain");
        let output = dir.path().join("out");
        write_file(&input, b"x");

        let cancel = AtomicBool::new(true); // pre-set
        let res = run_job(encrypt_job(input.clone(), output.clone()), &cancel, noop);
        assert!(matches!(res, Err(RunError::Core(PalError::Canceled))));
        assert!(!output.exists(), "canceled run must leave no output");
    }

    #[test]
    fn cancel_from_progress_callback_rolls_back() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain");
        let output = dir.path().join("out");
        // Span multiple chunks so the loop reports more than once.
        write_file(&input, &vec![1u8; 200 * 1024]);

        let cancel = AtomicBool::new(false);
        // Flip the flag on the first forwarded progress callback.
        let res = run_job(encrypt_job(input.clone(), output.clone()), &cancel, |_p| {
            cancel.store(true, Ordering::Relaxed)
        });
        assert!(matches!(res, Err(RunError::Core(PalError::Canceled))));
        assert!(!output.exists(), "canceled run must leave no output");
    }

    // --- same file ------------------------------------------------------------

    #[test]
    fn same_file_as_input_is_rejected() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("data");
        write_file(&file, b"plaintext");
        let cancel = AtomicBool::new(false);
        // The output exists (it is the input), so overwrite must be approved for
        // `open_output` to reach the same-file guard rather than `OutputExists`.
        let mut job = encrypt_job(file.clone(), file.clone());
        job.overwrite_approved = true;
        let res = run_job(job, &cancel, noop);
        assert!(matches!(res, Err(RunError::Fs(FsError::SameFileAsInput))));
        // The input is left intact (no temp committed over it).
        assert_eq!(fs::read(&file).unwrap(), b"plaintext");
    }

    // --- overwrite ------------------------------------------------------------

    #[test]
    fn overwrite_not_approved_is_output_exists() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain");
        let output = dir.path().join("out");
        write_file(&input, b"new plaintext");
        write_file(&output, b"existing");

        let cancel = AtomicBool::new(false);
        let mut job = encrypt_job(input.clone(), output.clone());
        job.overwrite_approved = false;
        let res = run_job(job, &cancel, noop);
        assert!(matches!(res, Err(RunError::Fs(FsError::OutputExists(_)))));
        // The existing file is untouched.
        assert_eq!(fs::read(&output).unwrap(), b"existing");
    }

    #[test]
    fn overwrite_approved_replaces_file() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain");
        let output = dir.path().join("out");
        write_file(&input, b"new plaintext");
        write_file(&output, b"existing");

        let cancel = AtomicBool::new(false);
        let mut job = encrypt_job(input.clone(), output.clone());
        job.overwrite_approved = true;
        let res = run_job(job, &cancel, noop);
        assert!(res.is_ok());
        // It is now a valid paladin container, not the old bytes.
        assert_ne!(fs::read(&output).unwrap(), b"existing");

        // And it round-trips back to the plaintext.
        let recovered = dir.path().join("recovered");
        let dec = run_job(
            decrypt_job(output.clone(), recovered.clone(), secret()),
            &cancel,
            noop,
        );
        assert!(dec.is_ok());
        assert_eq!(fs::read(&recovered).unwrap(), b"new plaintext");
    }
}
