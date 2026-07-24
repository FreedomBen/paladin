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
use std::io::{BufReader, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use paladin_core::{
    decrypt, encrypt, inspect, is_armored, verify, EncryptOptions, Metadata, PalError, Progress,
    Secret,
};

use crate::editor::{self, BoundedPlainWriter, EDITOR_MAX_BYTES};
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

/// The progress closure every runner hands to the core: observe `cancel` (a
/// set flag returns `Break`, which the core maps to [`PalError::Canceled`])
/// and forward throttled reports to `on_progress`.
fn progress_cb<'a, P: FnMut(Progress)>(
    cancel: &'a AtomicBool,
    throttle: &'a mut ProgressThrottle,
    on_progress: &'a mut P,
) -> impl FnMut(Progress) -> ControlFlow<()> + 'a {
    move |p: Progress| {
        if cancel.load(Ordering::Relaxed) {
            return ControlFlow::Break(());
        }
        if throttle.should_emit(p) {
            on_progress(p);
        }
        ControlFlow::Continue(())
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
    let mut cb = progress_cb(cancel, &mut throttle, &mut on_progress);

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
        Mode::Info | Mode::Edit => {
            // Info runs inline via `inspect`; Edit opens through
            // [`open_for_edit`]. Neither is ever built into a generic `Job`.
            debug_assert!(false, "Info/Edit are never generic worker Jobs");
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

// --- Editor open/save (DESIGN §8.4) -----------------------------------------

/// Everything the editor window needs after a successful open: the decrypted
/// text, the metadata its save derivation starts from, the recorded armor
/// layer, the backing path, and the session secret (retained so Save never
/// re-prompts; dropped — and zeroized — when the window closes).
pub struct EditorSeed {
    /// The decrypted text; zeroized on drop once its contents enter the widget.
    pub text: Zeroizing<String>,
    /// What `inspect` recognized (paladin vs AES Crypt source).
    pub metadata: Metadata,
    /// Whether the source was ASCII-armored; saves re-armor in kind.
    pub armored: bool,
    /// The opened file; Save writes back here.
    pub path: PathBuf,
    /// The session secret.
    pub secret: Secret,
}

/// Why an editor open failed. `TooLarge` and `NotText` get editor-specific
/// dialogs pointing at Decrypt mode; the other arms map like any run error.
#[derive(Debug)]
pub enum OpenError {
    /// The decrypted text exceeds the [`EDITOR_MAX_BYTES`] cap.
    TooLarge,
    /// The decrypted content is not UTF-8 text.
    NotText,
    /// A filesystem/glue error (missing input, not a regular file, …).
    Fs(FsError),
    /// A core error (auth failure, malformed file, canceled, …).
    Core(PalError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::TooLarge => write!(
                f,
                "the decrypted text exceeds the {} MiB editor limit",
                EDITOR_MAX_BYTES / (1024 * 1024)
            ),
            OpenError::NotText => write!(f, "{}", editor::NotText),
            OpenError::Fs(e) => write!(f, "{e}"),
            OpenError::Core(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Fs(e) => Some(e),
            OpenError::Core(e) => Some(e),
            OpenError::TooLarge | OpenError::NotText => None,
        }
    }
}

/// Ciphertext longer than this cannot decode to text under the editor cap, so
/// the open is refused before any KDF work. Worst case the plaintext is still
/// ≈ 0.72 × the file length (base64 armor with line breaks, minus bounded
/// header and per-chunk tag overhead), so at 2 × the cap the plaintext is
/// certainly over it. Fast path only — the bounded writer stays authoritative.
const OPEN_FAST_REFUSE: u64 = EDITOR_MAX_BYTES as u64 * 2;

/// Open `path` for the editor (DESIGN §8.4): decrypt it into a bounded
/// in-memory buffer and gate the result, returning the seed the editor window
/// is built from.
///
/// Steps: require a regular file → fast-refuse ciphertext over
/// [`OPEN_FAST_REFUSE`] → `inspect` (recording whether the source is a paladin
/// or AES Crypt container) → record the armor layer via `is_armored` → decrypt
/// through a [`BoundedPlainWriter`] capped at [`EDITOR_MAX_BYTES`] → strict
/// UTF-8 gate. Cancellation and progress behave exactly as in [`run_job`];
/// nothing is written to disk on any path.
pub fn open_for_edit<P: FnMut(Progress)>(
    path: &Path,
    secret: Secret,
    cancel: &AtomicBool,
    mut on_progress: P,
) -> Result<EditorSeed, OpenError> {
    fsio::require_regular_file(path).map_err(OpenError::Fs)?;

    let input_len = std::fs::metadata(path).ok().map(|m| m.len());
    if input_len.is_some_and(|len| len > OPEN_FAST_REFUSE) {
        return Err(OpenError::TooLarge);
    }

    let open = |p: &Path| File::open(p).map_err(|e| OpenError::Fs(FsError::Io(e)));

    // Which container is this? Save derivation needs to know (paladin headers
    // are preserved; AES Crypt sources migrate behind a confirmation).
    let metadata = inspect(BufReader::new(open(path)?)).map_err(OpenError::Core)?;

    // Record the armor layer from the leading bytes so a save re-encrypts in
    // kind; 512 bytes always decide exactly (see `paladin_core::is_armored`).
    let armored = {
        let mut file = open(path)?;
        let mut prefix = [0u8; 512];
        let mut filled = 0;
        loop {
            match file.read(&mut prefix[filled..]) {
                Ok(0) => break,
                Ok(n) => {
                    filled += n;
                    if filled == prefix.len() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(OpenError::Fs(FsError::Io(e))),
            }
        }
        is_armored(&prefix[..filled])
    };

    // Decrypt to memory behind the cap. No disk output exists on any path.
    let mut reader = BufReader::new(open(path)?);
    let mut writer = BoundedPlainWriter::new();
    let mut throttle = ProgressThrottle::new();
    let mut cb = progress_cb(cancel, &mut throttle, &mut on_progress);
    if let Err(e) = decrypt(&mut reader, &mut writer, &secret, input_len, &mut cb) {
        // The bounded writer failing the run is "too large", not an I/O fault.
        return Err(if writer.overflowed() {
            OpenError::TooLarge
        } else {
            OpenError::Core(e)
        });
    }

    let text = editor::text_from_buffer(writer.into_buffer()).map_err(|_| OpenError::NotText)?;
    Ok(EditorSeed {
        text,
        metadata,
        armored,
        path: path.to_path_buf(),
        secret,
    })
}

/// Encrypt the editor buffer to `target` through the same sibling-temp +
/// atomic-rename path as every other output, so a crash mid-save leaves the
/// original file intact (DESIGN §8.4). Every save is a complete fresh encrypt
/// (new salt and nonce prefix).
///
/// Overwrite is implicitly approved: Save writes back to the opened file
/// (that is what Save means) and Save As targets come from the native save
/// dialog, which already confirmed replacement. No same-file guard applies —
/// the input is the in-memory buffer, not a file.
pub fn save_from_editor<P: FnMut(Progress)>(
    text: &[u8],
    target: &Path,
    secret: &Secret,
    options: &EncryptOptions,
    cancel: &AtomicBool,
    mut on_progress: P,
) -> Result<(), RunError> {
    let mut out = fsio::open_output(target, None, true)?;
    let mut throttle = ProgressThrottle::new();
    let mut cb = progress_cb(cancel, &mut throttle, &mut on_progress);
    encrypt(
        text,
        out.as_write(),
        secret,
        options,
        Some(text.len() as u64),
        &mut cb,
    )
    .map_err(RunError::Core)?;
    out.commit()?;
    Ok(())
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

    // --- editor open/save (DESIGN §8.4) ----------------------------------------

    use crate::editor::SaveSource;

    /// The committed AES Crypt fixture from `paladin-core`'s test data.
    const AESCRYPT_V2: &[u8] =
        include_bytes!("../../paladin-core/tests/data/aescrypt/v2_size_17.aes");

    #[test]
    fn editor_round_trip_open_edit_save_reopen() {
        let (_dir, _plain, ct) = make_ciphertext(b"first draft\n");
        let cancel = AtomicBool::new(false);

        let seed = open_for_edit(&ct, secret(), &cancel, noop).unwrap();
        assert_eq!(&**seed.text, "first draft\n");
        assert!(matches!(seed.metadata, Metadata::Paladin(_)));
        assert!(!seed.armored);
        assert_eq!(seed.path, ct);

        // Derive the save options exactly as the editor window does.
        let source = SaveSource::from_metadata(&seed.metadata);
        assert!(!source.needs_migration_confirm());
        let opts = source.options_for(seed.armored, &seed.path).unwrap();
        save_from_editor(
            b"second draft\n",
            &seed.path,
            &seed.secret,
            &opts,
            &cancel,
            noop,
        )
        .unwrap();

        let reopened = open_for_edit(&ct, secret(), &cancel, noop).unwrap();
        assert_eq!(&**reopened.text, "second draft\n");
    }

    #[test]
    fn editor_preserves_armor_on_save() {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("a.txt");
        let ct = dir.path().join("a.txt.paladin.asc");
        write_file(&plain, b"armored text\n");
        let mut job = encrypt_job(plain, ct.clone());
        job.options.armor = true;
        let cancel = AtomicBool::new(false);
        run_job(job, &cancel, noop).unwrap();

        let seed = open_for_edit(&ct, secret(), &cancel, noop).unwrap();
        assert!(seed.armored, "the armor layer must be recorded at open");
        let opts = SaveSource::from_metadata(&seed.metadata)
            .options_for(seed.armored, &seed.path)
            .unwrap();
        assert!(opts.armor);
        save_from_editor(b"still armored\n", &ct, &seed.secret, &opts, &cancel, noop).unwrap();

        let bytes = fs::read(&ct).unwrap();
        assert!(bytes.starts_with(b"-----BEGIN PALADIN MESSAGE-----"));
        let reopened = open_for_edit(&ct, secret(), &cancel, noop).unwrap();
        assert!(reopened.armored);
        assert_eq!(&**reopened.text, "still armored\n");
    }

    #[test]
    fn editor_preserves_the_stored_name_choice() {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("orig.txt");
        let ct = dir.path().join("orig.txt.paladin");
        write_file(&plain, b"named text\n");
        let mut job = encrypt_job(plain, ct.clone());
        job.options.filename = Some("orig.txt".to_owned());
        let cancel = AtomicBool::new(false);
        run_job(job, &cancel, noop).unwrap();

        let seed = open_for_edit(&ct, secret(), &cancel, noop).unwrap();
        let opts = SaveSource::from_metadata(&seed.metadata)
            .options_for(seed.armored, &seed.path)
            .unwrap();
        // The choice is preserved; the embedded name is the save target's.
        assert_eq!(opts.filename.as_deref(), Some("orig.txt.paladin"));
        save_from_editor(b"renamed inside\n", &ct, &seed.secret, &opts, &cancel, noop).unwrap();

        let reopened = open_for_edit(&ct, secret(), &cancel, noop).unwrap();
        let Metadata::Paladin(header) = &reopened.metadata else {
            panic!("expected a paladin container");
        };
        assert_eq!(header.name.as_deref(), Some("orig.txt.paladin"));
    }

    #[test]
    fn editor_open_wrong_password_is_auth() {
        let (_dir, _plain, ct) = make_ciphertext(b"secret text");
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            open_for_edit(&ct, wrong_secret(), &cancel, noop),
            Err(OpenError::Core(PalError::Auth))
        ));
    }

    #[test]
    fn editor_migrates_an_aes_crypt_source_after_confirmation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.aes");
        write_file(&path, AESCRYPT_V2);
        let cancel = AtomicBool::new(false);
        let aes_secret = || Secret::new(b"aescrypt test password", None).unwrap();

        let seed = open_for_edit(&path, aes_secret(), &cancel, noop).unwrap();
        assert!(matches!(seed.metadata, Metadata::AesCrypt(_)));
        assert!(!seed.armored);
        let expected: Vec<u8> = (0..17).collect();
        assert_eq!(seed.text.as_bytes(), &expected[..]);

        // The window shows the migration dialog before this save...
        let mut source = SaveSource::from_metadata(&seed.metadata);
        assert!(source.needs_migration_confirm());

        // ...and on confirmation writes the derived options. That those derive
        // to the §12 defaults is asserted in editor.rs; cheap KDF parameters
        // keep this unoptimized test build fast through the same flow.
        let mut opts = source.options_for(seed.armored, &path).unwrap();
        opts.kdf_params = KdfParams::Argon2id {
            memory_kib: 8192,
            time_cost: 1,
            parallelism: 1,
        };
        save_from_editor(b"migrated\n", &path, &seed.secret, &opts, &cancel, noop).unwrap();
        source.saved(&opts);
        assert!(!source.needs_migration_confirm());

        // Same path, same .aes extension — but now a paladin container.
        let reopened = open_for_edit(&path, aes_secret(), &cancel, noop).unwrap();
        assert!(matches!(reopened.metadata, Metadata::Paladin(_)));
        assert_eq!(&**reopened.text, "migrated\n");
    }

    #[test]
    fn editor_open_fast_refuses_oversize_ciphertext() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("huge");
        // Over the fast-refuse bound: rejected before any header parsing or
        // KDF work, so the content need not be a valid container.
        write_file(&path, &vec![0u8; EDITOR_MAX_BYTES * 2 + 1]);
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            open_for_edit(&path, secret(), &cancel, noop),
            Err(OpenError::TooLarge)
        ));
    }

    #[test]
    fn editor_open_aborts_at_the_streamed_cap() {
        // Plaintext just over the cap but ciphertext under the fast-refuse
        // bound: the bounded writer must catch it mid-stream.
        let dir = tempdir().unwrap();
        let plain = dir.path().join("big.txt");
        let ct = dir.path().join("big.txt.paladin");
        write_file(&plain, &vec![b'a'; EDITOR_MAX_BYTES + 1]);
        let cancel = AtomicBool::new(false);
        run_job(encrypt_job(plain, ct.clone()), &cancel, noop).unwrap();
        assert!(fs::metadata(&ct).unwrap().len() <= OPEN_FAST_REFUSE);
        assert!(matches!(
            open_for_edit(&ct, secret(), &cancel, noop),
            Err(OpenError::TooLarge)
        ));
    }

    #[test]
    fn editor_open_rejects_binary_content_as_not_text() {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("blob");
        let ct = dir.path().join("blob.paladin");
        write_file(&plain, &[0xff, 0xfe, 0x00, 0x01]);
        let cancel = AtomicBool::new(false);
        run_job(encrypt_job(plain, ct.clone()), &cancel, noop).unwrap();
        assert!(matches!(
            open_for_edit(&ct, secret(), &cancel, noop),
            Err(OpenError::NotText)
        ));
    }

    #[test]
    fn editor_open_preset_cancel_is_canceled() {
        let (_dir, _plain, ct) = make_ciphertext(b"cancel me");
        let cancel = AtomicBool::new(true); // pre-set
        assert!(matches!(
            open_for_edit(&ct, secret(), &cancel, noop),
            Err(OpenError::Core(PalError::Canceled))
        ));
    }

    #[test]
    fn editor_save_refuses_a_non_regular_target() {
        let dir = tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let res = save_from_editor(b"x", dir.path(), &secret(), &cheap_opts(), &cancel, noop);
        assert!(matches!(
            res,
            Err(RunError::Fs(FsError::OutputNotRegular(_)))
        ));
    }

    #[test]
    fn editor_saves_are_complete_fresh_encrypts() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("n.paladin");
        let cancel = AtomicBool::new(false);
        save_from_editor(
            b"same text",
            &target,
            &secret(),
            &cheap_opts(),
            &cancel,
            noop,
        )
        .unwrap();
        let first = fs::read(&target).unwrap();
        save_from_editor(
            b"same text",
            &target,
            &secret(),
            &cheap_opts(),
            &cancel,
            noop,
        )
        .unwrap();
        let second = fs::read(&target).unwrap();
        // DESIGN §11: every save uses a fresh salt and nonce prefix.
        assert_ne!(first, second);
    }

    #[test]
    fn open_error_messages_are_nonempty_and_distinct() {
        let too_large = OpenError::TooLarge.to_string();
        let not_text = OpenError::NotText.to_string();
        assert!(too_large.contains("8 MiB"));
        assert!(!not_text.is_empty());
        assert_ne!(too_large, not_text);
    }
}
