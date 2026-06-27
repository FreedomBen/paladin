//! GTK-native file glue: regular-file/same-file checks, `0600` sibling-temp
//! finalization with atomic rename, best-effort remove, and bounded keyfile
//! reading. Re-implemented here because the GTK front-end deliberately does not
//! depend on `paladin-common` (DESIGN §2.2).
//!
//! This module is plain `std` + `tempfile` + `zeroize`, with no `gtk`/`adw`/
//! `relm4` usage, so it is fully unit-testable without a display. Outputs are
//! written to a sibling temporary file (mode 0600 on Unix) and renamed into
//! place only on [`OutputFile::commit`]; on error or drop the temporary is
//! removed, so a failed run never leaves a partial output.

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use paladin_core::KEYFILE_MAX_BYTES;

/// File-glue errors. Variants are kept distinct so the relm4 app can branch on
/// them — most notably [`FsError::OutputExists`], which prompts an
/// overwrite-confirm dialog rather than aborting.
#[derive(Debug)]
pub enum FsError {
    /// A path's metadata could not be read (e.g. it is missing).
    CannotUse(PathBuf, std::io::Error),
    /// A path exists but is not a regular file (a directory, device, etc.).
    NotRegularFile(PathBuf),
    /// The output is an existing regular file and overwrite was not approved.
    /// The app uses this to pop an overwrite-confirm dialog.
    OutputExists(PathBuf),
    /// The output path exists but is not a regular file; refused even if
    /// overwrite was approved.
    OutputNotRegular(PathBuf),
    /// The output resolves to the same file as the input.
    SameFileAsInput,
    /// The keyfile is empty.
    KeyfileEmpty,
    /// The keyfile exceeds [`KEYFILE_MAX_BYTES`].
    KeyfileTooLarge,
    /// An underlying I/O error.
    Io(std::io::Error),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::CannotUse(p, e) => write!(f, "cannot use {}: {e}", p.display()),
            FsError::NotRegularFile(p) => write!(f, "{} is not a regular file", p.display()),
            FsError::OutputExists(p) => write!(f, "{} already exists", p.display()),
            FsError::OutputNotRegular(p) => {
                write!(f, "output {} exists and is not a regular file", p.display())
            }
            FsError::SameFileAsInput => {
                write!(f, "the output path refers to the same file as the input")
            }
            FsError::KeyfileEmpty => write!(f, "keyfile is empty"),
            FsError::KeyfileTooLarge => write!(f, "keyfile exceeds the 1 MiB limit"),
            FsError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FsError::CannotUse(_, e) | FsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        FsError::Io(e)
    }
}

/// Require that `path` is an existing regular file. A metadata failure yields
/// [`FsError::CannotUse`]; an existing non-regular path yields
/// [`FsError::NotRegularFile`].
pub fn require_regular_file(path: &Path) -> Result<(), FsError> {
    let meta = fs::metadata(path).map_err(|e| FsError::CannotUse(path.to_path_buf(), e))?;
    if !meta.is_file() {
        return Err(FsError::NotRegularFile(path.to_path_buf()));
    }
    Ok(())
}

/// Whether two paths refer to the same file. On Unix this compares device and
/// inode (catching hardlinks and symlinks to the same target); elsewhere it
/// compares canonical paths. Returns false if either path cannot be resolved
/// (e.g. the output does not exist yet).
pub fn is_same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (fs::metadata(a), fs::metadata(b)) {
            return ma.dev() == mb.dev() && ma.ino() == mb.ino();
        }
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

/// Read keyfile bytes (DESIGN §4.2, §6.4): an existing regular file of
/// 1 byte..=1 MiB. Bytes live in a [`Zeroizing`] buffer so they are wiped on
/// drop. Empty and over-large keyfiles are errors.
pub fn read_keyfile(path: &Path) -> Result<Zeroizing<Vec<u8>>, FsError> {
    require_regular_file(path)?;
    let file = File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    // Read one byte past the cap so an over-large file is detectable.
    file.take(KEYFILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > KEYFILE_MAX_BYTES {
        return Err(FsError::KeyfileTooLarge);
    }
    if bytes.is_empty() {
        return Err(FsError::KeyfileEmpty);
    }
    Ok(bytes)
}

/// Best-effort delete of `path` (DESIGN §6.5, §11): a plain unlink, no secure
/// overwrite. The caller warns but still succeeds if this fails.
pub fn best_effort_remove(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

/// A pending file output written through a sibling temporary file. The temporary
/// is created with mode 0600 on Unix and renamed into place by [`commit`]; if
/// the value is dropped without committing, the temporary is removed and the
/// target is left untouched.
///
/// [`commit`]: OutputFile::commit
pub struct OutputFile {
    temp: NamedTempFile,
    target: PathBuf,
}

impl OutputFile {
    /// The writer to hand to the core. The borrow ends before
    /// [`commit`](Self::commit).
    pub fn as_write(&mut self) -> &mut File {
        self.temp.as_file_mut()
    }

    /// Finalize by renaming the temporary over `target` (atomic on the same
    /// filesystem), replacing any existing file. On failure the temporary is
    /// removed.
    pub fn commit(self) -> Result<(), FsError> {
        self.temp
            .persist(&self.target)
            .map(|_| ())
            .map_err(|e| FsError::Io(e.error))
    }
}

/// Open the output target as a file finalized via a sibling temporary. The
/// checks run in order:
///
/// 1. If `target` exists and is not a regular file → [`FsError::OutputNotRegular`].
/// 2. If `target` exists, is a regular file, and `overwrite_approved` is false →
///    [`FsError::OutputExists`] (the app then asks the user to confirm).
/// 3. If `input` is `Some(i)` and resolves to the same file as `target` →
///    [`FsError::SameFileAsInput`].
///
/// Otherwise a temporary is created in `target`'s parent directory (falling back
/// to `.` when the parent is empty).
pub fn open_output(
    target: &Path,
    input: Option<&Path>,
    overwrite_approved: bool,
) -> Result<OutputFile, FsError> {
    match fs::metadata(target) {
        Ok(meta) if !meta.is_file() => {
            return Err(FsError::OutputNotRegular(target.to_path_buf()));
        }
        Ok(_) if !overwrite_approved => {
            return Err(FsError::OutputExists(target.to_path_buf()));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(FsError::Io(e)),
    }

    if let Some(input) = input {
        if is_same_file(input, target) {
            return Err(FsError::SameFileAsInput);
        }
    }

    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let temp = NamedTempFile::new_in(parent)?;
    Ok(OutputFile {
        temp,
        target: target.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_file(path: &Path, contents: &[u8]) {
        let mut f = File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    // --- require_regular_file -------------------------------------------------

    #[test]
    fn require_regular_file_accepts_a_real_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("f");
        write_file(&file, b"x");
        assert!(require_regular_file(&file).is_ok());
    }

    #[test]
    fn require_regular_file_rejects_a_directory() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            require_regular_file(dir.path()),
            Err(FsError::NotRegularFile(_))
        ));
    }

    #[test]
    fn require_regular_file_rejects_a_missing_path() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(matches!(
            require_regular_file(&missing),
            Err(FsError::CannotUse(_, _))
        ));
    }

    // --- is_same_file ---------------------------------------------------------

    #[test]
    fn is_same_file_identical_path_is_true() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        write_file(&a, b"x");
        assert!(is_same_file(&a, &a));
    }

    #[cfg(unix)]
    #[test]
    fn is_same_file_detects_hard_links() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        write_file(&a, b"x");
        std::fs::hard_link(&a, &b).unwrap();
        assert!(is_same_file(&a, &b));
    }

    #[test]
    fn is_same_file_distinguishes_distinct_files() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        write_file(&a, b"x");
        write_file(&b, b"x");
        assert!(!is_same_file(&a, &b));
    }

    #[test]
    fn is_same_file_missing_output_is_false() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        write_file(&a, b"x");
        let missing = dir.path().join("missing");
        assert!(!is_same_file(&a, &missing));
        assert!(!is_same_file(&missing, &dir.path().join("also_missing")));
    }

    // --- read_keyfile ---------------------------------------------------------

    #[test]
    fn read_keyfile_returns_exact_bytes() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("kf");
        write_file(&kf, b"\x00\x01\x02keymaterial");
        assert_eq!(&*read_keyfile(&kf).unwrap(), b"\x00\x01\x02keymaterial");
    }

    #[test]
    fn read_keyfile_rejects_empty() {
        let dir = tempdir().unwrap();
        let empty = dir.path().join("empty");
        write_file(&empty, b"");
        assert!(matches!(read_keyfile(&empty), Err(FsError::KeyfileEmpty)));
    }

    #[test]
    fn read_keyfile_accepts_exactly_max() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("kf_max");
        write_file(&kf, &vec![0u8; KEYFILE_MAX_BYTES]);
        assert_eq!(read_keyfile(&kf).unwrap().len(), KEYFILE_MAX_BYTES);
    }

    #[test]
    fn read_keyfile_rejects_over_max() {
        let dir = tempdir().unwrap();
        let big = dir.path().join("big");
        write_file(&big, &vec![0u8; KEYFILE_MAX_BYTES + 1]);
        assert!(matches!(read_keyfile(&big), Err(FsError::KeyfileTooLarge)));
    }

    #[test]
    fn read_keyfile_rejects_a_directory() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            read_keyfile(dir.path()),
            Err(FsError::NotRegularFile(_))
        ));
    }

    // --- best_effort_remove ---------------------------------------------------

    #[test]
    fn best_effort_remove_deletes_an_existing_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("victim");
        write_file(&file, b"x");
        assert!(best_effort_remove(&file).is_ok());
        assert!(!file.exists());
    }

    #[test]
    fn best_effort_remove_errors_on_missing() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("missing");
        assert!(best_effort_remove(&file).is_err());
    }

    // --- open_output / OutputFile --------------------------------------------

    #[test]
    fn open_output_new_target_commits_exact_bytes() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("out");
        let mut out = open_output(&target, None, false).unwrap();
        out.as_write().write_all(b"finalized").unwrap();
        out.commit().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"finalized");
    }

    #[cfg(unix)]
    #[test]
    fn open_output_committed_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let target = dir.path().join("out");
        let mut out = open_output(&target, None, false).unwrap();
        out.as_write().write_all(b"y").unwrap();
        out.commit().unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn open_output_overwrite_approved_replaces_contents() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("out");
        write_file(&target, b"old");
        let mut out = open_output(&target, None, true).unwrap();
        out.as_write().write_all(b"new").unwrap();
        out.commit().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn open_output_existing_without_approval_is_output_exists() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("out");
        write_file(&target, b"old");
        assert!(matches!(
            open_output(&target, None, false),
            Err(FsError::OutputExists(_))
        ));
    }

    #[test]
    fn open_output_directory_is_not_regular_even_with_approval() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("sub");
        fs::create_dir(&subdir).unwrap();
        assert!(matches!(
            open_output(&subdir, None, false),
            Err(FsError::OutputNotRegular(_))
        ));
        assert!(matches!(
            open_output(&subdir, None, true),
            Err(FsError::OutputNotRegular(_))
        ));
    }

    #[test]
    fn open_output_same_file_as_input_is_refused() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("data");
        write_file(&file, b"x");
        assert!(matches!(
            open_output(&file, Some(&file), true),
            Err(FsError::SameFileAsInput)
        ));
    }

    #[test]
    fn open_output_distinct_input_is_allowed() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("in");
        let target = dir.path().join("out");
        write_file(&input, b"plaintext");
        let mut out = open_output(&target, Some(&input), false).unwrap();
        out.as_write().write_all(b"ciphertext").unwrap();
        out.commit().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"ciphertext");
    }

    #[test]
    fn dropping_output_without_commit_leaves_no_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("out");
        {
            let mut out = open_output(&target, None, false).unwrap();
            out.as_write().write_all(b"partial").unwrap();
            // dropped here without commit
        }
        assert!(!target.exists(), "temp must not be left as the target");
        // No stray files remain in the directory.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn dropping_output_without_commit_leaves_existing_target_untouched() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("out");
        write_file(&target, b"original");
        {
            let mut out = open_output(&target, None, true).unwrap();
            out.as_write().write_all(b"discarded").unwrap();
            // dropped here without commit
        }
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }
}
