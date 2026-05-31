//! Path-or-stdin I/O, output finalization, clobber/same-file checks, and
//! best-effort remove (DESIGN §6.5).
//!
//! File outputs are written to a sibling temporary file (mode 0600 on Unix) and
//! renamed into place only after the operation succeeds; on error or drop the
//! temporary is removed, so a failed run never leaves a partial output.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::error::{AppError, AppResult};

/// The reserved stdin/stdout marker.
const DASH: &str = "-";

/// Whether `path` is the `-` stdin/stdout marker.
pub fn is_stdio(path: &Path) -> bool {
    path.as_os_str() == DASH
}

/// Require that `path` is an existing regular file (DESIGN §6.5). Directories,
/// special files, and symlinks resolving to non-regular files are usage errors.
pub fn require_regular_file(path: &Path) -> AppResult<()> {
    let meta = fs::metadata(path)
        .map_err(|e| AppError::usage(format!("cannot use {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(AppError::usage(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(())
}

/// Open the main input as a `Read`: stdin for `-`, otherwise an existing regular
/// file (DESIGN §6.5).
pub fn open_input(path: &Path) -> AppResult<Box<dyn Read>> {
    if is_stdio(path) {
        Ok(Box::new(io::stdin()))
    } else {
        require_regular_file(path)?;
        Ok(Box::new(File::open(path).map_err(AppError::Io)?))
    }
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

/// Best-effort delete of `path` (DESIGN §6.5, §11): a plain unlink, no secure
/// overwrite. The caller warns but still succeeds if this fails.
pub fn best_effort_remove(path: &Path) -> io::Result<()> {
    fs::remove_file(path)
}

/// The resolved output: stdout, or a file finalized via a sibling temporary.
pub enum OutputSink {
    Stdout(io::Stdout),
    File(FileSink),
}

/// A pending file output written through a sibling temporary file.
pub struct FileSink {
    temp: NamedTempFile,
    target: PathBuf,
}

impl OutputSink {
    /// The writer to hand to the core. Borrow ends before [`commit`](Self::commit).
    pub fn as_write(&mut self) -> &mut dyn Write {
        match self {
            OutputSink::Stdout(s) => s,
            OutputSink::File(f) => f.temp.as_file_mut(),
        }
    }

    /// Finalize: flush stdout, or rename the temporary into place. On a file
    /// rename failure the temporary is removed and `--remove` is not attempted.
    pub fn commit(self) -> AppResult<()> {
        match self {
            OutputSink::Stdout(mut s) => s.flush().map_err(AppError::Io),
            OutputSink::File(f) => f
                .temp
                .persist(&f.target)
                .map(|_| ())
                .map_err(|e| AppError::Io(e.error)),
        }
    }
}

/// Open the output target (DESIGN §6.5): stdout for `-`, otherwise a file
/// finalized via a sibling temporary. `force` permits overwriting an existing
/// regular file; `input` (when a path) is checked so the output never names the
/// same file as the input.
pub fn open_output(target: &Path, force: bool, input: Option<&Path>) -> AppResult<OutputSink> {
    if is_stdio(target) {
        return Ok(OutputSink::Stdout(io::stdout()));
    }

    // An existing target must be a regular file, even with --force; refuse to
    // clobber a regular file unless --force is set.
    match fs::metadata(target) {
        Ok(meta) if !meta.is_file() => {
            return Err(AppError::usage(format!(
                "output {} exists and is not a regular file",
                target.display()
            )));
        }
        Ok(_) if !force => {
            return Err(AppError::usage(format!(
                "output {} already exists; use -f/--force to overwrite",
                target.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(AppError::Io(e)),
    }

    if let Some(input) = input {
        if !is_stdio(input) && is_same_file(input, target) {
            return Err(AppError::usage(
                "the output path refers to the same file as the input".to_string(),
            ));
        }
    }

    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let temp = NamedTempFile::new_in(parent).map_err(AppError::Io)?;
    Ok(OutputSink::File(FileSink {
        temp,
        target: target.to_path_buf(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(path: &Path, contents: &[u8]) {
        let mut f = File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    #[test]
    fn require_regular_file_accepts_files_and_rejects_others() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("f");
        write_file(&file, b"x");
        assert!(require_regular_file(&file).is_ok());
        assert!(require_regular_file(dir.path()).is_err()); // a directory
        assert!(require_regular_file(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn open_input_reads_a_regular_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("in");
        write_file(&file, b"payload");
        let mut r = open_input(&file).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"payload");
    }

    #[test]
    fn output_commit_renames_temp_into_place() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("out");
        let mut sink = open_output(&target, false, None).unwrap();
        sink.as_write().write_all(b"finalized").unwrap();
        sink.commit().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"finalized");
    }

    #[test]
    fn dropping_output_without_commit_leaves_no_target() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("out");
        {
            let mut sink = open_output(&target, false, None).unwrap();
            sink.as_write().write_all(b"partial").unwrap();
            // sink dropped here without commit
        }
        assert!(!target.exists(), "temp must not be left as the target");
        // No stray files remain in the directory.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn clobber_is_refused_without_force_and_allowed_with_force() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("out");
        write_file(&target, b"old");
        assert!(open_output(&target, false, None).is_err());
        let mut sink = open_output(&target, true, None).unwrap();
        sink.as_write().write_all(b"new").unwrap();
        sink.commit().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn existing_directory_output_is_rejected_even_with_force() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("sub");
        fs::create_dir(&subdir).unwrap();
        assert!(open_output(&subdir, true, None).is_err());
    }

    #[test]
    fn output_equal_to_input_is_refused() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("data");
        write_file(&file, b"x");
        assert!(open_output(&file, true, Some(&file)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn same_file_detects_hardlinks_and_output_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        write_file(&a, b"x");
        fs::hard_link(&a, &b).unwrap();
        assert!(is_same_file(&a, &b));
        // A fresh, unrelated output is finalized with mode 0600.
        let target = dir.path().join("out");
        let mut sink = open_output(&target, false, None).unwrap();
        sink.as_write().write_all(b"y").unwrap();
        sink.commit().unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn best_effort_remove_deletes_then_errors_when_missing() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("victim");
        write_file(&file, b"x");
        assert!(best_effort_remove(&file).is_ok());
        assert!(!file.exists());
        assert!(best_effort_remove(&file).is_err());
    }

    #[test]
    fn dash_opens_stdin_and_stdout() {
        // The "-" marker is recognized; real paths are not.
        assert!(is_stdio(Path::new("-")));
        assert!(!is_stdio(Path::new("file")));
        // open_input("-") yields a reader without touching the filesystem.
        // Do NOT read from it here; that would block on the real stdin.
        assert!(open_input(Path::new("-")).is_ok());
        // open_output("-") is stdout and commits by flushing (no bytes written).
        let sink = open_output(Path::new("-"), false, None).unwrap();
        assert!(matches!(sink, OutputSink::Stdout(_)));
        sink.commit().unwrap();
    }

    #[test]
    fn is_same_file_distinguishes_different_and_missing_paths() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        write_file(&a, b"x");
        write_file(&b, b"x");
        // Two distinct files are not the same file.
        assert!(!is_same_file(&a, &b));
        // A missing operand makes the comparison false, not an error.
        let missing = dir.path().join("missing");
        assert!(!is_same_file(&a, &missing));
        assert!(!is_same_file(&missing, &dir.path().join("also_missing")));
    }

    #[test]
    fn output_differing_from_input_is_allowed() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in");
        let target = dir.path().join("out");
        write_file(&input, b"plaintext");
        // A distinct input must not trip the same-file guard, even with force off.
        let mut sink = open_output(&target, false, Some(&input)).unwrap();
        sink.as_write().write_all(b"ciphertext").unwrap();
        sink.commit().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"ciphertext");
    }
}
