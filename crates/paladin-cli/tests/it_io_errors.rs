//! Integration tests for exit code 1 — general I/O errors (DESIGN §6.6).
//!
//! The clean trigger is an output path whose parent directory does not exist
//! (or is not a directory): the CLI creates a sibling temp file in that parent
//! before any crypto runs, and the failing `io::Error` maps to exit code 1.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn sc() -> Command {
    Command::cargo_bin("paladin").unwrap()
}

const FAST_KDF: [&str; 4] = ["--kdf", "pbkdf2", "--pbkdf2-iterations", "10000"];

/// Encrypting into a missing parent directory is an I/O error (exit 1), and
/// neither the output nor its missing parent directory is created.
#[test]
fn encrypt_into_missing_output_dir_is_io_error() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.txt");
    fs::write(&input, b"some bytes").unwrap();
    let missing_parent = dir.path().join("nope");
    let out = missing_parent.join("out.bin");
    sc().arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&out)
        .assert()
        .code(1);
    assert!(!out.exists(), "no output should be created on an I/O error");
    assert!(
        !missing_parent.exists(),
        "the missing parent directory must not be created"
    );
}

/// Decrypting into a missing parent directory is an I/O error (exit 1), not an
/// auth failure: the output is opened before any decryption begins.
#[test]
fn decrypt_into_missing_output_dir_is_io_error() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.txt");
    fs::write(&input, b"some bytes").unwrap();
    let cipher = dir.path().join("c.bin");
    sc().arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();

    let out = dir.path().join("nope2").join("out");
    sc().arg("-d")
        .arg(&cipher)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&out)
        .assert()
        .code(1);
    assert!(!out.exists(), "no output should be created on an I/O error");
}

/// Encrypting where the output's parent path is a regular file (not a
/// directory) is an I/O error (exit 1): creating a temp file inside a
/// non-directory fails.
#[test]
fn encrypt_with_output_parent_being_a_regular_file_is_io_error() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.txt");
    fs::write(&input, b"some bytes").unwrap();
    let notdir = dir.path().join("notdir");
    fs::write(&notdir, b"i am a file").unwrap();
    let out = notdir.join("out.bin");
    sc().arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&out)
        .assert()
        .code(1);
}
