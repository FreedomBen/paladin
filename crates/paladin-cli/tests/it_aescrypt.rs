//! AES Crypt (`.aes`) read-interop tests for the `paladin` binary (PLAN_05 §6).
//!
//! These run against a genuine AES Crypt Stream Format 2 fixture minted by
//! `aescrypt 3.16.1` (committed under `paladin-core/tests/data/aescrypt/`), so
//! they exercise the real decrypt/verify/inspect paths the way a user would.

use assert_cmd::Command;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// A genuine AES Crypt v2 fixture: 17-byte plaintext (bytes 0..17), ASCII
/// password. Shared with the core round-trip tests.
const V2_FIXTURE: &[u8] = include_bytes!("../../paladin-core/tests/data/aescrypt/v2_size_17.aes");
const PASSWORD: &str = "aescrypt test password";

/// A fresh `Command` for the `paladin` binary under test.
fn sc() -> Command {
    Command::cargo_bin("paladin").unwrap()
}

/// Write the fixture (optionally mutated) into `dir` and return its path.
fn place(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

/// The fixture's expected plaintext.
fn expected_plaintext() -> Vec<u8> {
    (0..17u8).collect()
}

// ---------------------------------------------------------------------------
// Decrypt.
// ---------------------------------------------------------------------------

#[test]
fn decrypt_default_output_strips_aes_suffix() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    sc().arg("-d")
        .arg(&aes)
        .args(["-p", PASSWORD])
        .assert()
        .success();
    // The default output drops the `.aes` suffix beside the input.
    let out = dir.path().join("sample");
    assert_eq!(fs::read(&out).unwrap(), expected_plaintext());
}

#[test]
fn decrypt_to_explicit_output_matches_plaintext() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let out = dir.path().join("plain.bin");
    sc().arg("-d")
        .arg(&aes)
        .args(["-p", PASSWORD])
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    assert_eq!(fs::read(&out).unwrap(), expected_plaintext());
}

#[test]
fn decrypt_to_stdout_streams_plaintext() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let assert = sc()
        .arg("-d")
        .arg(&aes)
        .args(["-p", PASSWORD])
        .args(["-o", "-"])
        .assert()
        .success();
    assert_eq!(assert.get_output().stdout, expected_plaintext());
}

#[test]
fn decrypt_wrong_password_is_auth_error() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let out = dir.path().join("plain.bin");
    sc().arg("-d")
        .arg(&aes)
        .args(["-p", "wrong"])
        .arg("-o")
        .arg(&out)
        .assert()
        .code(3);
    assert!(!out.exists(), "no output on auth failure");
}

#[test]
fn decrypt_truncated_body_is_auth_error() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "trunc.aes", &V2_FIXTURE[..V2_FIXTURE.len() - 1]);
    sc().arg("-d")
        .arg(&aes)
        .args(["-p", PASSWORD])
        .arg("-o")
        .arg(dir.path().join("out"))
        .assert()
        .code(3);
}

#[test]
fn unsupported_version_is_format_error() {
    let dir = TempDir::new().unwrap();
    let mut bytes = V2_FIXTURE.to_vec();
    bytes[3] = 0x03; // Stream Format 3 is not yet implemented
    let aes = place(dir.path(), "v3.aes", &bytes);
    sc().arg("-i").arg(&aes).assert().code(4);
}

// ---------------------------------------------------------------------------
// Verify.
// ---------------------------------------------------------------------------

#[test]
fn verify_accepts_correct_password() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    sc().arg("--verify")
        .arg(&aes)
        .args(["-p", PASSWORD])
        .assert()
        .success();
}

#[test]
fn verify_rejects_wrong_password() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    sc().arg("--verify")
        .arg(&aes)
        .args(["-p", "wrong"])
        .assert()
        .code(3);
}

// ---------------------------------------------------------------------------
// Keyfile / --no-password against a .aes file: usage error (exit 2), and it
// fires before any password prompt or keyfile read (PLAN_05 §6).
// ---------------------------------------------------------------------------

#[test]
fn keyfile_with_aescrypt_decrypt_default_output_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let key = place(dir.path(), "key.bin", b"keymaterial");
    sc().arg("-d")
        .arg(&aes)
        .arg("-k")
        .arg(&key)
        .assert()
        .code(2);
}

#[test]
fn keyfile_with_aescrypt_decrypt_explicit_output_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let key = place(dir.path(), "key.bin", b"keymaterial");
    sc().arg("-d")
        .arg(&aes)
        .arg("-k")
        .arg(&key)
        .arg("-o")
        .arg(dir.path().join("out"))
        .assert()
        .code(2);
}

#[test]
fn keyfile_with_aescrypt_verify_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let key = place(dir.path(), "key.bin", b"keymaterial");
    sc().arg("--verify")
        .arg(&aes)
        .arg("-k")
        .arg(&key)
        .assert()
        .code(2);
}

#[test]
fn no_password_keyfile_with_aescrypt_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let key = place(dir.path(), "key.bin", b"keymaterial");
    sc().arg("-d")
        .arg(&aes)
        .arg("--no-password")
        .arg("-k")
        .arg(&key)
        .assert()
        .code(2);
}

#[test]
fn non_utf8_password_file_against_aescrypt_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let pwf = place(dir.path(), "pw.bin", &[0xFF, 0xFE, 0x00]);
    sc().arg("-d")
        .arg(&aes)
        .arg("--password-file")
        .arg(&pwf)
        .arg("-o")
        .arg(dir.path().join("out"))
        .assert()
        .code(2);
}

// ---------------------------------------------------------------------------
// Info: byte-exact AES Crypt block.
// ---------------------------------------------------------------------------

#[test]
fn info_block_is_byte_exact() {
    let dir = TempDir::new().unwrap();
    let aes = place(dir.path(), "sample.aes", V2_FIXTURE);
    let assert = sc().arg("-i").arg(&aes).assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let expected = concat!(
        "format: aescrypt\n",
        "version: 2\n",
        "cipher: aes-256-cbc\n",
        "kdf: aescrypt-sha256\n",
        "kdf_iterations: 8192\n",
        "extensions: 2\n",
        "created_by: aescrypt 3.16.1\n",
        "authenticated: false\n",
    );
    assert_eq!(stdout, expected);
}
