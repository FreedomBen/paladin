//! STDIN (`-`) tests for `--info` and `--verify` on the `symcrypt` binary.
//!
//! DESIGN §6.5 says info/verify accept the container on stdin and need no `-o`,
//! and that decrypt/verify/info auto-detect ASCII armor. These tests pipe both
//! binary and armored containers into `-i -` / `--verify -` and assert the
//! byte-exact metadata block, success on the right password, and the auth
//! failure (exit 3) on the wrong one — including the armored cases, which must
//! work over a non-seekable pipe.

use assert_cmd::Command;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn sc() -> Command {
    Command::cargo_bin("symcrypt").unwrap()
}

const FAST_KDF: [&str; 4] = ["--kdf", "pbkdf2", "--pbkdf2-iterations", "10000"];

/// Encrypt `plaintext` with the fast KDF and any `extra` args (e.g. `-a`),
/// returning the raw container bytes.
fn encrypt_to_bytes(dir: &Path, plaintext: &[u8], extra: &[&str]) -> Vec<u8> {
    let input = dir.join("plain.bin");
    fs::write(&input, plaintext).unwrap();
    let cipher = dir.join("cipher.out");
    let mut cmd = sc();
    cmd.arg("-e").arg(&input).args(FAST_KDF).args(["-p", "pw"]);
    cmd.args(extra);
    cmd.arg("-o").arg(&cipher).assert().success();
    fs::read(&cipher).unwrap()
}

// ---------------------------------------------------------------------------
// 1 — `--info` reading a binary container from stdin is byte-exact.
// ---------------------------------------------------------------------------

/// `-i -` reads the container from stdin and prints the full 12-line block.
#[test]
fn info_from_stdin_binary_is_byte_exact() {
    let tmp = TempDir::new().unwrap();
    let container = encrypt_to_bytes(tmp.path(), b"hello stdin info", &[]);

    let assert = sc()
        .arg("-i")
        .arg("-")
        .write_stdin(container)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    let expected = concat!(
        "format: symcrypt\n",
        "version: 1\n",
        "cipher: aes-256-gcm\n",
        "kdf: pbkdf2\n",
        "kdf_params: iterations=10000\n",
        "flags: 0x00\n",
        "keyfile_hint: false\n",
        "chunk_size: 65536\n",
        "salt_len: 16\n",
        "nonce_prefix_len: 7\n",
        "name_status: absent\n",
        "name: \n",
    );
    assert_eq!(stdout, expected);
}

// ---------------------------------------------------------------------------
// 2 — `--info` auto-detects armor from a non-seekable stdin pipe.
// ---------------------------------------------------------------------------

/// `-i -` on an armored container yields the same metadata block; armor is
/// transparent to the header and must be auto-detected from the pipe.
#[test]
fn info_from_stdin_armored_is_autodetected() {
    let tmp = TempDir::new().unwrap();
    let container = encrypt_to_bytes(tmp.path(), b"hello stdin armor", &["-a"]);

    let assert = sc()
        .arg("-i")
        .arg("-")
        .write_stdin(container)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    let expected = concat!(
        "format: symcrypt\n",
        "version: 1\n",
        "cipher: aes-256-gcm\n",
        "kdf: pbkdf2\n",
        "kdf_params: iterations=10000\n",
        "flags: 0x00\n",
        "keyfile_hint: false\n",
        "chunk_size: 65536\n",
        "salt_len: 16\n",
        "nonce_prefix_len: 7\n",
        "name_status: absent\n",
        "name: \n",
    );
    assert_eq!(stdout, expected);
}

// ---------------------------------------------------------------------------
// 3 — `--verify` from stdin with the correct password succeeds.
// ---------------------------------------------------------------------------

/// `--verify -` reads the container from stdin; the right password exits 0.
#[test]
fn verify_from_stdin_correct_password_succeeds() {
    let tmp = TempDir::new().unwrap();
    let container = encrypt_to_bytes(tmp.path(), b"verify via stdin", &[]);

    sc().arg("--verify")
        .arg("-")
        .args(["-p", "pw"])
        .write_stdin(container)
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// 4 — `--verify` from stdin with the wrong password is an auth failure.
// ---------------------------------------------------------------------------

/// A wrong password on `--verify -` is reported as auth failure (exit 3).
#[test]
fn verify_from_stdin_wrong_password_is_auth_failure() {
    let tmp = TempDir::new().unwrap();
    let container = encrypt_to_bytes(tmp.path(), b"verify via stdin", &[]);

    sc().arg("--verify")
        .arg("-")
        .args(["-p", "wrong"])
        .write_stdin(container)
        .assert()
        .code(3);
}

// ---------------------------------------------------------------------------
// 5 — `--verify` auto-detects armor from stdin with the correct password.
// ---------------------------------------------------------------------------

/// `--verify -` on an armored container succeeds; armor is auto-detected from
/// the non-seekable pipe.
#[test]
fn verify_from_stdin_armored_correct_password_succeeds() {
    let tmp = TempDir::new().unwrap();
    let container = encrypt_to_bytes(tmp.path(), b"armored verify", &["-a"]);

    sc().arg("--verify")
        .arg("-")
        .args(["-p", "pw"])
        .write_stdin(container)
        .assert()
        .success();
}
