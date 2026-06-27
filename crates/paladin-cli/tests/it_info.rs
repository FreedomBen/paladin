//! Byte-exact `--info` output tests for the `paladin` binary (DESIGN §6).
//!
//! Each test encrypts a small file with a chosen KDF/flags, then runs `-i` on
//! the ciphertext and asserts the complete 12-line metadata block stdout,
//! enforcing the exact contract (field order, hex flags, trailing space on an
//! empty `name:`, and the final trailing newline).

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

/// A fresh `Command` for the `paladin` binary under test.
fn sc() -> Command {
    Command::cargo_bin("paladin").unwrap()
}

/// Run `-i <cipher>` and return its stdout as a UTF-8 string (asserts success).
fn info_stdout(cipher: &std::path::Path) -> String {
    let assert = sc().arg("-i").arg(cipher).assert().success();
    String::from_utf8(assert.get_output().stdout.clone()).unwrap()
}

// ---------------------------------------------------------------------------
// 1 — Argon2id: full byte-exact 12-line block.
// ---------------------------------------------------------------------------

#[test]
fn info_argon2id_full_block() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("cipher.bin");
    fs::write(&plain, b"hello argon2id").unwrap();

    sc().arg("-e")
        .arg(&plain)
        .arg("-o")
        .arg(&cipher)
        .args(["-p", "pw"])
        .args(["--kdf", "argon2id"])
        .args(["--argon2-memory", "8192"])
        .args(["--argon2-time", "1"])
        .args(["--argon2-parallelism", "1"])
        .assert()
        .success();

    let expected = concat!(
        "format: paladin\n",
        "version: 1\n",
        "cipher: aes-256-gcm\n",
        "kdf: argon2id\n",
        "kdf_params: memory=8192,time=1,parallelism=1\n",
        "flags: 0x00\n",
        "keyfile_hint: false\n",
        "chunk_size: 65536\n",
        "salt_len: 16\n",
        "nonce_prefix_len: 7\n",
        "name_status: absent\n",
        "name: \n",
    );
    assert_eq!(info_stdout(&cipher), expected);
}

// ---------------------------------------------------------------------------
// 2 — scrypt: full byte-exact 12-line block.
// ---------------------------------------------------------------------------

#[test]
fn info_scrypt_full_block() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("cipher.bin");
    fs::write(&plain, b"hello scrypt").unwrap();

    sc().arg("-e")
        .arg(&plain)
        .arg("-o")
        .arg(&cipher)
        .args(["-p", "pw"])
        .args(["--kdf", "scrypt"])
        .args(["--scrypt-log-n", "10"])
        .args(["--scrypt-r", "1"])
        .args(["--scrypt-p", "1"])
        .assert()
        .success();

    let expected = concat!(
        "format: paladin\n",
        "version: 1\n",
        "cipher: aes-256-gcm\n",
        "kdf: scrypt\n",
        "kdf_params: log_n=10,r=1,p=1\n",
        "flags: 0x00\n",
        "keyfile_hint: false\n",
        "chunk_size: 65536\n",
        "salt_len: 16\n",
        "nonce_prefix_len: 7\n",
        "name_status: absent\n",
        "name: \n",
    );
    assert_eq!(info_stdout(&cipher), expected);
}

// ---------------------------------------------------------------------------
// 3 — pbkdf2: full byte-exact 12-line block.
// ---------------------------------------------------------------------------

#[test]
fn info_pbkdf2_full_block() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("cipher.bin");
    fs::write(&plain, b"hello pbkdf2").unwrap();

    sc().arg("-e")
        .arg(&plain)
        .arg("-o")
        .arg(&cipher)
        .args(["-p", "pw"])
        .args(["--kdf", "pbkdf2"])
        .args(["--pbkdf2-iterations", "10000"])
        .assert()
        .success();

    let expected = concat!(
        "format: paladin\n",
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
    assert_eq!(info_stdout(&cipher), expected);
}

// ---------------------------------------------------------------------------
// 4 — stored name present: flags 0x01, name echoed back.
// ---------------------------------------------------------------------------

#[test]
fn info_stored_name_present() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("report.pdf");
    let cipher = dir.path().join("cipher.bin");
    fs::write(&plain, b"fake pdf bytes").unwrap();

    sc().arg("-e")
        .arg(&plain)
        .arg("-o")
        .arg(&cipher)
        .args(["-p", "pw"])
        .arg("--name")
        .args(["--kdf", "pbkdf2"])
        .args(["--pbkdf2-iterations", "10000"])
        .assert()
        .success();

    let expected = concat!(
        "format: paladin\n",
        "version: 1\n",
        "cipher: aes-256-gcm\n",
        "kdf: pbkdf2\n",
        "kdf_params: iterations=10000\n",
        "flags: 0x01\n",
        "keyfile_hint: false\n",
        "chunk_size: 65536\n",
        "salt_len: 16\n",
        "nonce_prefix_len: 7\n",
        "name_status: present\n",
        "name: report.pdf\n",
    );
    assert_eq!(info_stdout(&cipher), expected);
}

// ---------------------------------------------------------------------------
// 5 — keyfile hint: flags 0x02, keyfile_hint true, no stored name.
// ---------------------------------------------------------------------------

#[test]
fn info_keyfile_hint() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("cipher.bin");
    let keyfile = dir.path().join("key.bin");
    fs::write(&plain, b"hello keyfile").unwrap();
    fs::write(&keyfile, b"super-secret-key-material").unwrap();

    sc().arg("-e")
        .arg(&plain)
        .arg("-o")
        .arg(&cipher)
        .args(["-p", "pw"])
        .arg("-k")
        .arg(&keyfile)
        .args(["--kdf", "pbkdf2"])
        .args(["--pbkdf2-iterations", "10000"])
        .assert()
        .success();

    let expected = concat!(
        "format: paladin\n",
        "version: 1\n",
        "cipher: aes-256-gcm\n",
        "kdf: pbkdf2\n",
        "kdf_params: iterations=10000\n",
        "flags: 0x02\n",
        "keyfile_hint: true\n",
        "chunk_size: 65536\n",
        "salt_len: 16\n",
        "nonce_prefix_len: 7\n",
        "name_status: absent\n",
        "name: \n",
    );
    assert_eq!(info_stdout(&cipher), expected);
}

// ---------------------------------------------------------------------------
// 6 — armored input is auto-detected; header fields are unchanged by armor.
// ---------------------------------------------------------------------------

#[test]
fn info_armored_input_autodetected() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("cipher.asc");
    fs::write(&plain, b"hello armor").unwrap();

    sc().arg("-e")
        .arg(&plain)
        .arg("-o")
        .arg(&cipher)
        .args(["-p", "pw"])
        .arg("-a")
        .args(["--kdf", "pbkdf2"])
        .args(["--pbkdf2-iterations", "10000"])
        .assert()
        .success();

    // Armor wraps the container but does not alter header metadata: identical
    // to the plain pbkdf2 block.
    let expected = concat!(
        "format: paladin\n",
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
    assert_eq!(info_stdout(&cipher), expected);
}
