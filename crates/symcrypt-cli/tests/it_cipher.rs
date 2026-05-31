//! End-to-end CLI coverage for the non-default cipher `chacha20-poly1305`.
//!
//! The default round-trip tests only exercise AES-256-GCM; these mirror that
//! coverage for the selectable ChaCha20-Poly1305 cipher (`-c chacha20-poly1305`):
//! a binary round trip, the byte-exact `--info` block, and an armored round trip.
//! Each test runs in its own `TempDir` with a fast PBKDF2 KDF on encrypt; decrypt
//! and info read the cipher/KDF from the header, so they never receive `-c`/KDF flags.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn sc() -> Command {
    Command::cargo_bin("symcrypt").unwrap()
}

const FAST_KDF: [&str; 4] = ["--kdf", "pbkdf2", "--pbkdf2-iterations", "10000"];

/// Encrypt with `-c chacha20-poly1305`, then decrypt; the round trip must
/// reproduce the original bytes (decrypt reads the cipher from the header).
#[test]
fn chacha20_poly1305_round_trip_reproduces_plaintext() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let input = dir.join("plain.bin");
    let cipher = dir.join("c.bin");
    let out = dir.join("out.bin");
    let plain = b"chacha payload\n\x00\x01\xff";
    fs::write(&input, plain).unwrap();

    sc().arg("-e")
        .arg(&input)
        .args(["-c", "chacha20-poly1305"])
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();

    sc().arg("-d")
        .arg(&cipher)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    assert_eq!(fs::read(&out).unwrap(), plain);
}

/// `--info` on a ChaCha20-Poly1305 container reports `cipher: chacha20-poly1305`
/// and otherwise matches the byte-exact metadata block.
#[test]
fn chacha20_info_reports_cipher() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let input = dir.join("plain.txt");
    let cipher = dir.join("c.bin");
    fs::write(&input, b"hello chacha").unwrap();

    sc().arg("-e")
        .arg(&input)
        .args(["-c", "chacha20-poly1305"])
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();

    let assert = sc().arg("-i").arg(&cipher).assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    let expected = concat!(
        "format: symcrypt\n",
        "version: 1\n",
        "cipher: chacha20-poly1305\n",
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

/// Armored ChaCha20-Poly1305 round trip: encrypt with `-a`, then decrypt to
/// stdout (armor auto-detected); stdout must equal the original plaintext.
#[test]
fn chacha20_armored_round_trip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let input = dir.join("in.dat");
    let cipher = dir.join("c.asc");
    let plain = b"armored chacha\n\xff\xfe\x00";
    fs::write(&input, plain).unwrap();

    sc().arg("-e")
        .arg(&input)
        .args(["-c", "chacha20-poly1305"])
        .arg("-a")
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();

    let out = sc()
        .arg("-d")
        .arg(&cipher)
        .args(["-p", "pw"])
        .arg("-o")
        .arg("-")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(out, plain);
}
