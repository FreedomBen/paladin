//! `assert_cmd` integration tests for previously-untested CLI flag behaviors
//! of the `symcrypt` binary (DESIGN §6): decrypt + `--remove`, quiet mode not
//! suppressing primary `--info` stdout, and the positive content of verbose
//! (`-v`) diagnostics on stderr.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn sc() -> Command {
    Command::cargo_bin("symcrypt").unwrap()
}

const FAST_KDF: [&str; 4] = ["--kdf", "pbkdf2", "--pbkdf2-iterations", "10000"];

/// `--remove` on decrypt deletes the container once the plaintext is written.
#[test]
fn decrypt_remove_deletes_container_after_success() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.txt");
    let plaintext = b"plaintext to round-trip";
    fs::write(&input, plaintext).unwrap();
    let cipher = dir.path().join("c.bin");
    sc().arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();

    let out = dir.path().join("out.txt");
    sc().arg("-d")
        .arg(&cipher)
        .args(["-p", "pw", "--remove"])
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    assert!(out.exists(), "decrypt must write the plaintext output");
    assert_eq!(
        fs::read(&out).unwrap(),
        plaintext,
        "decrypted bytes must match the original plaintext"
    );
    assert!(
        !cipher.exists(),
        "decrypt --remove should delete the container input"
    );
}

/// Quiet mode silences chatter but must not suppress primary `--info` stdout.
#[test]
fn quiet_does_not_suppress_info_stdout() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("c.bin");
    fs::write(&plain, b"hello quiet info").unwrap();
    sc().arg("-e")
        .arg(&plain)
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();

    let assert = sc().arg("-i").arg(&cipher).arg("-q").assert().success();
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

/// Verbose (`-v`) emits the encrypt diagnostic lines on stderr.
#[test]
fn verbose_encrypt_emits_diagnostics_on_stderr() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.txt");
    fs::write(&input, b"diagnostic payload").unwrap();
    let out = dir.path().join("c.bin");
    let assert = sc()
        .arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", "pw", "-v"])
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    for needle in ["encrypt", "->", "cipher=", "kdf=", "wrote"] {
        assert!(
            stderr.contains(needle),
            "verbose stderr must contain `{needle}`:\n{stderr}"
        );
    }
}
