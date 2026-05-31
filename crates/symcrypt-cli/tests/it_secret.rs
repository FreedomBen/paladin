//! Integration tests for the `symcrypt` CLI's password/keyfile sources
//! (DESIGN §6.4).
//!
//! Each test runs in its own `TempDir` and uses a fast PBKDF2 KDF on encrypt to
//! keep the suite quick. Decrypt reads the KDF from the header, so it never
//! receives KDF flags. Exactly one password source is permitted per invocation;
//! a keyfile may be combined with any password source (including `--no-password`).

use assert_cmd::Command;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Build a fresh invocation of the `symcrypt` binary under test.
fn sc() -> Command {
    Command::cargo_bin("symcrypt").unwrap()
}

/// Convenience: absolute path string for a child of `dir`.
fn p(dir: &Path, name: &str) -> String {
    dir.join(name).to_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Round trips: encrypt then decrypt with the SAME source recovers plaintext.
// ---------------------------------------------------------------------------

/// 1. Inline `-p` password round-trips.
#[test]
fn inline_password_round_trip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"inline password payload";
    fs::write(p(dir, "in.dat"), plain).unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .success();

    sc().args(["-d", &p(dir, "c.bin"), "-p", "pw", "-o", &p(dir, "out.dat")])
        .assert()
        .success();

    assert_eq!(fs::read(p(dir, "out.dat")).unwrap(), plain);
}

/// 2. `--password-file` round-trips; the single trailing newline is trimmed on
///    both encrypt and decrypt so the effective password matches.
#[test]
fn password_file_round_trip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"password file payload";
    fs::write(p(dir, "in.dat"), plain).unwrap();
    fs::write(p(dir, "pw.txt"), b"filepw\n").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "--password-file",
        &p(dir, "pw.txt"),
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .success();

    sc().args([
        "-d",
        &p(dir, "c.bin"),
        "--password-file",
        &p(dir, "pw.txt"),
        "-o",
        &p(dir, "out.dat"),
    ])
    .assert()
    .success();

    assert_eq!(fs::read(p(dir, "out.dat")).unwrap(), plain);
}

/// 3. `--password-env` round-trips; the env var is set on both commands.
#[test]
fn password_env_round_trip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"env password payload";
    fs::write(p(dir, "in.dat"), plain).unwrap();

    sc().env("SYMCRYPT_TPW", "envpw")
        .args([
            "-e",
            &p(dir, "in.dat"),
            "--password-env",
            "SYMCRYPT_TPW",
            "--kdf",
            "pbkdf2",
            "--pbkdf2-iterations",
            "10000",
            "-o",
            &p(dir, "c.bin"),
        ])
        .assert()
        .success();

    sc().env("SYMCRYPT_TPW", "envpw")
        .args([
            "-d",
            &p(dir, "c.bin"),
            "--password-env",
            "SYMCRYPT_TPW",
            "-o",
            &p(dir, "out.dat"),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(p(dir, "out.dat")).unwrap(), plain);
}

/// 4. `--no-password` combined with a keyfile round-trips.
#[test]
fn no_password_with_keyfile_round_trip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"keyfile-only payload";
    fs::write(p(dir, "in.dat"), plain).unwrap();
    fs::write(p(dir, "key"), b"keyfile-secret-bytes").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "--no-password",
        "-k",
        &p(dir, "key"),
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .success();

    sc().args([
        "-d",
        &p(dir, "c.bin"),
        "--no-password",
        "-k",
        &p(dir, "key"),
        "-o",
        &p(dir, "out.dat"),
    ])
    .assert()
    .success();

    assert_eq!(fs::read(p(dir, "out.dat")).unwrap(), plain);
}

/// 5. A password combined with a keyfile round-trips.
#[test]
fn password_with_keyfile_round_trip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"password plus keyfile payload";
    fs::write(p(dir, "in.dat"), plain).unwrap();
    fs::write(p(dir, "key"), b"another-keyfile-secret").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-p",
        "pw",
        "-k",
        &p(dir, "key"),
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .success();

    sc().args([
        "-d",
        &p(dir, "c.bin"),
        "-p",
        "pw",
        "-k",
        &p(dir, "key"),
        "-o",
        &p(dir, "out.dat"),
    ])
    .assert()
    .success();

    assert_eq!(fs::read(p(dir, "out.dat")).unwrap(), plain);
}

// ---------------------------------------------------------------------------
// Authentication failures (exit 3): correct format, wrong secret.
// ---------------------------------------------------------------------------

/// 6. Decrypting with the wrong inline password is an auth failure.
#[test]
fn wrong_password_is_auth_failure() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"secret data").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-p",
        "right",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .success();

    sc().args([
        "-d",
        &p(dir, "c.bin"),
        "-p",
        "wrong",
        "-o",
        &p(dir, "out.dat"),
    ])
    .assert()
    .code(3);
}

/// 7. Decrypting with a different keyfile is an auth failure.
#[test]
fn wrong_keyfile_is_auth_failure() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"secret data").unwrap();
    fs::write(p(dir, "key1"), b"keyfile-one-bytes").unwrap();
    fs::write(p(dir, "key2"), b"keyfile-two-different").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-p",
        "pw",
        "-k",
        &p(dir, "key1"),
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .success();

    sc().args([
        "-d",
        &p(dir, "c.bin"),
        "-p",
        "pw",
        "-k",
        &p(dir, "key2"),
        "-o",
        &p(dir, "out.dat"),
    ])
    .assert()
    .code(3);
}

// ---------------------------------------------------------------------------
// Usage errors (exit 2): malformed or disallowed password-source combinations.
// ---------------------------------------------------------------------------

/// 8. An empty inline password is rejected as a usage error.
#[test]
fn empty_inline_password_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"data").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-p",
        "",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .code(2);
}

/// 9. An empty password file (no keyfile) is rejected as a usage error.
#[test]
fn empty_password_file_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"data").unwrap();
    fs::write(p(dir, "empty.txt"), b"").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "--password-file",
        &p(dir, "empty.txt"),
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .code(2);
}

/// 10. A set-but-empty env var (no keyfile) is rejected as a usage error.
#[test]
fn empty_password_env_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"data").unwrap();

    sc().env("SYMCRYPT_EPW", "")
        .args([
            "-e",
            &p(dir, "in.dat"),
            "--password-env",
            "SYMCRYPT_EPW",
            "--kdf",
            "pbkdf2",
            "--pbkdf2-iterations",
            "10000",
            "-o",
            &p(dir, "c.bin"),
        ])
        .assert()
        .code(2);
}

/// 11. `--no-password` without a keyfile is a usage error.
#[test]
fn no_password_without_keyfile_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"data").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "--no-password",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .code(2);
}

/// 12. `--password-file -` is a usage error: stdin is reserved.
#[test]
fn password_file_dash_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"data").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "--password-file",
        "-",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .code(2);
}

/// 13. `-k -` is a usage error: stdin is reserved.
#[test]
fn keyfile_dash_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"data").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-p",
        "pw",
        "-k",
        "-",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .code(2);
}

/// 14. A zero-byte keyfile is a usage error (keyfiles must be 1 byte..=1 MiB).
#[test]
fn zero_byte_keyfile_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"data").unwrap();
    fs::write(p(dir, "empty.key"), b"").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-p",
        "pw",
        "-k",
        &p(dir, "empty.key"),
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .code(2);
}

/// 15. Two password sources at once is a usage error.
#[test]
fn two_password_sources_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"data").unwrap();
    fs::write(p(dir, "pw.txt"), b"filepw\n").unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-p",
        "pw",
        "--password-file",
        &p(dir, "pw.txt"),
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.bin"),
    ])
    .assert()
    .code(2);
}
