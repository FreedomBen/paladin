//! Integration tests for the `symcrypt` CLI binary.
//!
//! Each test runs in its own `TempDir` and uses a fast PBKDF2 KDF on encrypt to
//! keep the suite quick. Decrypt/verify/info read the KDF from the header, so
//! they never receive KDF flags.

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

/// 1. Encrypt a file then decrypt it; the round trip must reproduce the bytes.
#[test]
fn binary_round_trip_reproduces_plaintext() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"hello world\nwith a newline and bytes \x00\x01\x02";
    fs::write(p(dir, "plain.txt"), plain).unwrap();

    sc().args([
        "-e",
        &p(dir, "plain.txt"),
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

    sc().args(["-d", &p(dir, "c.bin"), "-p", "pw", "-o", &p(dir, "out.txt")])
        .assert()
        .success();

    assert_eq!(fs::read(p(dir, "out.txt")).unwrap(), plain);
}

/// 2. Encrypt with no `-o` appends `.symcrypt` beside the input.
#[test]
fn default_encrypt_extension_is_symcrypt() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "report.pdf"), b"pdf-bytes").unwrap();

    sc().args([
        "-e",
        &p(dir, "report.pdf"),
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
    ])
    .assert()
    .success();

    assert!(dir.join("report.pdf.symcrypt").exists());
}

/// 3. Encrypt with `-a` appends `.symcrypt.asc` beside the input.
#[test]
fn default_armored_extension_is_symcrypt_asc() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "report.pdf"), b"pdf-bytes").unwrap();

    sc().args([
        "-e",
        &p(dir, "report.pdf"),
        "-a",
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
    ])
    .assert()
    .success();

    assert!(dir.join("report.pdf.symcrypt.asc").exists());
}

/// 4. Armored encrypt then decrypt to stdout; armor is auto-detected.
#[test]
fn armor_round_trip_to_stdout() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"armored payload\n\xff\xfe";
    fs::write(p(dir, "in.dat"), plain).unwrap();

    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-a",
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "c.asc"),
    ])
    .assert()
    .success();

    let out = sc()
        .args(["-d", &p(dir, "c.asc"), "-p", "pw", "-o", "-"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(out, plain);
}

/// 5. Encrypt to stdout, persist the captured bytes, then decrypt that file.
#[test]
fn stdout_encrypt_then_file_decrypt() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"stream me to stdout";
    fs::write(p(dir, "in.dat"), plain).unwrap();

    let cipher = sc()
        .args([
            "-e",
            &p(dir, "in.dat"),
            "-p",
            "pw",
            "--kdf",
            "pbkdf2",
            "--pbkdf2-iterations",
            "10000",
            "-o",
            "-",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    fs::write(p(dir, "c.bin"), &cipher).unwrap();

    sc().args(["-d", &p(dir, "c.bin"), "-p", "pw", "-o", &p(dir, "out.dat")])
        .assert()
        .success();

    assert_eq!(fs::read(p(dir, "out.dat")).unwrap(), plain);
}

/// 6. Decrypt restores the stored `--name` beside the cipher when no `-o` given.
#[test]
fn decrypt_uses_stored_name() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"named restore";
    fs::write(p(dir, "orig.txt"), plain).unwrap();
    fs::create_dir(dir.join("box")).unwrap();

    sc().args([
        "-e",
        &p(dir, "orig.txt"),
        "--name",
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "box/cipher"),
    ])
    .assert()
    .success();

    sc().args(["-d", &p(dir, "box/cipher"), "-p", "pw"])
        .assert()
        .success();

    let restored = dir.join("box").join("orig.txt");
    assert!(restored.exists());
    assert_eq!(fs::read(restored).unwrap(), plain);
}

/// 7. Decrypt strips a recognized `.symcrypt` extension when no `-o` given.
#[test]
fn decrypt_strips_known_extension() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"strip my extension";
    fs::write(p(dir, "orig"), plain).unwrap();
    fs::create_dir(dir.join("s")).unwrap();

    sc().args([
        "-e",
        &p(dir, "orig"),
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "s/payload.symcrypt"),
    ])
    .assert()
    .success();

    sc().args(["-d", &p(dir, "s/payload.symcrypt"), "-p", "pw"])
        .assert()
        .success();

    let restored = dir.join("s").join("payload");
    assert!(restored.exists());
    assert_eq!(fs::read(restored).unwrap(), plain);
}

/// 8. Decrypt appends `.dec` when the input has no recognized extension.
#[test]
fn decrypt_dec_fallback_for_unknown_extension() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"no recognizable suffix";
    fs::write(p(dir, "orig"), plain).unwrap();
    fs::create_dir(dir.join("s")).unwrap();

    sc().args([
        "-e",
        &p(dir, "orig"),
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "s/blob"),
    ])
    .assert()
    .success();

    sc().args(["-d", &p(dir, "s/blob"), "-p", "pw"])
        .assert()
        .success();

    let restored = dir.join("s").join("blob.dec");
    assert!(restored.exists());
    assert_eq!(fs::read(restored).unwrap(), plain);
}

/// 9. Decrypt of a file named exactly `.symcrypt` falls back to `.symcrypt.dec`.
#[test]
fn decrypt_empty_basename_fallback() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let plain = b"empty basename case";
    fs::write(p(dir, "orig"), plain).unwrap();
    fs::create_dir(dir.join("s")).unwrap();

    sc().args([
        "-e",
        &p(dir, "orig"),
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "s/.symcrypt"),
    ])
    .assert()
    .success();

    sc().args(["-d", &p(dir, "s/.symcrypt"), "-p", "pw"])
        .assert()
        .success();

    let restored = dir.join("s").join(".symcrypt.dec");
    assert!(restored.exists());
    assert_eq!(fs::read(restored).unwrap(), plain);
}

/// 10. Encrypting from stdin without `-o` is a usage error (exit 2).
#[test]
fn stdin_encrypt_requires_output() {
    sc().args([
        "-e",
        "-",
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
    ])
    .write_stdin("data")
    .assert()
    .code(2);
}

/// 11. Decrypting from stdin without `-o` is a usage error (exit 2).
#[test]
fn stdin_decrypt_requires_output() {
    sc().args(["-d", "-", "-p", "pw"])
        .write_stdin("whatever")
        .assert()
        .code(2);
}

/// 12. Refuse to clobber an existing output without `-f`; succeed with `-f`.
#[test]
fn clobber_refused_without_force() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    fs::write(p(dir, "in.dat"), b"clobber test").unwrap();
    fs::write(p(dir, "existing"), b"do not overwrite me").unwrap();

    // Without -f the existing output must not be overwritten.
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
        &p(dir, "existing"),
    ])
    .assert()
    .code(2);

    // With -f the encrypt succeeds.
    sc().args([
        "-e",
        &p(dir, "in.dat"),
        "-f",
        "-p",
        "pw",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-iterations",
        "10000",
        "-o",
        &p(dir, "existing"),
    ])
    .assert()
    .success();
}
