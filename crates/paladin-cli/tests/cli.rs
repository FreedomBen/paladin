//! `assert_cmd` integration tests for the `paladin` binary (DESIGN §6, plan §8).

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A fresh `Command` for the `paladin` binary under test.
fn sc() -> Command {
    Command::cargo_bin("paladin").unwrap()
}

/// Fast, valid KDF flags so encryption fixtures stay cheap.
const FAST_KDF: [&str; 4] = ["--kdf", "pbkdf2", "--pbkdf2-iterations", "10000"];

/// Encrypt `plaintext` to a binary (un-armored) container and return its path.
fn encrypt_fixture(dir: &Path, plaintext: &[u8]) -> PathBuf {
    let input = dir.join("plain.bin");
    fs::write(&input, plaintext).unwrap();
    let cipher = dir.join("cipher.bin");
    sc().arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();
    cipher
}

/// Write `bytes` with the byte at `offset` set to `value`, returning the path.
fn write_with_byte(
    dir: &Path,
    name: &str,
    mut bytes: Vec<u8>,
    offset: usize,
    value: u8,
) -> PathBuf {
    bytes[offset] = value;
    let path = dir.join(name);
    fs::write(&path, &bytes).unwrap();
    path
}

// ---------------------------------------------------------------------------
// Step 1 — wiring & skeleton: --version / --help.
// ---------------------------------------------------------------------------

#[test]
fn version_succeeds() {
    sc().arg("--version").assert().success();
}

#[test]
fn help_succeeds() {
    sc().arg("--help").assert().success();
}

#[test]
fn help_lists_every_documented_flag() {
    let assert = sc().arg("--help").assert().success();
    let text = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    for flag in [
        "--encrypt",
        "--decrypt",
        "--info",
        "--verify",
        "--output",
        "--password",
        "--password-file",
        "--password-env",
        "--no-password",
        "--keyfile",
        "--cipher",
        "--kdf",
        "--argon2-memory",
        "--argon2-time",
        "--argon2-parallelism",
        "--scrypt-log-n",
        "--scrypt-r",
        "--scrypt-p",
        "--pbkdf2-iterations",
        "--armor",
        "--name",
        "--force",
        "--remove",
        "--progress",
        "--no-progress",
        "--verbose",
        "--quiet",
    ] {
        assert!(text.contains(flag), "--help is missing `{flag}`:\n{text}");
    }
}

// ---------------------------------------------------------------------------
// Step 2 — arg model: required mode group + positional <FILE>.
// ---------------------------------------------------------------------------

#[test]
fn missing_mode_is_usage_error() {
    sc().arg("somefile").assert().code(2);
}

#[test]
fn two_modes_is_usage_error() {
    sc().args(["-e", "-d", "somefile"]).assert().code(2);
}

#[test]
fn missing_file_is_usage_error() {
    sc().arg("-e").assert().code(2);
}

// ---------------------------------------------------------------------------
// Step 8 — crafted-header rejection (exit 4) at the offsets from DESIGN §5.2:
// version@8, cipher_id@9, kdf_id@10, flags@11.
// ---------------------------------------------------------------------------

#[test]
fn unsupported_version_is_format_error() {
    let dir = TempDir::new().unwrap();
    let bytes = fs::read(encrypt_fixture(dir.path(), b"data")).unwrap();
    let t = write_with_byte(dir.path(), "t.bin", bytes, 8, 0xFF);
    sc().arg("-i").arg(&t).assert().code(4);
}

#[test]
fn unknown_cipher_id_is_format_error() {
    let dir = TempDir::new().unwrap();
    let bytes = fs::read(encrypt_fixture(dir.path(), b"data")).unwrap();
    let t = write_with_byte(dir.path(), "t.bin", bytes, 9, 0xFF);
    sc().arg("-i").arg(&t).assert().code(4);
}

#[test]
fn unknown_kdf_id_is_format_error() {
    let dir = TempDir::new().unwrap();
    let bytes = fs::read(encrypt_fixture(dir.path(), b"data")).unwrap();
    let t = write_with_byte(dir.path(), "t.bin", bytes, 10, 0xFF);
    sc().arg("-i").arg(&t).assert().code(4);
}

#[test]
fn reserved_flags_bit_is_format_error() {
    let dir = TempDir::new().unwrap();
    let mut bytes = fs::read(encrypt_fixture(dir.path(), b"data")).unwrap();
    bytes[11] |= 0x04; // a reserved flags bit (bits 2..=7 must be 0)
    let t = dir.path().join("t.bin");
    fs::write(&t, &bytes).unwrap();
    sc().arg("-i").arg(&t).assert().code(4);
}

#[test]
fn bad_magic_is_format_error() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("not-paladin");
    fs::write(&f, b"this is plainly not a paladin container").unwrap();
    sc().arg("-i").arg(&f).assert().code(4);
}

// ---------------------------------------------------------------------------
// Step 8 — verify mode exit codes.
// ---------------------------------------------------------------------------

#[test]
fn verify_accepts_correct_password() {
    let dir = TempDir::new().unwrap();
    let cipher = encrypt_fixture(dir.path(), b"verify me");
    sc().arg("--verify")
        .arg(&cipher)
        .args(["-p", "pw"])
        .assert()
        .success();
}

#[test]
fn verify_rejects_wrong_password() {
    let dir = TempDir::new().unwrap();
    let cipher = encrypt_fixture(dir.path(), b"verify me");
    sc().arg("--verify")
        .arg(&cipher)
        .args(["-p", "wrong"])
        .assert()
        .code(3);
}

#[test]
fn verify_rejects_tampered_body() {
    let dir = TempDir::new().unwrap();
    let mut bytes = fs::read(encrypt_fixture(dir.path(), b"verify me")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01; // corrupt the final auth tag
    let t = dir.path().join("t.bin");
    fs::write(&t, &bytes).unwrap();
    sc().arg("--verify")
        .arg(&t)
        .args(["-p", "pw"])
        .assert()
        .code(3);
}

// ---------------------------------------------------------------------------
// Step 6 — finalization, --remove, same-file, directory, modes, conflicts.
// ---------------------------------------------------------------------------

#[test]
fn remove_deletes_input_after_success() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.txt");
    fs::write(&input, b"bye").unwrap();
    let out = dir.path().join("c.bin");
    sc().arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", "pw", "--remove"])
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    assert!(!input.exists(), "--remove should delete the input");
    assert!(out.exists());
}

#[test]
fn remove_with_stdin_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("c.bin");
    sc().arg("-e")
        .arg("-")
        .args(FAST_KDF)
        .args(["-p", "pw", "--remove"])
        .arg("-o")
        .arg(&out)
        .write_stdin("data")
        .assert()
        .code(2);
}

#[test]
fn output_equal_to_input_is_refused() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("data");
    fs::write(&f, b"x").unwrap();
    // -f permits clobber, isolating the same-file refusal.
    sc().arg("-e")
        .arg(&f)
        .args(FAST_KDF)
        .args(["-p", "pw", "-f"])
        .arg("-o")
        .arg(&f)
        .assert()
        .code(2);
}

#[test]
fn directory_input_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("adir");
    fs::create_dir(&sub).unwrap();
    let out = dir.path().join("c.bin");
    sc().arg("-e")
        .arg(&sub)
        .args(FAST_KDF)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&out)
        .assert()
        .code(2);
}

#[test]
fn failed_decrypt_leaves_no_output() {
    let dir = TempDir::new().unwrap();
    let bad = dir.path().join("bad");
    fs::write(&bad, b"not a paladin file").unwrap();
    let out = dir.path().join("out");
    sc().arg("-d")
        .arg(&bad)
        .args(["-p", "pw"])
        .arg("-o")
        .arg(&out)
        .assert()
        .code(4);
    assert!(
        !out.exists(),
        "the temp output must be cleaned up on failure"
    );
}

#[test]
fn quiet_and_verbose_conflict_is_usage_error() {
    sc().arg("-e")
        .arg("anyfile")
        .args(FAST_KDF)
        .args(["-p", "pw", "-q", "-v"])
        .assert()
        .code(2);
}

#[test]
fn progress_and_quiet_conflict_is_usage_error() {
    sc().arg("-e")
        .arg("anyfile")
        .args(FAST_KDF)
        .args(["-p", "pw", "--progress", "-q"])
        .assert()
        .code(2);
}

#[cfg(unix)]
#[test]
fn encrypt_output_is_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let cipher = encrypt_fixture(dir.path(), b"data");
    let mode = fs::metadata(&cipher).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[test]
fn remove_failure_warns_but_succeeds() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let rodir = dir.path().join("ro");
    fs::create_dir(&rodir).unwrap();
    let input = rodir.join("in");
    fs::write(&input, b"data").unwrap();
    let out = dir.path().join("out.bin"); // outside the read-only dir
                                          // Read-only parent dir: reading `in` is fine, unlinking it fails.
    fs::set_permissions(&rodir, fs::Permissions::from_mode(0o500)).unwrap();
    sc().arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", "pw", "--remove"])
        .arg("-o")
        .arg(&out)
        .assert()
        .success(); // deletion failure is a warning, not an error
    fs::set_permissions(&rodir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(out.exists(), "output must be finalized");
    assert!(input.exists(), "input survives a failed --remove");
}

#[test]
fn verbose_output_does_not_leak_the_password() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.txt");
    fs::write(&input, b"top secret data").unwrap();
    let out = dir.path().join("c.bin");
    let secret = "SUPERSECRETPW12345";
    let assert = sc()
        .arg("-e")
        .arg(&input)
        .args(FAST_KDF)
        .args(["-p", secret, "-v"])
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        !stderr.contains(secret),
        "verbose stderr must never contain the password:\n{stderr}"
    );
}
