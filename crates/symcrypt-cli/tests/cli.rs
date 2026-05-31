//! `assert_cmd` integration tests for the `symcrypt` binary (DESIGN §6, plan §8).

use assert_cmd::Command;

/// A fresh `Command` for the `symcrypt` binary under test.
fn sc() -> Command {
    Command::cargo_bin("symcrypt").unwrap()
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
