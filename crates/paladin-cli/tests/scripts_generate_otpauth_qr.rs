// SPDX-License-Identifier: AGPL-3.0-or-later

//! Behavioral tests for `scripts/generate-otpauth-qr.sh`, the developer
//! helper that renders an `otpauth://` URI as a QR PNG for manually
//! testing the add-account flows.
//!
//! The script prints the URI it encodes on stdout, so `--no-image` runs
//! feed it straight to `paladin_core::parse_otpauth` and
//! `paladin add --uri`. The render and `--copy` plumbing runs against
//! recording stand-ins for `qrencode`, `wl-copy`, and `xclip`, so all of
//! that needs only bash and coreutils. The real PNG round trip needs
//! `qrencode`, which the CI `test` job installs: under GitHub Actions a
//! missing `qrencode` fails that case, and elsewhere it is skipped with a
//! note, like the `xvfb-run` cases in `paladin-gtk/tests/gtk_smoke.rs`.

mod common;

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::SystemTime;

use paladin_core::{parse_otpauth, Account, AccountKindSummary, Algorithm, Store, VaultInit};
use serde_json::{json, Value};
use tempfile::TempDir;

use common::{fresh_vault_path, paladin, test_tempdir};

/// RFC 4226 Appendix D secret (`12345678901234567890`) in base32.
const RFC4226_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .join("scripts/generate-otpauth-qr.sh")
}

fn run_script(args: &[&str]) -> Output {
    Command::new(script_path())
        .args(args)
        .output()
        .expect("spawn scripts/generate-otpauth-qr.sh")
}

/// Run the script, require success, and return the URI line it printed.
fn script_uri(args: &[&str]) -> String {
    let output = run_script(args);
    assert!(
        output.status.success(),
        "script {args:?} failed with {}:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("expected one newline-terminated line, got {stdout:?}"))
        .to_owned()
}

fn parse(uri: &str) -> Account {
    parse_otpauth(uri, SystemTime::now())
        .unwrap_or_else(|err| panic!("parse_otpauth rejected {uri}: {err}"))
        .account
}

/// The raw `secret` query value of `uri`.
fn secret_param(uri: &str) -> &str {
    uri.split_once("secret=")
        .and_then(|(_, rest)| rest.split('&').next())
        .unwrap_or_else(|| panic!("no secret parameter in {uri}"))
}

fn qrencode_available() -> bool {
    Command::new("qrencode")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A `PATH` directory holding only a `bash` symlink: enough to run the
/// script up to its `qrencode` check, which then fails even on hosts
/// (like CI) that have `qrencode` installed.
fn bash_only_path() -> TempDir {
    let dir = test_tempdir();
    let bash = std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|entry| entry.join("bash"))
                .find(|candidate| candidate.is_file())
        })
        .expect("bash on PATH");
    symlink(bash, dir.path().join("bash")).expect("symlink bash");
    dir
}

/// Stand-ins for `qrencode`, `wl-copy`, and `xclip` that record their
/// argv (one per line) and input beside themselves, so the render and
/// `--copy` plumbing runs without the real tools or a display.
fn fake_tools() -> TempDir {
    let dir = test_tempdir();
    let tools = [
        (
            "qrencode",
            r#"printf '%s\n' "${@}" >"${0%/*}/qrencode.args"
for arg in "${@}"; do case "${arg}" in --output=*) out="${arg#--output=}" ;; esac; done
cat >"${out}""#,
        ),
        (
            "wl-copy",
            r#"printf '%s\n' "${@}" >"${0%/*}/wl-copy.args"
cat >"${0%/*}/wl-copy.stdin""#,
        ),
        (
            "xclip",
            r#"printf '%s\n' "${@}" >"${0%/*}/xclip.args"
cat "${@: -1}" >"${0%/*}/xclip.stdin""#,
        ),
    ];
    for (name, body) in tools {
        let path = dir.path().join(name);
        std::fs::write(&path, format!("#!/usr/bin/env bash\nset -eu\n{body}\n"))
            .expect("write fake tool");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake tool");
    }
    dir
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Run `--copy` against [`fake_tools`] with only `display_var` set, check
/// the render step, and return the fakes dir, PNG path, and printed URI.
fn copy_with_fake_tools(display_var: &str) -> (TempDir, PathBuf, String) {
    let fakes = fake_tools();
    let png = fakes.path().join("out").join("qr.png");
    let path_var = format!(
        "{}:{}",
        fakes.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(script_path())
        .args(["--copy", "--out", png.to_str().unwrap()])
        .args(["--secret", RFC4226_SECRET])
        .env("PATH", path_var)
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DISPLAY")
        .env(display_var, "test-display")
        .output()
        .expect("spawn script");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let uri = String::from_utf8(output.stdout)
        .expect("utf-8 stdout")
        .trim_end()
        .to_owned();

    // qrencode gets the URI on stdin, never in argv.
    let output_arg = format!("--output={}", png.display());
    assert_eq!(
        read_lines(&fakes.path().join("qrencode.args")),
        ["--level=M", "--size=8", output_arg.as_str()],
    );
    assert_eq!(std::fs::read_to_string(&png).expect("read PNG"), uri);
    let mode = std::fs::metadata(&png)
        .expect("stat PNG")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "umask must apply before rendering");
    (fakes, png, uri)
}

fn empty_vault() -> (TempDir, PathBuf) {
    let (dir, path) = fresh_vault_path();
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create vault");
    vault.save(&store).expect("save vault");
    (dir, path)
}

fn paladin_json(vault: &Path, args: &[&str]) -> Value {
    let assert = paladin()
        .args(["--json", "--vault", vault.to_str().unwrap()])
        .args(args)
        .assert()
        .success();
    serde_json::from_slice(&assert.get_output().stdout).expect("JSON on stdout")
}

// --- URI construction (`--no-image`) ----------------------------------------

#[test]
fn defaults_build_a_minimal_totp_uri_paladin_accepts() {
    let uri = script_uri(&["--no-image"]);
    let secret = secret_param(&uri);
    assert_eq!(
        uri,
        format!(
            "otpauth://totp/Paladin%20Test:alice%40example.com?secret={secret}\
             &issuer=Paladin%20Test"
        ),
    );

    let validated = parse_otpauth(&uri, SystemTime::now()).expect("parse default URI");
    assert_eq!(validated.warnings, vec![], "a 20-byte secret must not warn");
    let account = validated.account;
    assert_eq!(account.issuer(), Some("Paladin Test"));
    assert_eq!(account.label(), "alice@example.com");
    assert_eq!(account.kind(), AccountKindSummary::Totp);
    assert_eq!(account.algorithm(), Algorithm::Sha1);
    assert_eq!(account.digits(), 6);
    assert_eq!(account.period(), Some(30));
}

#[test]
fn default_secret_is_fresh_unpadded_base32_of_20_bytes() {
    let first = script_uri(&["--no-image"]);
    let second = script_uri(&["--no-image"]);
    let secret = secret_param(&first);
    // 20 bytes encode to exactly 32 base32 characters with no padding.
    assert_eq!(secret.len(), 32, "{first}");
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
        "not RFC 4648 base32: {secret}",
    );
    assert_ne!(secret, secret_param(&second), "secrets must differ per run");
}

#[test]
fn totp_flags_map_onto_uri_parameters() {
    let uri = script_uri(&[
        "--no-image",
        "--issuer",
        "GitHub",
        "--label",
        "octocat",
        "--secret",
        RFC4226_SECRET,
        "--algorithm",
        "SHA256",
        "--digits",
        "8",
        "--period",
        "60",
    ]);
    assert_eq!(
        uri,
        format!(
            "otpauth://totp/GitHub:octocat?secret={RFC4226_SECRET}&issuer=GitHub\
             &algorithm=SHA256&digits=8&period=60"
        ),
    );
    let account = parse(&uri);
    assert_eq!(account.algorithm(), Algorithm::Sha256);
    assert_eq!(account.digits(), 8);
    assert_eq!(account.period(), Some(60));
}

#[test]
fn short_flags_match_long_flags() {
    let long = script_uri(&[
        "--no-image",
        "--type",
        "hotp",
        "--issuer",
        "Acme",
        "--label",
        "al",
        "--secret",
        RFC4226_SECRET,
        "--algorithm",
        "SHA512",
        "--digits",
        "7",
        "--counter",
        "3",
    ]);
    let short = script_uri(&[
        "--no-image",
        "-t",
        "hotp",
        "-i",
        "Acme",
        "-l",
        "al",
        "-s",
        RFC4226_SECRET,
        "-a",
        "SHA512",
        "-d",
        "7",
        "-c",
        "3",
    ]);
    assert_eq!(long, short);
}

#[test]
fn equals_form_flags_split_on_the_first_equals_sign() {
    let account = parse(&script_uri(&[
        "--no-image",
        "--issuer=Acme",
        "--label=al=ice",
    ]));
    assert_eq!(account.issuer(), Some("Acme"));
    assert_eq!(account.label(), "al=ice");
}

#[test]
fn hotp_counter_defaults_to_zero() {
    let uri = script_uri(&["--no-image", "--type", "hotp"]);
    assert!(uri.starts_with("otpauth://hotp/"), "{uri}");
    assert!(uri.ends_with("&counter=0"), "{uri}");
    let account = parse(&uri);
    assert_eq!(account.kind(), AccountKindSummary::Hotp);
    assert_eq!(account.counter(), Some(0));
    assert_eq!(account.period(), None);
}

#[test]
fn hotp_counter_flag_is_carried() {
    let uri = script_uri(&["--no-image", "--type", "hotp", "--counter", "42"]);
    assert!(uri.ends_with("&counter=42"), "{uri}");
    assert_eq!(parse(&uri).counter(), Some(42));
}

#[test]
fn reserved_and_non_ascii_characters_round_trip() {
    // No ':' in the issuer: the parser splits the label on the first one.
    let issuer = "Ünïcødé & Co. 100%+";
    let label = "bob smith+tag@example.com/a?b#c:d=e";
    let uri = script_uri(&["--no-image", "--issuer", issuer, "--label", label]);
    assert!(
        uri.is_ascii() && !uri.contains(' '),
        "not fully encoded: {uri}"
    );
    let account = parse(&uri);
    assert_eq!(account.issuer(), Some(issuer));
    assert_eq!(account.label(), label);
}

#[test]
fn empty_issuer_drops_the_prefix_and_parameter() {
    let uri = script_uri(&["--no-image", "--issuer", "", "--label", "solo"]);
    assert!(uri.starts_with("otpauth://totp/solo?secret="), "{uri}");
    assert!(!uri.contains("issuer="), "{uri}");
    assert_eq!(parse(&uri).issuer(), None);
}

#[test]
fn raw_uri_is_emitted_verbatim_without_validation() {
    for raw in [
        "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme\
         &image=https%3A%2F%2Fexample.com%2Fa.png",
        "otpauth://totp/x?secret=not*base32",
        "not an otpauth uri",
    ] {
        assert_eq!(script_uri(&["--no-image", "--uri", raw]), raw);
    }
}

#[test]
fn usage_errors_exit_2_before_any_output() {
    let cases: &[&[&str]] = &[
        &["--bogus"],
        &["stray-positional"],
        &["--issuer"],
        &["--type", "motp"],
        &["--type", "hotp", "--period", "30"],
        &["--counter", "1"],
        &["--uri", "otpauth://totp/x?secret=GEZDGNBV", "--label", "x"],
        &["--no-image", "--out", "unused.png"],
        &["--no-image", "--copy"],
    ];
    for args in cases {
        let output = run_script(args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.starts_with("error: "), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?} wrote to stdout");
    }
}

#[test]
fn help_prints_the_usage_block_without_the_license_header() {
    let output = run_script(&["--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("utf-8 help");
    assert!(
        text.contains("Usage:") && text.contains("--no-image"),
        "{text}"
    );
    assert!(!text.contains("SPDX") && !text.contains("#!"), "{text}");
}

#[test]
fn copy_without_a_clipboard_tool_fails_before_rendering() {
    let dir = test_tempdir();
    let png = dir.path().join("qr.png");
    let output = Command::new(script_path())
        .args(["--copy", "--out", png.to_str().unwrap()])
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DISPLAY")
        .output()
        .expect("spawn script");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("--copy needs"), "{stderr}");
    assert!(output.stdout.is_empty() && !png.exists());
}

#[test]
fn copy_uses_wl_copy_in_a_wayland_session() {
    let (fakes, _png, uri) = copy_with_fake_tools("WAYLAND_DISPLAY");
    assert_eq!(
        read_lines(&fakes.path().join("wl-copy.args")),
        ["--type", "image/png"],
    );
    let copied = std::fs::read_to_string(fakes.path().join("wl-copy.stdin")).expect("copied");
    assert_eq!(copied, uri);
    assert!(!fakes.path().join("xclip.args").exists());
}

#[test]
fn copy_uses_xclip_in_an_x11_session() {
    let (fakes, png, uri) = copy_with_fake_tools("DISPLAY");
    assert_eq!(
        read_lines(&fakes.path().join("xclip.args")),
        [
            "-selection",
            "clipboard",
            "-target",
            "image/png",
            "-in",
            png.to_str().unwrap(),
        ],
    );
    let copied = std::fs::read_to_string(fakes.path().join("xclip.stdin")).expect("copied");
    assert_eq!(copied, uri);
    assert!(!fakes.path().join("wl-copy.args").exists());
}

// --- End to end through the `paladin` CLI -----------------------------------

#[test]
fn generated_uri_adds_an_account_that_yields_rfc4226_codes() {
    let (_dir, vault) = empty_vault();
    let uri = script_uri(&[
        "--no-image",
        "--type",
        "hotp",
        "--issuer",
        "RFC 4226",
        "--label",
        "appendix-d",
        "--secret",
        RFC4226_SECRET,
        "--counter",
        "1",
    ]);

    let added = paladin_json(&vault, &["add", "--uri", &uri]);
    assert_eq!(added["account"]["issuer"], json!("RFC 4226"));
    assert_eq!(added["account"]["label"], json!("appendix-d"));
    assert_eq!(added["account"]["counter"], json!(1));

    // RFC 4226 Appendix D: HOTP(K, 1) = 287082.
    let peeked = paladin_json(&vault, &["peek", "appendix-d"]);
    assert_eq!(peeked["codes"][0]["code"], json!("287082"));
}

// --- PNG rendering (needs `qrencode`) ----------------------------------------

#[test]
fn png_decodes_to_the_printed_uri_and_adds_via_qr() {
    if !qrencode_available() {
        // Captured output hides skips in CI logs, so fail there instead.
        assert!(
            std::env::var_os("GITHUB_ACTIONS").is_none(),
            "`qrencode` is not on PATH; the `test` job in \
             .github/workflows/ci.yml must install it",
        );
        eprintln!(
            "skipping: `qrencode` is not on PATH. CI installs it; install it \
             locally to exercise the PNG path of scripts/generate-otpauth-qr.sh."
        );
        return;
    }
    let (dir, vault) = empty_vault();
    let png = dir.path().join("nested").join("qr.png");
    let uri = script_uri(&[
        "--out",
        png.to_str().unwrap(),
        "--type",
        "hotp",
        "--issuer",
        "Ünïcødé & Co",
        "--label",
        "png-check",
        "--secret",
        RFC4226_SECRET,
    ]);

    let mode = std::fs::metadata(&png)
        .expect("PNG written")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "PNG carries a secret: {:o}",
        mode & 0o777
    );
    let decoded = paladin_core::import::read_qr_image(&png).expect("decode PNG");
    assert_eq!(decoded, vec![uri]);

    let imported = paladin_json(&vault, &["add", "--qr", png.to_str().unwrap()]);
    assert_eq!(imported["imported"], json!(1));
    assert_eq!(imported["accounts"][0]["issuer"], json!("Ünïcødé & Co"));
    assert_eq!(imported["accounts"][0]["label"], json!("png-check"));

    // RFC 4226 Appendix D: HOTP(K, 0) = 755224.
    let peeked = paladin_json(&vault, &["peek", "png-check"]);
    assert_eq!(peeked["codes"][0]["code"], json!("755224"));
}

#[test]
fn missing_qrencode_is_reported_with_an_install_hint() {
    let bin = bash_only_path();
    let png = bin.path().join("qr.png");
    // `--secret` skips random_secret, whose coreutils are not on this PATH.
    let output = Command::new(script_path())
        .args(["--secret", RFC4226_SECRET, "--out", png.to_str().unwrap()])
        .env("PATH", bin.path())
        .output()
        .expect("spawn script");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("dnf install qrencode") && stderr.contains("--no-image"),
        "{stderr}",
    );
    assert!(output.stdout.is_empty() && !png.exists());
}
