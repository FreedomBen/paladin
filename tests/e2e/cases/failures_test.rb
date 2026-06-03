# frozen_string_literal: true
#
# End-to-end exit-code matrix for the symcrypt CLI. Each failure class must map
# to the documented exit code (DESIGN + symcrypt-common/src/error.rs):
#
#   0 ok · 1 general/IO · 2 usage · 3 auth failure · 4 unsupported format · 130 cancel
#
# Security-relevant properties under test:
#   * A wrong password and a corrupted/tampered/truncated file are
#     cryptographically indistinguishable under AEAD, so they MUST be reported
#     identically (exit 3, same message) — no oracle that leaks the cause.
#   * An unknown format/version MUST be rejected (exit 4), never guessed at.

require "test_helper"

class FailuresTest < E2ETest
  AUTH_MSG = "authentication failed: wrong password or corrupted/tampered file"

  # ---- exit 3: authentication failures are indistinguishable ----------------

  def test_auth_failures_are_indistinguishable
    env = { "PW" => DEFAULT_PASSWORD }

    wrong_pw = symcrypt("--decrypt", good_cipher("a.symcrypt"), "--output", tmp("o1"),
                        "--password-env", "PW", env: { "PW" => "wrong-password" })

    tampered_file = good_cipher("b.symcrypt")
    flip_byte(tampered_file, File.size(tampered_file) - 1) # last byte = final AEAD tag
    tampered = symcrypt("--decrypt", tampered_file, "--output", tmp("o2"),
                        "--password-env", "PW", env: env)

    truncated_file = good_cipher("c.symcrypt")
    truncate_input(truncated_file, 10)
    truncated = symcrypt("--decrypt", truncated_file, "--output", tmp("o3"),
                         "--password-env", "PW", env: env)

    results = { wrong_pw: wrong_pw, tampered: tampered, truncated: truncated }
    results.each do |cause, r|
      assert_status r, 3, "#{cause} should be an auth failure"
      assert_includes r.stderr, AUTH_MSG, "#{cause} should report the auth message"
    end

    # The crux: the three distinct causes are reported identically.
    assert_equal wrong_pw.stderr.strip, tampered.stderr.strip,
                 "wrong-password and a tampered file must be indistinguishable"
    assert_equal wrong_pw.stderr.strip, truncated.stderr.strip,
                 "wrong-password and a truncated file must be indistinguishable"
  end

  def test_verify_reports_auth_failure
    good = good_cipher

    bad = symcrypt("--verify", good, "--password-env", "PW",
                   env: { "PW" => "wrong-password" })
    assert_failure bad, 3, AUTH_MSG

    ok = symcrypt("--verify", good, "--password-env", "PW",
                  env: { "PW" => DEFAULT_PASSWORD })
    assert_status ok, 0, "control: --verify with the correct password should succeed"
  end

  # ---- exit 4: unsupported / unrecognized format ----------------------------

  def test_not_a_symcrypt_file_is_rejected
    junk = write_input("junk.bin", "this is not a symcrypt container, just text")

    dec = symcrypt("--decrypt", junk, "--output", tmp("o"),
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure dec, 4, "not a symcrypt file (bad magic)"

    # --info needs no password and must also reject it.
    assert_failure symcrypt("--info", junk), 4, "not a symcrypt file (bad magic)"
  end

  def test_unsupported_version_is_rejected
    f = good_cipher("badver.symcrypt")
    flip_byte(f, 8) # version byte, immediately after the 8-byte magic

    dec = symcrypt("--decrypt", f, "--output", tmp("o"),
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure dec, 4, "unsupported symcrypt version"

    # Version is checked first, so even --info (no password) rejects it.
    assert_failure symcrypt("--info", f), 4, "unsupported symcrypt version"
  end

  # ---- exit 2: refuse-to-overwrite, missing input, usage / bad options ------

  def test_refuse_to_overwrite_without_force
    target = good_cipher("keep.symcrypt")
    before = File.binread(target)
    src    = write_input("plain.txt", "different content\n")
    env    = { "PW" => DEFAULT_PASSWORD }

    refused = symcrypt("--encrypt", src, "--output", target, *FAST_KDF,
                       "--password-env", "PW", env: env)
    assert_failure refused, 2, "already exists"
    assert_equal before, File.binread(target), "a refused encrypt must not touch the existing file"

    forced = symcrypt("--encrypt", src, "--output", target, "--force", *FAST_KDF,
                      "--password-env", "PW", env: env)
    assert_status forced, 0, "--force should overwrite"
    refute_equal before, File.binread(target), "--force should have rewritten the file"
  end

  def test_missing_input_file_is_usage_error
    res = symcrypt("--decrypt", tmp("does-not-exist.symcrypt"), "--output", tmp("o"),
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 2, "cannot use"
  end

  def test_usage_and_option_errors_exit_2
    src = write_input("u.txt", "x")
    env = { "PW" => DEFAULT_PASSWORD }

    # No mode selected (clap: required group).
    assert_status symcrypt(src, "--password-env", "PW", env: env), 2, "no mode should be usage error"
    # Mutually exclusive modes (clap: conflict).
    assert_status symcrypt("--encrypt", "--decrypt", src, "-p", "x"), 2, "-e and -d conflict"
    # Missing FILE argument (clap: required arg).
    assert_status symcrypt("--encrypt", "-p", "x"), 2, "missing FILE should be usage error"
    # App-level validation: empty password needs a keyfile.
    assert_failure symcrypt("--encrypt", src, "--output", tmp("o"), "--no-password"),
                   2, "--no-password requires a keyfile"
    # App-level validation: KDF cost out of range.
    range = symcrypt("--encrypt", src, "--output", tmp("o2"),
                     "--kdf", "pbkdf2", "--pbkdf2-iterations", "1",
                     "--password-env", "PW", env: env)
    assert_failure range, 2, "out of range"
  end

  private

  # Produce a valid encrypted container in the temp dir; returns its path. The
  # payload is comfortably larger than the header so truncation lands in the body.
  def good_cipher(name = "good.symcrypt", plaintext: ("symcrypt e2e payload " * 16))
    src    = write_input("src-#{name}.txt", plaintext)
    cipher = tmp(name)
    res = symcrypt("--encrypt", src, "--output", cipher, *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status res, 0, "good_cipher setup failed: #{res.stderr}"
    cipher
  end

  def assert_failure(result, code, substr)
    assert_status result, code
    assert_includes result.stderr, substr,
                    "expected stderr to include #{substr.inspect}\nstderr: #{result.stderr}"
  end
end
