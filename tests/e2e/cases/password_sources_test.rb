# frozen_string_literal: true
#
# Password sources (DESIGN §6.4): `-p/--password` inline, `--password-file`, and
# `--password-env`. The secret is what matters, not how it was supplied, so the
# sources interoperate. Exactly one source may be given; a misconfigured source
# is a usage error (exit 2) and never silently downgrades the password.
#
# This is the black-box complement to the in-process it_secret.rs tests: it
# exercises real environment variables and real on-disk password files.

require "test_helper"

class PasswordSourcesTest < E2ETest
  # Inline `-p` round-trips.
  def test_inline_password_round_trip
    cipher = tmp("inline.symcrypt")
    out    = tmp("inline.out")
    enc = symcrypt("-e", Symcrypt::LOREM, "-o", cipher, *FAST_KDF, "-p", DEFAULT_PASSWORD)
    assert_status enc, 0
    dec = symcrypt("-d", cipher, "-o", out, "-p", DEFAULT_PASSWORD)
    assert_status dec, 0
    assert_identical Symcrypt::LOREM, out
  end

  # `--password-file` round-trips (one trailing newline is trimmed on read).
  def test_password_file_round_trip
    pw_file = write_input("pw", "#{DEFAULT_PASSWORD}\n")
    cipher  = tmp("file.symcrypt")
    out     = tmp("file.out")
    enc = symcrypt("-e", Symcrypt::LOREM, "-o", cipher, *FAST_KDF, "--password-file", pw_file)
    assert_status enc, 0
    dec = symcrypt("-d", cipher, "-o", out, "--password-file", pw_file)
    assert_status dec, 0
    assert_identical Symcrypt::LOREM, out
  end

  # The three sources hold the same secret, so any can decrypt what another
  # encrypted: encrypt via env, decrypt via inline `-p` and via a file.
  def test_sources_interoperate
    cipher = tmp("interop.symcrypt")
    out_p  = tmp("interop_p.out")
    out_f  = tmp("interop_f.out")
    pw_file = write_input("pw", DEFAULT_PASSWORD) # no trailing newline

    enc = symcrypt("-e", Symcrypt::LOREM, "-o", cipher, *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status enc, 0

    dec_p = symcrypt("-d", cipher, "-o", out_p, "-p", DEFAULT_PASSWORD)
    assert_status dec_p, 0
    assert_identical Symcrypt::LOREM, out_p

    dec_f = symcrypt("-d", cipher, "-o", out_f, "--password-file", pw_file)
    assert_status dec_f, 0
    assert_identical Symcrypt::LOREM, out_f
  end

  # `--password-file` trims exactly one trailing newline, so a `"pw\n"` file holds
  # the same secret as inline `pw`: encrypt with the file, decrypt with `-p`.
  def test_password_file_trims_one_trailing_newline
    pw_file = write_input("pw_nl", "#{DEFAULT_PASSWORD}\n")
    cipher  = tmp("trim.symcrypt")
    out     = tmp("trim.out")

    enc = symcrypt("-e", Symcrypt::LOREM, "-o", cipher, *FAST_KDF, "--password-file", pw_file)
    assert_status enc, 0
    dec = symcrypt("-d", cipher, "-o", out, "-p", DEFAULT_PASSWORD)
    assert_status dec, 0, "newline-trimmed file password must equal the inline password"
    assert_identical Symcrypt::LOREM, out
  end

  # A wrong password is an auth failure (exit 3).
  def test_password_mismatch_is_auth_failure
    cipher = tmp("mismatch.symcrypt")
    symcrypt("-e", Symcrypt::LOREM, "-o", cipher, *FAST_KDF, "-p", "alpha")
    res = symcrypt("-d", cipher, "-o", tmp("o"), "-p", "beta")
    assert_failure res, 3, "authentication failed"
  end

  # A password with spaces and multibyte unicode round-trips when delivered via
  # the environment (avoids shell/argv quoting concerns).
  def test_password_with_spaces_and_unicode_round_trips
    secret = "pä ss · wörd · 🔐 end"
    cipher = tmp("unicode.symcrypt")
    out    = tmp("unicode.out")
    env    = { "PW" => secret }
    enc = symcrypt("-e", Symcrypt::LOREM, "-o", cipher, *FAST_KDF,
                   "--password-env", "PW", env: env)
    assert_status enc, 0
    dec = symcrypt("-d", cipher, "-o", out, "--password-env", "PW", env: env)
    assert_status dec, 0
    assert_identical Symcrypt::LOREM, out
  end

  # At most one password source may be given; two at once is a usage error.
  def test_multiple_sources_is_usage_error
    pw_file = write_input("pw", DEFAULT_PASSWORD)
    res = symcrypt("-e", Symcrypt::LOREM, "-o", tmp("o"), *FAST_KDF,
                   "-p", DEFAULT_PASSWORD, "--password-file", pw_file)
    assert_failure res, 2, "at most one of"
  end

  # An empty `--password-file` (0 bytes) is a usage error: an empty password must
  # be requested explicitly with `--no-password` (+ keyfile), never inferred.
  def test_empty_password_file_is_usage_error
    empty = write_input("empty_pw", "")
    res = symcrypt("-e", Symcrypt::LOREM, "-o", tmp("o"), *FAST_KDF, "--password-file", empty)
    assert_failure res, 2
  end
end
