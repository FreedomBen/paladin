# frozen_string_literal: true
#
# Keyfiles (DESIGN §4.2, §6.4): `-k/--keyfile` mixes extra key material into the
# KDF input. A keyfile combines *with* the password source (it is not a
# replacement), except `--no-password` makes it keyfile-only. The keyfile is part
# of the key, so a wrong or missing keyfile is an auth failure (exit 3), while a
# malformed keyfile argument is a usage error (exit 2).

require "test_helper"

class KeyfileTest < E2ETest
  # password + keyfile round-trips (both required to decrypt).
  def test_password_plus_keyfile_round_trip
    kf     = make_keyfile
    cipher = tmp("pk.symcrypt")
    out    = tmp("pk.out")
    env    = { "PW" => DEFAULT_PASSWORD }
    enc = symcrypt("-e", Symcrypt::LOREM, "-o", cipher, "-k", kf, *FAST_KDF,
                   "--password-env", "PW", env: env)
    assert_status enc, 0
    dec = symcrypt("-d", cipher, "-o", out, "-k", kf, "--password-env", "PW", env: env)
    assert_status dec, 0
    assert_identical Symcrypt::LOREM, out
  end

  # keyfile-only (`--no-password`) round-trips.
  def test_keyfile_only_round_trip
    kf     = make_keyfile
    cipher = tmp("ko.symcrypt")
    out    = tmp("ko.out")
    enc = symcrypt("-e", Symcrypt::LOREM, "-o", cipher, "-k", kf, "--no-password", *FAST_KDF)
    assert_status enc, 0
    dec = symcrypt("-d", cipher, "-o", out, "-k", kf, "--no-password")
    assert_status dec, 0
    assert_identical Symcrypt::LOREM, out
  end

  # A different keyfile yields a different key → auth failure (exit 3).
  def test_wrong_keyfile_is_auth_failure
    good = make_keyfile("good.bin")
    bad  = write_input("bad.bin", "totally different key material padded out")
    cipher = tmp("wk.symcrypt")
    symcrypt("-e", Symcrypt::LOREM, "-o", cipher, "-k", good, "--no-password", *FAST_KDF)
    res = symcrypt("-d", cipher, "-o", tmp("o"), "-k", bad, "--no-password")
    assert_failure res, 3, "authentication failed"
  end

  # Encrypted with a keyfile; decrypting without `-k` fails as auth (exit 3) — the
  # keyfile is part of the key, and its absence is indistinguishable from a wrong
  # secret. (Uses password + keyfile so a password source is still present.)
  def test_missing_keyfile_on_decrypt_is_auth_failure
    kf     = make_keyfile
    cipher = tmp("mk.symcrypt")
    env    = { "PW" => DEFAULT_PASSWORD }
    symcrypt("-e", Symcrypt::LOREM, "-o", cipher, "-k", kf, *FAST_KDF,
             "--password-env", "PW", env: env)

    without = symcrypt("-d", cipher, "-o", tmp("o1"), "--password-env", "PW", env: env)
    assert_failure without, 3, "authentication failed"

    with = symcrypt("-d", cipher, "-o", tmp("o2"), "-k", kf, "--password-env", "PW", env: env)
    assert_status with, 0, "control: password + keyfile must decrypt"
  end

  # Two different keyfiles produce independent keys: each decrypts only its own
  # container (keyfile-only mode isolates the key to the keyfile).
  def test_two_keyfiles_yield_different_keys
    kf1 = write_input("k1.bin", "key one material with enough bytes here")
    kf2 = write_input("k2.bin", "key two material with enough bytes here")
    c1  = tmp("c1.symcrypt")
    c2  = tmp("c2.symcrypt")
    symcrypt("-e", Symcrypt::LOREM, "-o", c1, "-k", kf1, "--no-password", *FAST_KDF)
    symcrypt("-e", Symcrypt::LOREM, "-o", c2, "-k", kf2, "--no-password", *FAST_KDF)

    # Each keyfile decrypts its own file...
    assert_status symcrypt("-d", c1, "-o", tmp("o1"), "-k", kf1, "--no-password"), 0
    assert_status symcrypt("-d", c2, "-o", tmp("o2"), "-k", kf2, "--no-password"), 0
    # ...but not the other's.
    assert_failure symcrypt("-d", c1, "-o", tmp("x1"), "-k", kf2, "--no-password"), 3
    assert_failure symcrypt("-d", c2, "-o", tmp("x2"), "-k", kf1, "--no-password"), 3
  end

  # `-k -` is rejected: stdin is reserved for the main input stream (exit 2).
  def test_keyfile_from_stdin_is_rejected
    res = symcrypt("-e", Symcrypt::LOREM, "-o", tmp("o"), "-k", "-", "--no-password", *FAST_KDF)
    assert_failure res, 2
  end

  # A keyfile path that does not exist is a usage error (exit 2), not auth.
  def test_missing_keyfile_path_is_usage_error
    res = symcrypt("-e", Symcrypt::LOREM, "-o", tmp("o"), "-k", tmp("nope.bin"),
                   "--no-password", *FAST_KDF)
    assert_failure res, 2
  end
end
