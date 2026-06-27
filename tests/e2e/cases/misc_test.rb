# frozen_string_literal: true
#
# Cross-cutting properties that don't belong to a single flag area: header
# authentication / downgrade resistance, reserved-flag rejection, fresh
# per-file randomness, quiet-mode quietness, and the --help/--version surface.

require "test_helper"

class MiscTest < E2ETest
  # The whole serialized header is chunk-0 AAD, so swapping one structurally-valid
  # field for another valid value (cipher id 0x01 aes → 0x02 chacha) leaves a
  # parseable header but breaks authentication: decrypt is exit 3, not a silent
  # downgrade. `--info` (which never authenticates) still parses the tampered id.
  def test_header_is_authenticated_no_downgrade
    cipher = good_cipher("dg.paladin") # encrypted with the default aes-256-gcm
    set_byte(cipher, 9, 0x02)           # cipher_id byte → chacha20-poly1305

    info = paladin("-i", cipher)
    assert_status info, 0, "a structurally valid header still parses"
    assert_includes info.stdout, "cipher: chacha20-poly1305\n"

    res = paladin("-d", cipher, "-o", tmp("o"), "--password-env", "PW",
                   env: { "PW" => DEFAULT_PASSWORD })
    # A tampered-but-valid header must fail authentication, not silently downgrade.
    assert_failure res, 3, "authentication failed"
  end

  # Any reserved flag bit set → exit 4, even from `--info` (the flags byte is
  # validated during the no-password header parse).
  def test_reserved_flag_bit_is_rejected
    cipher = good_cipher("rf.paladin")
    set_byte(cipher, 11, 0x04) # flags byte: set a reserved bit

    assert_failure paladin("-i", cipher), 4, "reserved flags"
    res = paladin("-d", cipher, "-o", tmp("o"), "--password-env", "PW",
                   env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 4, "reserved flags"
  end

  # Fresh randomness: encrypting identical input twice yields different
  # ciphertext (random salt + nonce prefix per file), yet both decrypt.
  def test_fresh_randomness_per_file
    env = { "PW" => DEFAULT_PASSWORD }
    c1 = tmp("r1.paladin")
    c2 = tmp("r2.paladin")
    paladin("-e", Paladin::LOREM, "-o", c1, *FAST_KDF, "--password-env", "PW", env: env)
    paladin("-e", Paladin::LOREM, "-o", c2, *FAST_KDF, "--password-env", "PW", env: env)

    refute_equal File.binread(c1), File.binread(c2),
                 "two encryptions of the same input must differ"

    o1 = tmp("r1.out")
    o2 = tmp("r2.out")
    assert_status paladin("-d", c1, "-o", o1, "--password-env", "PW", env: env), 0
    assert_status paladin("-d", c2, "-o", o2, "--password-env", "PW", env: env), 0
    assert_identical Paladin::LOREM, o1
    assert_identical Paladin::LOREM, o2
  end

  # `-q` produces no stderr chatter on a successful file operation.
  def test_quiet_is_silent_on_success
    env    = { "PW" => DEFAULT_PASSWORD }
    cipher = tmp("q.paladin")
    enc = paladin("-e", Paladin::LOREM, "-o", cipher, "-q", *FAST_KDF,
                   "--password-env", "PW", env: env)
    assert_status enc, 0
    assert_empty enc.stderr, "--quiet encrypt should not chatter on stderr"

    dec = paladin("-d", cipher, "-o", tmp("q.out"), "-q",
                   "--password-env", "PW", env: env)
    assert_status dec, 0
    assert_empty dec.stderr, "--quiet decrypt should not chatter on stderr"
  end

  # `--help` and `--version` exit 0 with the expected surface text.
  def test_help_and_version
    help = paladin("--help")
    assert_status help, 0
    assert_includes help.stdout, "Usage"
    assert_includes help.stdout, "--encrypt"
    assert_includes help.stdout, "--decrypt"

    version = paladin("--version")
    assert_status version, 0
    assert_match(/paladin \d+\.\d+\.\d+/, version.stdout)
  end

  private

  def good_cipher(name)
    cipher = tmp(name)
    res = paladin("-e", Paladin::LOREM, "-o", cipher, *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status res, 0, "good_cipher setup failed: #{res.stderr}"
    cipher
  end
end
