# frozen_string_literal: true
#
# Cipher selection and header authority (DESIGN §4.1, §6.3). `-c/--cipher`
# chooses the AEAD: aes-256-gcm (default) or chacha20-poly1305. Decrypt, verify,
# and info are header-driven — they read the cipher from the authenticated header
# and never accept `-c`.

require "test_helper"

class CipherTest < E2ETest
  CIPHERS = %w[aes-256-gcm chacha20-poly1305].freeze

  # Each cipher (including an explicit default) must round-trip, and decrypt —
  # given no `-c` — must recover the cipher from the header alone.
  def test_each_cipher_round_trips_header_driven
    env = { "PW" => DEFAULT_PASSWORD }
    CIPHERS.each do |cipher|
      input  = write_input("p_#{cipher}.txt", "payload for #{cipher}\n" * 8)
      cipher_file = tmp("c_#{cipher}.symcrypt")
      out    = tmp("d_#{cipher}.txt")

      enc = symcrypt("-e", input, "-o", cipher_file, "--cipher", cipher, *FAST_KDF,
                     "--password-env", "PW", env: env)
      assert_status enc, 0, "encrypt with #{cipher} failed: #{enc.stderr}"

      # No --cipher on decrypt: the header must carry it.
      dec = symcrypt("-d", cipher_file, "-o", out, "--password-env", "PW", env: env)
      assert_status dec, 0, "header-driven decrypt for #{cipher} failed"
      assert_identical input, out
    end
  end

  # `--info` names each cipher; the line is a stable contract front-ends parse.
  def test_info_reports_each_cipher
    CIPHERS.each do |cipher|
      cipher_file = tmp("c_#{cipher}.symcrypt")
      symcrypt("-e", Symcrypt::LOREM, "-o", cipher_file, "--cipher", cipher, *FAST_KDF,
               "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
      info = symcrypt("-i", cipher_file)
      assert_status info, 0
      assert_includes info.stdout, "cipher: #{cipher}\n", "info should name #{cipher}"
    end
  end

  # Both ciphers must hold across a multi-chunk (> 64 KiB) payload.
  def test_both_ciphers_round_trip_multi_chunk
    input = make_input("big.bin", (3 * CHUNK) + 17)
    env   = { "PW" => DEFAULT_PASSWORD }
    CIPHERS.each do |cipher|
      cipher_file = tmp("big_#{cipher}.symcrypt")
      out = tmp("big_#{cipher}.out")
      enc = symcrypt("-e", input, "-o", cipher_file, "--cipher", cipher, *FAST_KDF,
                     "--password-env", "PW", env: env)
      assert_status enc, 0
      dec = symcrypt("-d", cipher_file, "-o", out, "--password-env", "PW", env: env)
      assert_status dec, 0
      assert_identical input, out, "multi-chunk round-trip failed for #{cipher}"
    end
  end

  # An unknown cipher name is a usage error (exit 2), never a guess.
  def test_invalid_cipher_name_is_usage_error
    res = symcrypt("-e", Symcrypt::LOREM, "-o", tmp("o"), "--cipher", "rot13",
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 2, "unknown cipher"
  end

  # Decrypt forbids algorithm flags: a mismatched `-c` on decrypt is refused
  # outright (exit 2), so a flag can never silently override the authenticated
  # header. (The header — not the flag — decides the cipher.)
  def test_decrypt_rejects_cipher_flag
    cipher_file = tmp("c.symcrypt")
    symcrypt("-e", Symcrypt::LOREM, "-o", cipher_file, "--cipher", "chacha20-poly1305",
             *FAST_KDF, "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })

    res = symcrypt("-d", cipher_file, "-o", tmp("o"), "-c", "aes-256-gcm",
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 2, "apply only to encrypt"
  end
end
