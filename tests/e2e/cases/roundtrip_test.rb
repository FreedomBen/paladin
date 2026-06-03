# frozen_string_literal: true
#
# End-to-end round-trip coverage for the symcrypt CLI: decrypting an encrypted
# container must reproduce the input byte-for-byte, and the container is always
# larger than the plaintext (self-describing header + per-chunk AEAD tags).
#
# Folds in the original tests/roundtrip_cli.sh (test_fixture_round_trips_with_defaults).

require "test_helper"

class RoundtripTest < E2ETest
  # FAST_KDF (a cheap PBKDF2) is inherited from E2ETest; the size sweep uses it
  # since the KDF is irrelevant to STREAM correctness.

  # Folds in tests/roundtrip_cli.sh: with default settings, encrypt the committed
  # fixture, confirm the ciphertext is slightly larger than the plaintext, then
  # decrypt and confirm a byte-for-byte match. Uses the real default KDF
  # (Argon2id), so this doubles as a realistic smoke test.
  def test_fixture_round_trips_with_defaults
    cipher = tmp("lorem.symcrypt")
    plain  = tmp("lorem.decrypted.txt")
    env    = { "PW" => DEFAULT_PASSWORD }

    enc = symcrypt("--encrypt", Symcrypt::LOREM, "--output", cipher,
                   "--password-env", "PW", env: env)
    assert_status enc, 0
    assert_size_grew Symcrypt::LOREM, cipher

    dec = symcrypt("--decrypt", cipher, "--output", plain,
                   "--password-env", "PW", env: env)
    assert_status dec, 0
    assert_identical Symcrypt::LOREM, plain
  end

  # Round-trips must hold for empty input and at/around the 64 KiB STREAM chunk
  # boundary. The KDF is irrelevant to this property, so use the cheap one.
  def test_round_trip_preserves_content_across_sizes
    env   = { "PW" => DEFAULT_PASSWORD }
    sizes = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, (3 * CHUNK) + 123]

    sizes.each do |size|
      input  = make_input("plain_#{size}.bin", size)
      cipher = tmp("cipher_#{size}.symcrypt")
      plain  = tmp("plain_#{size}.out")

      enc = symcrypt("--encrypt", input, "--output", cipher, *FAST_KDF,
                     "--password-env", "PW", env: env)
      assert_status enc, 0, "encrypt failed for size #{size}"
      assert_size_grew input, cipher, "ciphertext not larger than plaintext for size #{size}"

      dec = symcrypt("--decrypt", cipher, "--output", plain,
                     "--password-env", "PW", env: env)
      assert_status dec, 0, "decrypt failed for size #{size}"
      assert_identical input, plain, "round-trip mismatch for size #{size}"
    end
  end

  # Without --output, encrypt appends ".symcrypt" beside the input (DESIGN §6.5).
  # Operate on a copy inside the temp dir so the default output lands there.
  def test_default_encrypt_output_name
    input = write_input("note.txt", File.binread(Symcrypt::LOREM))
    env   = { "PW" => DEFAULT_PASSWORD }

    enc = symcrypt("--encrypt", input, *FAST_KDF, "--password-env", "PW", env: env)
    assert_status enc, 0

    cipher = "#{input}.symcrypt"
    assert File.file?(cipher), "expected default ciphertext at #{cipher}"
    assert_size_grew input, cipher

    plain = tmp("note.decrypted.txt")
    dec = symcrypt("--decrypt", cipher, "--output", plain,
                   "--password-env", "PW", env: env)
    assert_status dec, 0
    assert_identical input, plain
  end
end
