# frozen_string_literal: true
#
# `-i/--info` (header metadata, no password) and `--verify` (decrypt-and-discard)
# (DESIGN §6.2). Info reads only the unauthenticated header and writes nothing.
# Verify confirms integrity + secret without producing any plaintext file:
# success is exit 0, a bad tag is exit 3. Both auto-detect armor.

require "test_helper"

class InfoVerifyTest < E2ETest
  # `--info` prints the documented fields and exits 0, without a password.
  def test_info_prints_expected_fields
    cipher = good_cipher("info.paladin")
    info = paladin("-i", cipher) # note: no password flag at all
    assert_status info, 0
    %w[format: version: cipher: kdf: kdf_params: chunk_size: name_status:].each do |field|
      assert_includes info.stdout, field, "info should report #{field}"
    end
  end

  # `--info` writes no output file: the temp dir gains nothing beyond the inputs.
  def test_info_writes_nothing
    cipher = good_cipher("nowrite.paladin")
    before = dir_entries
    info = paladin("-i", cipher)
    assert_status info, 0
    assert_equal before, dir_entries, "--info must not create files"
  end

  # With `--name`, the stored basename is reported (it is off by default).
  def test_info_reports_stored_filename_with_name_flag
    src = write_input("report.txt", File.binread(Paladin::LOREM))
    cipher = tmp("named.paladin")
    enc = paladin("-e", src, "-o", cipher, "--name", *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status enc, 0
    info = paladin("-i", cipher)
    assert_includes info.stdout, "name_status: present\n"
    assert_includes info.stdout, "name: report.txt\n"
  end

  # `--verify` with the correct password succeeds (exit 0).
  def test_verify_correct_password_succeeds
    cipher = good_cipher("v.paladin")
    ok = paladin("--verify", cipher, "--password-env", "PW",
                  env: { "PW" => DEFAULT_PASSWORD })
    assert_status ok, 0
  end

  # `--verify` produces no output file even on success.
  def test_verify_writes_no_output
    cipher = good_cipher("vno.paladin")
    before = dir_entries
    ok = paladin("--verify", cipher, "--password-env", "PW",
                  env: { "PW" => DEFAULT_PASSWORD })
    assert_status ok, 0
    assert_equal before, dir_entries, "--verify must not create files"
  end

  # `--verify` on a tampered file is an auth failure (exit 3).
  def test_verify_tampered_file_is_auth_failure
    cipher = good_cipher("vt.paladin")
    flip_byte(cipher, File.size(cipher) - 1) # final AEAD tag
    res = paladin("--verify", cipher, "--password-env", "PW",
                   env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 3, "authentication failed"
  end

  # `--info` and `--verify` both auto-detect armor.
  def test_info_and_verify_on_armored_file
    cipher = tmp("armored.asc")
    enc = paladin("-e", Paladin::LOREM, "-o", cipher, "-a", *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status enc, 0

    info = paladin("-i", cipher)
    assert_status info, 0
    assert_includes info.stdout, "format: paladin\n"

    ver = paladin("--verify", cipher, "--password-env", "PW",
                   env: { "PW" => DEFAULT_PASSWORD })
    assert_status ver, 0
  end

  private

  # Names of the entries currently in the per-test temp dir.
  def dir_entries
    Dir.children(@tmpdir).sort
  end

  # A valid encrypted container (fast KDF, default password); returns its path.
  def good_cipher(name = "good.paladin")
    cipher = tmp(name)
    res = paladin("-e", Paladin::LOREM, "-o", cipher, *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status res, 0, "good_cipher setup failed: #{res.stderr}"
    cipher
  end
end
