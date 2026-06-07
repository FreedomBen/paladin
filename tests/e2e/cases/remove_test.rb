# frozen_string_literal: true
#
# `--remove` (DESIGN §6.5): after a *successful* operation whose output is
# finalized, the input file is deleted (a plain unlink, not a secure erase). It
# must never delete the input when the operation fails, and it cannot be used
# with stdin (there is no input file to remove → usage error, exit 2).

require "test_helper"

class RemoveTest < E2ETest
  # After a successful encrypt, `--remove` deletes the input; the output remains.
  def test_remove_after_successful_encrypt
    src    = write_input("doc.txt", File.binread(Symcrypt::LOREM))
    cipher = tmp("doc.symcrypt")
    enc = symcrypt("-e", src, "-o", cipher, "--remove", *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status enc, 0
    refute File.exist?(src), "input should be removed after a successful encrypt"
    assert File.file?(cipher), "output must remain"
  end

  # After a successful decrypt, `--remove` deletes the (container) input.
  def test_remove_after_successful_decrypt
    cipher = tmp("doc.symcrypt")
    symcrypt("-e", Symcrypt::LOREM, "-o", cipher, *FAST_KDF,
             "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    out = tmp("doc.out")
    dec = symcrypt("-d", cipher, "-o", out, "--remove",
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status dec, 0
    refute File.exist?(cipher), "container should be removed after a successful decrypt"
    assert_identical Symcrypt::LOREM, out
  end

  # On an auth failure the input is preserved (nothing was finalized).
  def test_remove_preserves_input_on_auth_failure
    cipher = tmp("doc.symcrypt")
    symcrypt("-e", Symcrypt::LOREM, "-o", cipher, *FAST_KDF, "-p", "right-secret")
    res = symcrypt("-d", cipher, "-o", tmp("o"), "--remove", "-p", "wrong-secret")
    assert_failure res, 3, "authentication failed"
    assert File.file?(cipher), "a failed decrypt must not remove the input"
  end

  # On a refuse-to-overwrite (exit 2) the input is preserved: the operation never
  # ran, so there is nothing to clean up after.
  def test_remove_preserves_input_on_refuse_to_overwrite
    src      = write_input("doc.txt", "fresh content\n")
    existing = write_input("out.symcrypt", "do not clobber me\n")
    res = symcrypt("-e", src, "-o", existing, "--remove", *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 2, "already exists"
    assert File.exist?(src), "a refused encrypt must not remove the input"
    assert_equal "do not clobber me\n", File.binread(existing), "existing output untouched"
  end

  # `--remove` cannot be combined with stdin input: there is no file to remove,
  # so it is a usage error (exit 2) — not a silent no-op.
  def test_remove_with_stdin_is_usage_error
    res = symcrypt("-e", "-", "-o", tmp("o.symcrypt"), "--remove", *FAST_KDF,
                   "--password-env", "PW", stdin: "x", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 2, "stdin"
  end
end
