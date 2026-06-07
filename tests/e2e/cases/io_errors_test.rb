# frozen_string_literal: true
#
# Real-filesystem error paths (DESIGN §6.5, §6.6). These cover exit 1
# (general/I/O) — the one code the failures_test matrix doesn't reach — and the
# usage/exit-2 boundary for a non-regular input.
#
#   * Output whose parent directory is missing or unwritable → exit 1.
#   * Unreadable input (chmod 000) → exit 1.
#   * Non-regular input (a directory) → exit 2 (require_regular_file).
#
# The permission-based cases are skipped when running as root, where the mode
# bits do not deny access.

require "test_helper"

class IoErrorsTest < E2ETest
  # Encrypting into a non-existent output directory is a general I/O error: the
  # sibling temp file can't be created. (DESIGN §6.6 → exit 1.)
  def test_output_into_missing_directory_is_io_error
    res = symcrypt("-e", Symcrypt::LOREM, "-o", tmp("no_such_dir/out.symcrypt"),
                   *FAST_KDF, "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status res, 1
  end

  # An unreadable input file (mode 000) fails to open → I/O error (exit 1).
  def test_unreadable_input_is_io_error
    skip "permission bits do not deny root" if Process.uid.zero?
    src = write_input("secret.txt", "data")
    File.chmod(0o000, src)
    begin
      res = symcrypt("-e", src, "-o", tmp("o.symcrypt"), *FAST_KDF,
                     "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
      assert_status res, 1
    ensure
      File.chmod(0o644, src) # so teardown can clean up
    end
  end

  # A directory is not a regular file, so it is rejected as a usage error
  # (exit 2) before any crypto runs.
  def test_directory_input_is_usage_error
    subdir = tmp("a_directory")
    FileUtils.mkdir_p(subdir)
    res = symcrypt("-e", subdir, "-o", tmp("o.symcrypt"), *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 2, "not a regular file"
  end

  # Writing into a read-only directory fails to create the sibling temp file →
  # I/O error (exit 1).
  def test_write_into_readonly_directory_is_io_error
    skip "permission bits do not deny root" if Process.uid.zero?
    ro = tmp("ro_dir")
    FileUtils.mkdir_p(ro)
    File.chmod(0o555, ro)
    begin
      res = symcrypt("-e", Symcrypt::LOREM, "-o", File.join(ro, "out.symcrypt"),
                     *FAST_KDF, "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
      assert_status res, 1
    ensure
      File.chmod(0o755, ro) # so teardown can remove it
    end
  end
end
