# frozen_string_literal: true
#
# Advanced / opt-in cases: a multi-megabyte round-trip and SIGINT cancellation.
# Both are slow and/or timing-sensitive, so they only run when SYMCRYPT_E2E_SLOW
# is set:
#
#   SYMCRYPT_E2E_SLOW=1 tests/e2e/run.sh
#
# They are otherwise skipped (and reported as skips) so the default suite stays
# fast and deterministic.

require "test_helper"

class AdvancedTest < E2ETest
  # A multi-MB payload round-trips end-to-end (STREAM across many chunks).
  def test_large_file_round_trip
    skip "slow; set SYMCRYPT_E2E_SLOW=1 to run" unless slow_enabled?

    size   = 8 * 1024 * 1024 # 8 MiB: well past the 64 KiB chunk boundary
    input  = make_input("large.bin", size)
    cipher = tmp("large.symcrypt")
    out    = tmp("large.out")
    env    = { "PW" => DEFAULT_PASSWORD }

    enc = symcrypt("-e", input, "-o", cipher, *FAST_KDF, "--password-env", "PW", env: env)
    assert_status enc, 0
    assert_size_grew input, cipher
    dec = symcrypt("-d", cipher, "-o", out, "--password-env", "PW", env: env)
    assert_status dec, 0
    assert_identical input, out
  end

  # SIGINT mid-encrypt exits 130 (canceled) and leaves no partial output: the
  # unfinalized temp sink is dropped, so the target file is never created.
  #
  # Reads an endless stream (/dev/zero) so the process is reliably still
  # streaming when the signal lands — no race on a fixed-size input finishing
  # first. Spawned directly (not via the `symcrypt` helper) so we hold the PID.
  def test_sigint_cancels_and_removes_partial_output
    skip "timing-sensitive; set SYMCRYPT_E2E_SLOW=1 to run" unless slow_enabled?
    skip "/dev/zero not available" unless File.readable?("/dev/zero")

    out = tmp("canceled.symcrypt")
    pid = Process.spawn(
      { "PW" => DEFAULT_PASSWORD }, Symcrypt.binary,
      "-e", "-", "-o", out, *FAST_KDF, "--password-env", "PW", "--no-progress",
      in: "/dev/zero", out: File::NULL, err: File::NULL
    )
    sleep 0.3 # past the (fast) KDF and well into streaming
    Process.kill("INT", pid)
    _, status = Process.wait2(pid)

    assert_equal 130, status.exitstatus, "SIGINT should exit 130 (canceled)"
    refute File.exist?(out), "a canceled run must leave no partial output"
  end

  private

  def slow_enabled?
    %w[1 true yes].include?(ENV["SYMCRYPT_E2E_SLOW"].to_s.downcase)
  end
end
