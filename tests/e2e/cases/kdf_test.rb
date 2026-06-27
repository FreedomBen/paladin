# frozen_string_literal: true
#
# KDF selection, cost parameters, and header authority (DESIGN §4.2, §5.4, §6.3).
# `--kdf` chooses argon2id (default), scrypt, or pbkdf2; per-KDF knobs tune the
# cost. Decrypt is header-driven and never takes `--kdf`. Cost knobs are bounded
# by DESIGN §5.4; out-of-range or mismatched knobs are usage errors (exit 2).

require "test_helper"

class KdfTest < E2ETest
  # name => [encrypt cost flags, expected `kdf_params:` line value]. The costs are
  # the cheapest interesting in-range values so the suite stays fast.
  KDFS = {
    "argon2id" => [%w[--argon2-memory 8192 --argon2-time 2 --argon2-parallelism 2],
                   "memory=8192,time=2,parallelism=2"],
    "scrypt"   => [%w[--scrypt-log-n 12 --scrypt-r 4 --scrypt-p 2], "log_n=12,r=4,p=2"],
    "pbkdf2"   => [%w[--pbkdf2-iterations 20000], "iterations=20000"],
  }.freeze

  # Each KDF round-trips, decrypt recovers it from the header (no `--kdf`), and
  # the custom cost parameters survive into `--info` verbatim.
  def test_each_kdf_round_trips_and_info_reports_params
    env = { "PW" => DEFAULT_PASSWORD }
    KDFS.each do |kdf, (cost, params)|
      input  = write_input("p_#{kdf}.txt", "data for #{kdf}\n" * 8)
      cipher = tmp("c_#{kdf}.paladin")
      out    = tmp("d_#{kdf}.txt")

      enc = paladin("-e", input, "-o", cipher, "--kdf", kdf, *cost,
                     "--password-env", "PW", env: env)
      assert_status enc, 0, "encrypt with #{kdf} failed: #{enc.stderr}"

      info = paladin("-i", cipher)
      assert_status info, 0
      assert_includes info.stdout, "kdf: #{kdf}\n", "info should name #{kdf}"
      assert_includes info.stdout, "kdf_params: #{params}\n",
                      "info should echo #{kdf} cost params"

      dec = paladin("-d", cipher, "-o", out, "--password-env", "PW", env: env)
      assert_status dec, 0, "header-driven decrypt for #{kdf} failed"
      assert_identical input, out
    end
  end

  # The default KDF (no `--kdf`) is argon2id (DESIGN §12). Cheapest valid argon2
  # cost keeps it quick.
  def test_default_kdf_is_argon2id
    cipher = tmp("def.paladin")
    enc = paladin("-e", Paladin::LOREM, "-o", cipher,
                   "--argon2-memory", "8192", "--argon2-time", "1",
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status enc, 0
    info = paladin("-i", cipher)
    assert_includes info.stdout, "kdf: argon2id\n"
  end

  # Out-of-range costs are usage errors (exit 2) for every KDF (DESIGN §5.4):
  # below/above each documented bound.
  def test_out_of_range_costs_are_usage_errors
    env = { "PW" => DEFAULT_PASSWORD }
    cases = [
      %w[--kdf pbkdf2 --pbkdf2-iterations 9999],       # < 10_000
      %w[--kdf pbkdf2 --pbkdf2-iterations 10000001],   # > 10_000_000
      %w[--kdf argon2id --argon2-memory 8191],         # < 8192 KiB
      %w[--kdf argon2id --argon2-time 11],             # > 10
      %w[--kdf argon2id --argon2-parallelism 17],      # > 16
      %w[--kdf scrypt --scrypt-log-n 9],               # < 10
      %w[--kdf scrypt --scrypt-log-n 21],              # > 20
    ]
    cases.each_with_index do |flags, i|
      res = paladin("-e", Paladin::LOREM, "-o", tmp("o#{i}"),
                     *flags, "--password-env", "PW", env: env)
      assert_status res, 2, "#{flags.join(' ')} should be a usage error"
    end
  end

  # A cost knob requires its matching `--kdf` (a knob never implies a KDF). argon2
  # knobs are the exception, since argon2id is the default.
  def test_cost_knob_requires_matching_kdf
    env = { "PW" => DEFAULT_PASSWORD }

    no_pbkdf2 = paladin("-e", Paladin::LOREM, "-o", tmp("o1"),
                         "--pbkdf2-iterations", "20000",
                         "--password-env", "PW", env: env)
    assert_failure no_pbkdf2, 2, "requires --kdf pbkdf2"

    no_scrypt = paladin("-e", Paladin::LOREM, "-o", tmp("o2"),
                         "--scrypt-log-n", "12",
                         "--password-env", "PW", env: env)
    assert_failure no_scrypt, 2, "scrypt cost options require --kdf scrypt"
  end

  # An unknown KDF name is a usage error (exit 2).
  def test_invalid_kdf_name_is_usage_error
    res = paladin("-e", Paladin::LOREM, "-o", tmp("o"), "--kdf", "bcrypt",
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 2, "unknown kdf"
  end
end
