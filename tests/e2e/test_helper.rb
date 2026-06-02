# frozen_string_literal: true
#
# Shared foundation for the symcrypt CLI end-to-end suite.
#
# Every case file does `require "test_helper"` and subclasses E2ETest. Tests run
# against the REAL built binary (resolved from SYMCRYPT_BIN, otherwise the
# workspace debug build) through the `symcrypt` helper, so they exercise the tool
# exactly as a user would from a shell.
#
# We deliberately stick to pure-Ruby stdlib (minitest, open3, tmpdir, fileutils)
# and avoid json/yaml/psych: this environment's native extensions for those gems
# are not built.

require "minitest/autorun"
require "open3"
require "tmpdir"
require "fileutils"

module Symcrypt
  E2E_DIR        = __dir__
  WORKSPACE_ROOT = File.expand_path("../..", __dir__) # tests/e2e -> repo root
  FIXTURES_DIR   = File.expand_path("../fixtures", __dir__) # -> tests/fixtures
  LOREM          = File.join(FIXTURES_DIR, "LOREM_IPSUM.txt")
  GOLDEN_DIR     = File.join(FIXTURES_DIR, "golden")

  # Path to the CLI binary under test. Override with SYMCRYPT_BIN to test, e.g.,
  # a release build or an installed copy.
  def self.binary
    ENV["SYMCRYPT_BIN"] || File.join(WORKSPACE_ROOT, "target", "debug", "symcrypt")
  end

  # Outcome of one CLI invocation. `status` is the process exit code.
  Result = Struct.new(:status, :stdout, :stderr, keyword_init: true) do
    def ok? = status.zero?
  end
end

# Base class for every end-to-end case. Provides a per-test temp dir, a runner
# for the binary, helpers to build/corrupt inputs, and domain assertions.
class E2ETest < Minitest::Test
  DEFAULT_PASSWORD = "correct horse battery staple"
  CHUNK = 64 * 1024 # core's default STREAM chunk size; handy for boundary inputs

  def setup
    @tmpdir = Dir.mktmpdir("symcrypt-e2e-")
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.directory?(@tmpdir)
  end

  # --- invoking the CLI ----------------------------------------------------

  # Run the binary with the given args. Returns Symcrypt::Result and never raises
  # on a non-zero exit (assert on result.status yourself). Examples:
  #   symcrypt("--encrypt", input, "-o", out,
  #            "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
  #   symcrypt("-e", "-", stdin: data)   # read stdin, write stdout
  def symcrypt(*args, stdin: nil, env: {})
    str_env = env.transform_keys(&:to_s).transform_values(&:to_s)
    out, err, status = Open3.capture3(
      str_env, Symcrypt.binary, *args.map(&:to_s),
      stdin_data: stdin.nil? ? "" : stdin, binmode: true
    )
    Symcrypt::Result.new(status: status.exitstatus, stdout: out, stderr: err)
  end

  # --- building inputs -----------------------------------------------------

  def tmp(name) = File.join(@tmpdir, name)

  # Write arbitrary bytes to a temp file; returns its path.
  def write_input(name, content)
    path = tmp(name)
    File.binwrite(path, content)
    path
  end

  # Create a temp file of exactly `size` bytes with deterministic content.
  def make_input(name, size)
    write_input(name, sample_bytes(size))
  end

  # Deterministic pseudo-data (repeating 0x00..0xff) so round-trips are
  # reproducible across runs.
  def sample_bytes(size)
    block = (0..255).to_a.pack("C*")
    full, rem = size.divmod(block.bytesize)
    (block * full) + block.byteslice(0, rem)
  end

  # A keyfile is just bytes; reuse the input generator.
  def make_keyfile(name = "keyfile.bin", size = 64)
    make_input(name, size)
  end

  # --- corrupting inputs (for tamper / truncate cases) ---------------------

  def flip_byte(path, offset)
    data = File.binread(path)
    data.setbyte(offset, data.getbyte(offset) ^ 0xff)
    File.binwrite(path, data)
    path
  end

  def truncate_input(path, drop_bytes)
    File.truncate(path, File.size(path) - drop_bytes)
    path
  end

  # --- domain assertions ---------------------------------------------------

  def file_size(path) = File.size(path)

  def assert_size_grew(original, output, msg = nil)
    o = file_size(original)
    n = file_size(output)
    assert_operator n, :>, o,
                    msg || "expected output #{output} (#{n} B) to be larger than input #{original} (#{o} B)"
  end

  def assert_identical(expected, actual, msg = nil)
    assert_equal File.binread(expected), File.binread(actual),
                 msg || "expected #{actual} to be byte-for-byte identical to #{expected}"
  end

  def assert_status(result, code, msg = nil)
    assert_equal code, result.status,
                 msg || "expected exit #{code}, got #{result.status}\nSTDERR:\n#{result.stderr}"
  end
end
