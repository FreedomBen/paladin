# frozen_string_literal: true
#
# stdin/stdout streaming via `-` (DESIGN §6.5). The container is designed to flow
# through a shell pipeline without temp files. Because stdin has no path, encrypt
# and decrypt both require an explicit `-o` when reading from `-`, and no original
# filename is ever stored.
#
# Black-box complement to it_stdio.rs / it_roundtrip.rs: real pipe plumbing and
# the purity of stdout under `-q`.

require "test_helper"

class StreamingTest < E2ETest
  # Full pipe: encrypt stdin→stdout, feed that into decrypt stdin→stdout.
  def test_full_pipe_round_trip
    data = sample_bytes(4096)
    env  = { "PW" => DEFAULT_PASSWORD }
    enc = symcrypt("-e", "-", "-o", "-", *FAST_KDF, "--password-env", "PW",
                   stdin: data, env: env)
    assert_status enc, 0
    dec = symcrypt("-d", "-", "-o", "-", "--password-env", "PW",
                   stdin: enc.stdout, env: env)
    assert_status dec, 0
    assert_equal data, dec.stdout
  end

  # Encrypt a file to stdout, then decrypt that captured stream back to a file.
  def test_file_to_stdout_then_decrypt
    env = { "PW" => DEFAULT_PASSWORD }
    enc = symcrypt("-e", Symcrypt::LOREM, "-o", "-", *FAST_KDF,
                   "--password-env", "PW", env: env)
    assert_status enc, 0
    out = tmp("back.out")
    dec = symcrypt("-d", "-", "-o", out, "--password-env", "PW",
                   stdin: enc.stdout, env: env)
    assert_status dec, 0
    assert_identical Symcrypt::LOREM, out
  end

  # A multi-chunk (> 64 KiB) payload survives the full stdin/stdout pipe.
  def test_multi_chunk_through_pipe
    data = sample_bytes((3 * CHUNK) + 99)
    env  = { "PW" => DEFAULT_PASSWORD }
    enc = symcrypt("-e", "-", "-o", "-", *FAST_KDF, "--password-env", "PW",
                   stdin: data, env: env)
    assert_status enc, 0
    dec = symcrypt("-d", "-", "-o", "-", "--password-env", "PW",
                   stdin: enc.stdout, env: env)
    assert_status dec, 0
    assert_equal data, dec.stdout
  end

  # Armored streaming: `-e - -a -o -` emits armor text that round-trips.
  def test_armored_streaming
    data = sample_bytes(2048)
    env  = { "PW" => DEFAULT_PASSWORD }
    enc = symcrypt("-e", "-", "-a", "-o", "-", *FAST_KDF, "--password-env", "PW",
                   stdin: data, env: env)
    assert_status enc, 0
    assert enc.stdout.start_with?("-----BEGIN SYMCRYPT MESSAGE-----"),
           "armored stdout should start with the BEGIN marker"
    dec = symcrypt("-d", "-", "-o", "-", "--password-env", "PW",
                   stdin: enc.stdout, env: env)
    assert_status dec, 0
    assert_equal data, dec.stdout
  end

  # A stdin-sourced container stores no filename: `--info` shows it absent, and
  # decrypting that stream back requires `-o` (there is no input path to derive
  # an output name from).
  def test_stdin_stores_no_filename_and_decrypt_needs_output
    env = { "PW" => DEFAULT_PASSWORD }
    cipher = tmp("from_stdin.symcrypt")
    enc = symcrypt("-e", "-", "-o", cipher, *FAST_KDF, "--password-env", "PW",
                   stdin: sample_bytes(512), env: env)
    assert_status enc, 0

    info = symcrypt("-i", cipher)
    assert_includes info.stdout, "name_status: absent\n"

    # Decrypting from stdin without -o is a usage error.
    no_out = symcrypt("-d", "-", "--password-env", "PW",
                      stdin: File.binread(cipher), env: env)
    assert_failure no_out, 2, "requires -o"
  end

  # `-q` keeps stdout pure: only the container goes to stdout, nothing leaks to
  # stderr on success, and the captured stdout still round-trips.
  def test_quiet_keeps_stdout_pure
    data = sample_bytes(4096)
    env  = { "PW" => DEFAULT_PASSWORD }
    enc = symcrypt("-e", "-", "-o", "-", "-q", *FAST_KDF, "--password-env", "PW",
                   stdin: data, env: env)
    assert_status enc, 0
    assert_empty enc.stderr, "--quiet must not emit status to stderr"
    dec = symcrypt("-d", "-", "-o", "-", "--password-env", "PW",
                   stdin: enc.stdout, env: env)
    assert_status dec, 0
    assert_equal data, dec.stdout, "stdout must be exactly the container"
  end
end
