# frozen_string_literal: true
#
# ASCII armor (DESIGN §5.6, §6.5). `-a/--armor` wraps the binary container in a
# PEM-style base64 envelope; decrypt/verify/info auto-detect armor, so they never
# need `-a`. This suite asserts the on-the-wire text shape (markers, 7-bit ASCII),
# the default `.paladin.asc` name, streaming through stdout, and that the reader
# is lenient about surrounding whitespace yet still authenticates the payload.

require "test_helper"

class ArmorTest < E2ETest
  BEGIN_MARKER = "-----BEGIN PALADIN MESSAGE-----"
  END_MARKER   = "-----END PALADIN MESSAGE-----"

  # `-a` encrypt, then auto-detected decrypt, reproduces the input.
  def test_armored_round_trip
    cipher = tmp("a.asc")
    out    = tmp("a.out")
    env    = { "PW" => DEFAULT_PASSWORD }

    enc = paladin("-e", Paladin::LOREM, "-o", cipher, "-a", *FAST_KDF,
                   "--password-env", "PW", env: env)
    assert_status enc, 0
    dec = paladin("-d", cipher, "-o", out, "--password-env", "PW", env: env)
    assert_status dec, 0
    assert_identical Paladin::LOREM, out
  end

  # Armored output is 7-bit printable ASCII: every byte is a newline or in the
  # 0x20..0x7e printable range. (Safe to paste into text channels.)
  def test_armored_output_is_7bit_printable_ascii
    cipher = armor_fixture("ascii.asc")
    bytes = File.binread(cipher).bytes
    offenders = bytes.reject { |b| b == 0x0a || (b >= 0x20 && b <= 0x7e) }
    assert_empty offenders, "armored output must be 7-bit printable ASCII + LF"
  end

  # The envelope begins with the exact BEGIN marker and ends with the exact END
  # marker on its own line.
  def test_armored_has_expected_banner_lines
    cipher = armor_fixture("banner.asc")
    lines = File.binread(cipher).split("\n")
    assert_equal BEGIN_MARKER, lines.first, "first line must be the BEGIN marker"
    assert_includes lines, END_MARKER, "an END marker line must be present"
  end

  # Without `-o`, armored encrypt appends `.paladin.asc` beside the input
  # (DESIGN §6.5). Operate on a copy in the temp dir so the default lands there.
  def test_default_armored_output_name
    input = write_input("note.txt", File.binread(Paladin::LOREM))
    enc = paladin("-e", input, "-a", *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status enc, 0
    assert File.file?("#{input}.paladin.asc"),
           "expected default armored output at #{input}.paladin.asc"
  end

  # `--info` auto-detects armor and reports the header.
  def test_info_on_armored_file
    cipher = armor_fixture("info.asc")
    info = paladin("-i", cipher)
    assert_status info, 0
    assert_includes info.stdout, "format: paladin\n"
  end

  # Armor to stdout emits text, and that text round-trips back through `-d -`.
  def test_armor_to_stdout_round_trips
    env = { "PW" => DEFAULT_PASSWORD }
    enc = paladin("-e", Paladin::LOREM, "-o", "-", "-a", *FAST_KDF,
                   "--password-env", "PW", env: env)
    assert_status enc, 0
    assert enc.stdout.start_with?(BEGIN_MARKER), "stdout should be armored text"

    dec = paladin("-d", "-", "-o", "-", "--password-env", "PW",
                   stdin: enc.stdout, env: env)
    assert_status dec, 0
    assert_equal File.binread(Paladin::LOREM), dec.stdout
  end

  # A multi-chunk (> 64 KiB) payload round-trips through armor. LOREM is ~293 KiB,
  # so it already spans several chunks.
  def test_armored_multi_chunk_round_trip
    input = make_input("big.bin", (2 * CHUNK) + 5)
    cipher = tmp("big.asc")
    out    = tmp("big.out")
    env    = { "PW" => DEFAULT_PASSWORD }
    enc = paladin("-e", input, "-o", cipher, "-a", *FAST_KDF,
                   "--password-env", "PW", env: env)
    assert_status enc, 0
    dec = paladin("-d", cipher, "-o", out, "--password-env", "PW", env: env)
    assert_status dec, 0
    assert_identical input, out
  end

  # Flipping one base64 char in the body corrupts the authenticated payload, so
  # decrypt is an auth failure (exit 3) — armor adds no integrity of its own.
  def test_tampered_armored_payload_is_auth_failure
    cipher = armor_fixture("tamper.asc")
    flip_armor_body_char(cipher)
    res = paladin("-d", cipher, "-o", tmp("o"), "--password-env", "PW",
                   env: { "PW" => DEFAULT_PASSWORD })
    assert_failure res, 3, "authentication failed"
  end

  # The reader tolerates surrounding/extra whitespace and CRLF endings yet still
  # authenticates and decrypts (DESIGN §5.6 leniency).
  def test_lenient_whitespace_still_decrypts
    cipher = armor_fixture("lenient.asc")
    text   = File.binread(cipher)
    padded = "\n  \n#{text.gsub("\n", "\r\n")}\n\t\n" # leading/trailing ws + CRLF
    messy  = write_input("messy.asc", padded)

    out = tmp("lenient.out")
    dec = paladin("-d", messy, "-o", out, "--password-env", "PW",
                   env: { "PW" => DEFAULT_PASSWORD })
    assert_status dec, 0
    assert_identical Paladin::LOREM, out
  end

  private

  # Produce an armored container of the LOREM fixture; returns its path.
  def armor_fixture(name)
    cipher = tmp(name)
    res = paladin("-e", Paladin::LOREM, "-o", cipher, "-a", *FAST_KDF,
                   "--password-env", "PW", env: { "PW" => DEFAULT_PASSWORD })
    assert_status res, 0, "armor_fixture setup failed: #{res.stderr}"
    cipher
  end

  # Flip the first base64 char of the last body line (just before END). That maps
  # into the trailing ciphertext/tag — never the header or base64 padding — so it
  # is a clean auth failure rather than a malformed-header error.
  def flip_armor_body_char(path)
    lines = File.binread(path).split("\n")
    end_idx = lines.index { |l| l.strip == END_MARKER }
    body_idx = end_idx - 1
    line = lines[body_idx].dup
    line[0] = (line[0] == "A" ? "B" : "A")
    lines[body_idx] = line
    File.binwrite(path, "#{lines.join("\n")}\n")
    path
  end
end
