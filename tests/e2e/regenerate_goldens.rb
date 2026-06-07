#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Regenerate the backward-compatibility goldens in tests/fixtures/golden/.
#
# This is a DELIBERATE, REVIEWED step — goldens exist to catch accidental
# on-disk-format changes, so they must never be overwritten casually. The script
# refuses to clobber existing goldens unless you pass --force, and it prints a
# git diff hint so the regeneration lands in a reviewable commit.
#
#   ruby tests/e2e/regenerate_goldens.rb           # create goldens (won't clobber)
#   ruby tests/e2e/regenerate_goldens.rb --force   # intentionally rewrite them
#   SYMCRYPT_BIN=target/release/symcrypt ruby tests/e2e/regenerate_goldens.rb
#
# Ciphertext is non-deterministic (random salt/nonce per file), so regenerating
# changes the bytes every time; that is expected. The test never compares bytes —
# it decrypts with the fixed password and checks the result + header metadata.

require "open3"
require_relative "golden_manifest"

force = ARGV.include?("--force")

unless File.executable?(Golden.binary)
  warn "symcrypt binary not found at #{Golden.binary}"
  warn "build it first:  cargo build -p symcrypt-cli   (or set SYMCRYPT_BIN)"
  exit 1
end

unless File.file?(Golden::PLAINTEXT)
  warn "canonical plaintext missing: #{Golden::PLAINTEXT}"
  exit 1
end

existing = Golden.manifest.map { |g| g[:path] }.select { |p| File.exist?(p) }
if existing.any? && !force
  warn "Refusing to overwrite #{existing.size} existing golden(s):"
  existing.each { |p| warn "  #{p}" }
  warn "Re-run with --force to deliberately regenerate them."
  exit 1
end

def run!(args, stdin: nil)
  out, err, status = Open3.capture3(
    { "GPW" => Golden::PASSWORD }, Golden.binary, *args,
    stdin_data: stdin.nil? ? "" : stdin, binmode: true
  )
  return if status.exitstatus.zero?

  warn "golden generation failed (exit #{status.exitstatus}): symcrypt #{args.join(' ')}"
  warn err
  warn out
  exit 1
end

Golden.manifest.each do |g|
  # -f lets symcrypt overwrite an existing golden; the script-level --force guard
  # above is what actually decides whether we regenerate at all.
  base = %W[--cipher #{g[:cipher]} --kdf #{g[:kdf]}] + g[:cost] + %w[--password-env GPW -f]
  base << "-a" if g[:armored]
  if g[:from_stdin]
    # Encrypt from stdin: no input path, so no original filename is stored.
    run!(["-e", "-", "-o", g[:path], *base], stdin: File.binread(Golden::PLAINTEXT))
  else
    run!(["-e", Golden::PLAINTEXT, "-o", g[:path], *base])
  end
  puts "wrote #{g[:file]}  (#{File.size(g[:path])} B, #{g[:cipher]} / #{g[:kdf]})"
end

puts
puts "Generated #{Golden.manifest.size} goldens in #{Golden::DIR}"
puts "Review and commit them deliberately, e.g.:"
puts "  git add tests/fixtures/golden && git status"
