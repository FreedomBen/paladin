# frozen_string_literal: true
#
# Single source of truth for the backward-compatibility goldens (DESIGN §5 format
# lock): the fixed password, the canonical plaintext, and the manifest of golden
# files with the cipher/KDF/params each must report. Required by BOTH the
# regeneration script (regenerate_goldens.rb) and the test
# (cases/backward_compat_test.rb) so the generator and the checker can never
# drift. Plain Ruby — no minitest — so the generator can load it standalone.

module Golden
  DIR       = File.expand_path("../fixtures/golden", __dir__) # tests/e2e -> tests/fixtures/golden
  PLAINTEXT = File.join(DIR, "plaintext.txt")
  # Fixed password for every golden. Public on purpose: these files exist only to
  # be decrypted by the test, never to protect anything.
  PASSWORD = "symcrypt golden v1"

  CIPHERS = %w[aes-256-gcm chacha20-poly1305].freeze
  KDFS    = %w[argon2id scrypt pbkdf2].freeze

  # Fixed REDUCED KDF costs. The goldens lock the on-disk *format* (field layout,
  # ids, STREAM framing) — not production cost config — so they deliberately use
  # the cheapest valid costs to keep decrypting them fast, even against a debug
  # build where memory-hard KDFs are slow. (The shipped defaults are pinned by the
  # core unit tests and the real-Argon2id roundtrip case.)
  COSTS = {
    "argon2id" => %w[--argon2-memory 8192 --argon2-time 1 --argon2-parallelism 1],
    "scrypt"   => %w[--scrypt-log-n 10 --scrypt-r 1 --scrypt-p 1],
    "pbkdf2"   => %w[--pbkdf2-iterations 10000],
  }.freeze

  # The `--info` rendering of COSTS above, used by the test to assert each header.
  PARAMS = {
    "argon2id" => "memory=8192,time=1,parallelism=1",
    "scrypt"   => "log_n=10,r=1,p=1",
    "pbkdf2"   => "iterations=10000",
  }.freeze

  # The full golden set: the cipher × KDF matrix, one armored file, and one
  # stdin-encrypted file (which stores no original filename). Each entry says what
  # `--info` must report so the test can assert it.
  def self.manifest
    matrix = CIPHERS.product(KDFS).map do |cipher, kdf|
      entry("#{cipher}.#{kdf}.symcrypt", cipher, kdf)
    end
    matrix + [
      entry("armored.symcrypt.asc", "aes-256-gcm", "argon2id", armored: true),
      entry("stdin_no_name.symcrypt", "aes-256-gcm", "pbkdf2", from_stdin: true),
    ]
  end

  def self.entry(file, cipher, kdf, armored: false, from_stdin: false)
    {
      file: file, path: File.join(DIR, file),
      cipher: cipher, kdf: kdf, params: PARAMS.fetch(kdf), cost: COSTS.fetch(kdf),
      armored: armored, from_stdin: from_stdin,
      name_status: "absent", # --name is off by default and never used here
    }
  end

  # The CLI binary under test (shared resolution with the e2e harness).
  def self.binary
    ENV["SYMCRYPT_BIN"] || File.expand_path("../../target/debug/symcrypt", __dir__)
  end
end
