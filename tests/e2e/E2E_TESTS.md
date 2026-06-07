# symcrypt CLI — E2E test backlog

The backlog of end-to-end cases for the Ruby/minitest suite in `tests/e2e/`.
Each planned `cases/<name>_test.rb` is a section below; check items off as they
land. See `README.md` for how to run the suite and add a case.

**Ground rules**

- Black-box only: drive the real built binary via the `symcrypt` helper. Don't
  re-prove the in-process Rust assertions in `crates/symcrypt-cli/tests/it_*.rs`
  (cipher, flags, info, io_errors, roundtrip, secret, stdio) — cover what only a
  full-binary shell test can.
- Reuse `E2ETest` helpers: `symcrypt`, `make_input`/`write_input`, `flip_byte`,
  `truncate_input`, `assert_status`, `assert_size_grew`, `assert_identical`,
  and constants `DEFAULT_PASSWORD`, `CHUNK`, `FAST_KDF`.
- Use `FAST_KDF` unless the KDF itself is under test. Decrypt/verify/info are
  header-driven — never pass cipher/KDF flags to them.

**Legend:** `[x]` done · `[ ]` to do · ⚠ needs a fixture or a confirm-against-binary step first.

**Exit codes** (`symcrypt-common/src/error.rs`)

| Code | Meaning              | Example trigger                                                   |
| ---: | -------------------- | ---------------------------------------------------------------- |
|    0 | success              | any successful operation                                         |
|    1 | general / I/O        | output directory missing, write failure                         |
|    2 | usage                | bad flags, refuse-to-overwrite, missing input, bad options      |
|    3 | auth failure         | wrong password / tampered / truncated (indistinguishable)       |
|    4 | unsupported format   | bad magic, unknown version/cipher/kdf id, reserved flag bits    |
|  130 | canceled             | SIGINT mid-operation                                            |

---

## Done (for context)

- [x] **roundtrip** (`cases/roundtrip_test.rb`) — fixture round-trip on defaults,
  size sweep across the 64 KiB chunk boundary (incl. empty), default `.symcrypt` name.
- [x] **failures** (`cases/failures_test.rb`) — exit-code matrix: auth (3),
  format/version (4), refuse-to-overwrite / missing-input / usage / bad-options (2).

---

## cipher — `cases/cipher_test.rb`

Cipher selection and header authority (`-c/--cipher`: `aes-256-gcm` default,
`chacha20-poly1305`).

- [ ] Round-trip with `--cipher chacha20-poly1305`.
- [ ] Round-trip with explicit `--cipher aes-256-gcm`.
- [ ] Header-driven decrypt: encrypt with chacha20, decrypt with no `-c` → success.
- [ ] Decrypt ignores a mismatched `-c` (decrypt a chacha file while passing
  `-c aes-256-gcm`) — ⚠ confirm the flag is ignored on decrypt, header wins.
- [ ] `--info` reports the correct cipher name for each.
- [ ] Invalid cipher name (`--cipher rot13`) → exit 2.
- [ ] Both ciphers round-trip across a multi-chunk size.

## kdf — `cases/kdf_test.rb`

KDF selection and cost parameters (`--kdf argon2id|scrypt|pbkdf2`).

- [ ] Round-trip with each KDF: `argon2id` (default), `scrypt`, `pbkdf2`.
- [ ] Header-driven decrypt for each (no `--kdf` on decrypt).
- [ ] `--info` reports the KDF name and its stored parameters for each.
- [ ] Custom Argon2id cost round-trips and shows in `--info`
  (`--argon2-memory`, `--argon2-time`, `--argon2-parallelism`).
- [ ] Custom scrypt cost round-trips (`--scrypt-log-n`, `--scrypt-r`, `--scrypt-p`).
- [ ] Custom `--pbkdf2-iterations` round-trips and shows in `--info`.
- [ ] Out-of-range cost → exit 2 (pbkdf2 < 10000 or > 10_000_000; ⚠ find argon2/scrypt bounds).
- [ ] Cost flag without its `--kdf` → exit 2 (e.g. `--pbkdf2-iterations` sans `--kdf pbkdf2`).
- [ ] Invalid KDF name (`--kdf bcrypt`) → exit 2.

## armor — `cases/armor_test.rb`

ASCII armor (`-a/--armor`; decrypt/verify/info auto-detect).

- [ ] Armored round-trip: `-a` encrypt → decrypt (auto-detect) → identical.
- [ ] Armored output is 7-bit printable ASCII (no byte > 0x7e besides newlines).
- [ ] Armored output has the expected BEGIN/END banner lines — ⚠ confirm exact
  marker text from core.
- [ ] Default armored output name is `<input>.symcrypt.asc` (DESIGN §6.5).
- [ ] `--info` on an armored file works (auto-detect).
- [ ] Armor to stdout (`-a -o -`) emits text; round-trips back through `-d -`.
- [ ] Armored multi-chunk file round-trips.
- [ ] Tampered armored payload (flip a base64 char in the body) → exit 3.
- [ ] ⚠ Confirm leniency: surrounding whitespace / extra trailing newline still decrypts.

## password_sources — `cases/password_sources_test.rb`

`-p/--password`, `--password-file`, `--password-env`.

- [ ] Round-trip with `-p` inline.
- [ ] Round-trip with `--password-file`.
- [ ] Interop: encrypt with one source, decrypt with another holding the same secret.
- [ ] `--password-file` trims exactly one trailing newline (`"pw\n"` == `"pw"`):
  encrypt with the newline file, decrypt with an inline `pw`.
- [ ] Password mismatch → exit 3 (encrypt `-p a`, decrypt `-p b`).
- [ ] Password with spaces / unicode round-trips (deliver via env or file).
- [ ] ⚠ Confirm behavior when multiple sources are given at once (conflict vs precedence).
- [ ] ⚠ Confirm empty `--password-file` (0 bytes) behavior (empty password → needs `-k`?).

## keyfile — `cases/keyfile_test.rb`

`-k/--keyfile` combined with the password source; `--no-password`.

- [ ] Round-trip with `-k keyfile -p pw`.
- [ ] Round-trip with `-k keyfile --no-password` (keyfile-only).
- [ ] Wrong keyfile → exit 3.
- [ ] Missing keyfile (encrypted with one, decrypt without `-k`) → exit 3.
- [ ] Keyfile is combined with the password: `-k`+`-p` to encrypt, decrypt with
  only `-p` (no keyfile) → exit 3; with both → success.
- [ ] `-k -` (keyfile from stdin) is rejected → exit 2.
- [ ] Missing keyfile path → exit 2.
- [ ] Two different keyfiles yield different keys (each decrypts only with its own).

## streaming — `cases/streaming_test.rb`

stdin/stdout via `-` (DESIGN §6.5).

- [ ] Full pipe round-trip: `-e - -o -` (stdin→stdout) piped into `-d - -o -`.
- [ ] Encrypt file → stdout (`-o -`); decrypt that stream back.
- [ ] Decrypt from stdin (`-d -` with ciphertext on stdin) → plaintext.
- [ ] Stdin input stores no filename: `--info` shows none/empty; decrypt needs `-o`.
- [ ] Armored streaming (`-e - -a -o -`).
- [ ] Multi-chunk input through the pipe round-trips.
- [ ] `-q` keeps stdout pure (ciphertext only; no status leaks onto stdout).
- [ ] ⚠ Confirm `--info` / `-` from stdin behavior.

## info_verify — `cases/info_verify_test.rb`

`-i/--info` (no password) and `--verify` (decrypt-and-discard).

- [ ] `--info` on a valid file prints version, cipher, KDF + params, chunk size,
  and stored filename; exit 0; ⚠ confirm exact field labels to grep.
- [ ] `--info` needs no password and writes nothing.
- [ ] `--info` reports the stored original filename (encrypt `file.txt` → shows `file.txt`).
- [ ] `--verify` with the correct password → exit 0 (and ⚠ confirm any "OK" line).
- [ ] `--verify` writes no output file (assert none created).
- [ ] `--verify` on a tampered file → exit 3.
- [ ] `--info` / `--verify` on an armored file (auto-detect) → exit 0.

## remove — `cases/remove_test.rb`

`--remove` (plain delete of the input after success).

- [ ] `--remove` deletes the input after a successful encrypt (output present).
- [ ] `--remove` deletes the input after a successful decrypt.
- [ ] `--remove` does NOT delete the input on auth failure (wrong password, exit 3).
- [ ] `--remove` does NOT delete the input on refuse-to-overwrite (exit 2).
- [ ] ⚠ Confirm `--remove` with stdin input (nothing to remove) is a no-op, not an error.

## io_errors — `cases/io_errors_test.rb`

Real-filesystem error paths (covers exit **1**, the one code the matrix doesn't hit yet).

- [ ] Output into a non-existent directory → exit 1 (general/I/O). ⚠ confirm 1 vs 2.
- [ ] Unreadable input (chmod 000) → ⚠ confirm exit code (1 or 2).
- [ ] Non-regular input (a directory, or a FIFO) → exit 2 (require_regular_file).
- [ ] Write failure to a read-only target dir → exit 1.

## backward_compat — `cases/backward_compat_test.rb` ⚠ needs golden fixtures

Lock the on-disk format: decrypt committed ciphertexts produced by this version
so future changes can't silently break old files. Store goldens in
`tests/fixtures/golden/`.

- [ ] Generate & commit goldens: one per cipher × KDF, one armored (`.asc`), and
  one stdin-encrypted (no filename). Record the fixed password (and assert the
  plaintext equals `LOREM_IPSUM.txt`).
- [ ] Decrypt each golden with the known password → matches the expected plaintext.
- [ ] `--info` on each golden reports its expected cipher/KDF/params.
- [ ] Wrong password against a golden → exit 3.
- [ ] Document a deliberate, reviewed regeneration step (never auto-overwrite goldens).

## cross-cutting — fold into the most relevant file or a `misc_test.rb`

- [ ] **Header is authenticated / no downgrade:** flip a structurally-valid header
  field (e.g. cipher id) → decrypt fails (the whole header is AEAD AAD). ⚠ confirm 3 vs 4.
- [ ] **Reserved flag bits** set → exit 4 (`reserved flags bit set`).
- [ ] **Fresh randomness:** encrypting the same input twice yields different
  ciphertext, yet both decrypt (random salt/nonce per file).
- [ ] **Quiet:** `-q` produces no extra stderr chatter on success.
- [ ] **`--help` / `--version`** → exit 0 with expected text.

## advanced / optional

- [ ] **Cancellation (exit 130):** SIGINT a large in-progress encrypt → exit 130
  and partial output removed. ⚠ timing-sensitive/flaky; gate or mark slow.
- [ ] **Large-file smoke** (multi-MB) round-trip — ⚠ slow; consider an opt-in env gate.

---

## Gotchas already learned

- Tamper the **body's final tag** for exit 3; a corrupted header field is a
  distinct exit 4 (`malformed header`), so fixed header offsets are brittle.
- The magic is 8 bytes (`SYMCRYPT`); the version byte is at offset 8 and is
  checked first — flipping it gives exit 4 even from `--info` (no password).
- `--pbkdf2-iterations` is bounded to `10000..=10_000_000`; out of range → exit 2.
- Decrypt is header-driven: it ignores/forbids algorithm flags and reads
  everything from the authenticated header.
- Refuse-to-overwrite is exit **2** (not 1) and leaves the existing file untouched.
- Missing input file is exit **2** (usage), not exit 1.
