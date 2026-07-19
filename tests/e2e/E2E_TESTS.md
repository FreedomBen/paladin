# paladin CLI — E2E test backlog

The backlog of end-to-end cases for the Ruby/minitest suite in `tests/e2e/`.
Each planned `cases/<name>_test.rb` is a section below; check items off as they
land. See `README.md` for how to run the suite and add a case.

**Status:** the backlog below is fully implemented. Every section maps to a
`cases/*_test.rb` file; the advanced cases are opt-in (see the last section).

**Ground rules**

- Black-box only: drive the real built binary via the `paladin` helper. Don't
  re-prove the in-process Rust assertions in `crates/paladin-cli/tests/it_*.rs`
  (cipher, flags, info, io_errors, roundtrip, secret, stdio) — cover what only a
  full-binary shell test can.
- Reuse `E2ETest` helpers: `paladin`, `make_input`/`write_input`, `flip_byte`,
  `set_byte`, `truncate_input`, `assert_status`, `assert_failure`,
  `assert_size_grew`, `assert_identical`, and constants `DEFAULT_PASSWORD`,
  `CHUNK`, `FAST_KDF`.
- Use `FAST_KDF` unless the KDF itself is under test. Decrypt/verify/info are
  header-driven — never pass cipher/KDF flags to them (they're rejected, exit 2).

**Legend:** `[x]` done · `[ ]` to do · ⚠ resolved-against-binary note.

**Exit codes** (`paladin-common/src/error.rs`)

| Code | Meaning              | Example trigger                                                   |
| ---: | -------------------- | ---------------------------------------------------------------- |
|    0 | success              | any successful operation                                         |
|    1 | general / I/O        | output directory missing, write failure, unreadable input        |
|    2 | usage                | bad flags, refuse-to-overwrite, missing/non-regular input, bad options |
|    3 | auth failure         | wrong password / tampered / truncated (indistinguishable)       |
|    4 | unsupported format   | bad magic, unknown version/cipher/kdf id, reserved flag bits     |
|  130 | canceled             | SIGINT mid-operation                                            |

---

## Done (for context)

- [x] **roundtrip** (`cases/roundtrip_test.rb`) — fixture round-trip on defaults,
  size sweep across the 64 KiB chunk boundary (incl. empty), default `.paladin` name.
- [x] **failures** (`cases/failures_test.rb`) — exit-code matrix: auth (3),
  format/version (4), refuse-to-overwrite / missing-input / usage / bad-options (2).

---

## cipher — `cases/cipher_test.rb` ✅

Cipher selection and header authority (`-c/--cipher`: `aes-256-gcm` default,
`chacha20-poly1305`).

- [x] Round-trip with `--cipher chacha20-poly1305` (and explicit `aes-256-gcm`).
- [x] Header-driven decrypt: encrypt with either cipher, decrypt with no `-c` → success.
- [x] ⚠ Decrypt **rejects** a mismatched `-c` (exit 2, "apply only to encrypt") —
  the flag is *not* silently ignored; the authenticated header alone decides.
- [x] `--info` reports the correct cipher name for each.
- [x] Invalid cipher name (`--cipher rot13`) → exit 2.
- [x] Both ciphers round-trip across a multi-chunk size.

## kdf — `cases/kdf_test.rb` ✅

KDF selection and cost parameters (`--kdf argon2id|scrypt|pbkdf2`).

- [x] Round-trip with each KDF: `argon2id` (default), `scrypt`, `pbkdf2`.
- [x] Header-driven decrypt for each (no `--kdf` on decrypt).
- [x] `--info` reports the KDF name and its stored parameters for each.
- [x] Custom cost round-trips and shows in `--info` (argon2id, scrypt, pbkdf2 knobs).
- [x] Default KDF (no `--kdf`) is argon2id.
- [x] ⚠ Out-of-range cost → exit 2. Bounds (DESIGN §5.4): argon2 memory
  `8192..=1048576` KiB, time `1..=10`, parallelism `1..=16`; scrypt log_n
  `10..=20`, r `1..=32`, p `1..=16`; pbkdf2 `10000..=10000000`.
- [x] Cost flag without its `--kdf` → exit 2 (argon2 knobs are exempt: argon2id is default).
- [x] Invalid KDF name (`--kdf bcrypt`) → exit 2.

## armor — `cases/armor_test.rb` ✅

ASCII armor (`-a/--armor`; decrypt/verify/info auto-detect).

- [x] Armored round-trip: `-a` encrypt → decrypt (auto-detect) → identical.
- [x] Armored output is 7-bit printable ASCII (only LF + `0x20..0x7e`).
- [x] ⚠ Banner lines are exactly `-----BEGIN PALADIN MESSAGE-----` /
  `-----END PALADIN MESSAGE-----` (64-column base64 body, LF endings).
- [x] Default armored output name is `<input>.paladin.asc` (DESIGN §6.5).
- [x] `--info` on an armored file works (auto-detect).
- [x] Armor to stdout (`-a -o -`) emits text; round-trips back through `-d -`.
- [x] Armored multi-chunk file round-trips.
- [x] Tampered armored payload (flip a base64 char in the last body line) → exit 3.
- [x] ⚠ Leniency: leading/trailing whitespace + CRLF still decrypts.

## password_sources — `cases/password_sources_test.rb` ✅

`-p/--password`, `--password-file`, `--password-env`.

- [x] Round-trip with `-p` inline and with `--password-file`.
- [x] Interop: encrypt with one source, decrypt with another holding the same secret.
- [x] `--password-file` trims exactly one trailing newline (`"pw\n"` == `"pw"`).
- [x] Password mismatch → exit 3.
- [x] Password with spaces / unicode round-trips (delivered via env).
- [x] ⚠ Multiple sources at once → exit 2 ("at most one of …").
- [x] ⚠ Empty `--password-file` (0 bytes) → exit 2 (use `--no-password` for empty).

## keyfile — `cases/keyfile_test.rb` ✅

`-k/--keyfile` combined with the password source; `--no-password`.

- [x] Round-trip with `-k keyfile -p pw`.
- [x] Round-trip with `-k keyfile --no-password` (keyfile-only).
- [x] Wrong keyfile → exit 3.
- [x] Missing keyfile (encrypted with one, decrypt without `-k`) → exit 3; with both → success.
- [x] `-k -` (keyfile from stdin) is rejected → exit 2.
- [x] Missing keyfile path → exit 2.
- [x] Two different keyfiles yield different keys (each decrypts only with its own).

## streaming — `cases/streaming_test.rb` ✅

stdin/stdout via `-` (DESIGN §6.5).

- [x] Full pipe round-trip: `-e - -o -` (stdin→stdout) into `-d - -o -`.
- [x] Encrypt file → stdout (`-o -`); decrypt that stream back.
- [x] Decrypt from stdin (`-d -`).
- [x] Stdin input stores no filename: `--info` shows `name_status: absent`;
  decrypting from stdin needs `-o` (exit 2 otherwise).
- [x] Armored streaming (`-e - -a -o -`).
- [x] Multi-chunk input through the pipe round-trips.
- [x] `-q` keeps stdout pure (ciphertext only; nothing on stderr).

## info_verify — `cases/info_verify_test.rb` ✅

`-i/--info` (no password) and `--verify` (decrypt-and-discard).

- [x] `--info` prints the documented fields (format/version/cipher/kdf/params/
  chunk_size/name_status …); exit 0. Exact 12-line block is pinned by it_info.rs.
- [x] `--info` needs no password and writes nothing.
- [x] ⚠ `--info` reports the stored original filename only with `--name`
  (filename storage is off by default).
- [x] `--verify` with the correct password → exit 0.
- [x] `--verify` writes no output file (asserted: temp dir unchanged).
- [x] `--verify` on a tampered file → exit 3.
- [x] `--info` / `--verify` on an armored file (auto-detect) → exit 0.

## remove — `cases/remove_test.rb` ✅

`--remove` (plain delete of the input after success).

- [x] `--remove` deletes the input after a successful encrypt (output present).
- [x] `--remove` deletes the input after a successful decrypt.
- [x] `--remove` does NOT delete the input on auth failure (wrong password, exit 3).
- [x] `--remove` does NOT delete the input on refuse-to-overwrite (exit 2).
- [x] ⚠ `--remove` with stdin input is a usage error (exit 2), **not** a no-op
  (rejected in validation: "there is no input file to remove").

## io_errors — `cases/io_errors_test.rb` ✅

Real-filesystem error paths (covers exit **1**, the one code the matrix doesn't hit).

- [x] ⚠ Output into a non-existent directory → exit 1 (sibling temp can't be created).
- [x] ⚠ Unreadable input (chmod 000) → exit 1 (skipped as root).
- [x] ⚠ Non-regular input (a directory) → exit 2 (require_regular_file).
- [x] ⚠ Write into a read-only target dir → exit 1 (skipped as root).

## backward_compat — `cases/backward_compat_test.rb` ✅

Locks the on-disk format: decrypt committed ciphertexts produced by this version
so future changes can't silently break old files. Goldens live in
`tests/fixtures/golden/`; the manifest + fixed password are in
`tests/e2e/golden_manifest.rb`; regenerate with `tests/e2e/regenerate_goldens.rb`.

- [x] Goldens committed: cipher × KDF (6), one armored (`.asc`), one stdin-encrypted
  (no filename). ⚠ They decrypt to a small fixed `golden/plaintext.txt` — **not**
  the 300 KiB `LOREM_IPSUM.txt` — to honor "commit only small golden files", and
  use fixed reduced KDF costs so decrypting them is fast even in debug builds.
- [x] Decrypt each golden with the known password → matches the expected plaintext.
- [x] `--info` on each golden reports its expected cipher/KDF/params/name_status.
- [x] Wrong password against a golden → exit 3.
- [x] Deliberate regeneration step documented (`golden/README.md`); the script
  refuses to overwrite without `--force` (never auto-overwrites goldens).

## interop_fixtures — `cases/interop_fixtures_test.rb` ✅

Committed **full-size** (~294 KiB) ciphertexts of `tests/fixtures/LOREM_IPSUM.txt`,
minted by real tool runs with the fixed public password `password`:
`LOREM_IPSUM.txt.aes` by the genuine AES Crypt CLI (`aescrypt 3.16.1`, Stream
Format 2) and `LOREM_IPSUM.txt.paladin` by the paladin CLI at shipped defaults
(aes-256-gcm, argon2id `memory=65536,time=3,parallelism=1`). Provenance and
regeneration: `tests/fixtures/README.md`.

- [x] `.aes` decrypts byte-for-byte to `LOREM_IPSUM.txt` — AES Crypt interop at
  scale (the committed Rust `.aes` fixtures are ≤ 3000 B; this is thousands of
  CBC blocks plus the final padding/HMAC path, through the real binary).
- [x] `.paladin` decrypts byte-for-byte — a multi-chunk body at the shipped
  DEFAULT KDF costs (the goldens use reduced costs and a small plaintext).
- [x] `--info` on each is **byte-exact** (no password): locks the aescrypt
  `created_by`/`extensions` fields and the defaults recorded in the container.
- [x] `--verify` accepts both fixtures with the fixed password.
- [x] Wrong password → exit 3 for **both** formats (unified auth failure), and
  no output file remains.

## cross-cutting — `cases/misc_test.rb` ✅

- [x] ⚠ **Header is authenticated / no downgrade:** swap a structurally-valid
  field (cipher id `0x01`→`0x02`, via `set_byte`) → `--info` still parses but
  decrypt fails authentication (**exit 3**, the whole header is AEAD AAD).
- [x] **Reserved flag bits** set → exit 4 (`reserved flags bit set`), even from `--info`.
- [x] **Fresh randomness:** encrypting the same input twice yields different
  ciphertext, yet both decrypt (random salt/nonce per file).
- [x] **Quiet:** `-q` produces no stderr chatter on success.
- [x] **`--help` / `--version`** → exit 0 with expected text.

## advanced / optional — `cases/advanced_test.rb` (opt-in: `PALADIN_E2E_SLOW=1`) ✅

Skipped by default so the suite stays fast/deterministic.

- [x] **Cancellation (exit 130):** SIGINT a streaming encrypt (endless `/dev/zero`
  input) → exit 130 and the partial output is removed.
- [x] **Large-file smoke** (8 MiB) round-trip.

---

## Gotchas already learned

- Tamper the **body's final tag** for exit 3; a corrupted header field is a
  distinct exit 4 (`malformed header`), so fixed header offsets are brittle.
- For a **downgrade** test, `set_byte` a header field to another *valid* value
  (e.g. cipher id `0x01`→`0x02`): the header still parses (so `--info` succeeds),
  but decrypt is exit **3** because the serialized header is chunk-0 AAD.
- The magic is 8 bytes (`PALADIN`); the version byte is at offset 8 and is
  checked first — flipping it gives exit 4 even from `--info` (no password).
  The cipher id is offset 9, the kdf id offset 10, the flags byte offset 11.
- Decrypt/verify/info are **header-driven**: passing `-c`/`--kdf`/`-a`/`--name`
  to them is a usage error (exit 2, "apply only to encrypt"), not a no-op.
- `--remove` with stdin input is a usage error (exit 2), not a silent no-op.
- The output target must be a **regular file**: `/dev/null` (or any non-regular
  path) is rejected (exit 2). Always write outputs to a real temp file.
- Filename storage is **off by default**; `--info` shows `name_status: absent`
  unless the file was encrypted with `--name`.
- `--pbkdf2-iterations` is bounded to `10000..=10_000_000`; out of range → exit 2.
- Refuse-to-overwrite is exit **2** (not 1) and leaves the existing file untouched.
- Missing input file is exit **2** (usage), not exit 1.
