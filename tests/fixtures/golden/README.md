# Golden ciphertexts (on-disk format lock)

These files are **committed ciphertexts** produced by a known `paladin` build.
The end-to-end suite (`tests/e2e/cases/backward_compat_test.rb`) decrypts them on
every run, so if a future change alters the on-disk format
(`docs/DESIGN.md` §5) in a way that breaks old files, a test fails instead of the
breakage shipping silently.

## What's here

| File                                  | Cipher            | KDF      | Notes                          |
| ------------------------------------- | ----------------- | -------- | ------------------------------ |
| `plaintext.txt`                       | —                 | —        | Canonical plaintext (the source) |
| `aes-256-gcm.argon2id.paladin`       | aes-256-gcm       | argon2id | default costs                  |
| `aes-256-gcm.scrypt.paladin`         | aes-256-gcm       | scrypt   | default costs                  |
| `aes-256-gcm.pbkdf2.paladin`         | aes-256-gcm       | pbkdf2   | default costs                  |
| `chacha20-poly1305.argon2id.paladin` | chacha20-poly1305 | argon2id | default costs                  |
| `chacha20-poly1305.scrypt.paladin`   | chacha20-poly1305 | scrypt   | default costs                  |
| `chacha20-poly1305.pbkdf2.paladin`   | chacha20-poly1305 | pbkdf2   | default costs                  |
| `armored.paladin.asc`                | aes-256-gcm       | argon2id | ASCII-armored                  |
| `stdin_no_name.paladin`              | aes-256-gcm       | pbkdf2   | encrypted from stdin; no stored filename |

Each ciphertext decrypts to `plaintext.txt`. They are generated with **default
KDF costs**, so the test also pins the shipped defaults
(`docs/DESIGN.md` §12).

## Fixed parameters

- **Password:** `paladin golden v1` (public on purpose — these files protect
  nothing; they exist only to be decrypted by the test).
- **Plaintext:** `plaintext.txt` in this directory.

The password and the golden manifest are defined once in
`tests/e2e/golden_manifest.rb`, shared by the test and the regeneration script.

## Regenerating (deliberate, reviewed)

Do **not** regenerate casually — the whole point is that these bytes are stable.
Regenerate only when you have intentionally changed the format or defaults, and
land the result in its own reviewed commit:

```sh
cargo build -p paladin-cli
ruby tests/e2e/regenerate_goldens.rb --force   # --force is required to overwrite
git add tests/fixtures/golden && git diff --cached --stat
```

Ciphertext is non-deterministic (random salt/nonce per file), so the bytes change
on every regeneration; that is expected. The test never compares raw bytes — it
decrypts with the fixed password and checks the plaintext plus the `--info`
metadata.
