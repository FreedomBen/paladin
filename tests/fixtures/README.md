# Committed test fixtures

Inputs and ciphertexts used by the end-to-end suite (`tests/e2e/`). The
`golden/` subdirectory (small format-lock ciphertexts) has its own
[README](golden/README.md).

## Files

| File                      | What it is                                                                                                                    |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `LOREM_IPSUM.txt`         | Canonical ~294 KiB plaintext input, also used by the round-trip cases.                                                          |
| `LOREM_IPSUM.txt.aes`     | `LOREM_IPSUM.txt` encrypted by the genuine AES Crypt CLI (`aescrypt 3.16.1`, Stream Format 2).                                  |
| `LOREM_IPSUM.txt.paladin` | `LOREM_IPSUM.txt` encrypted by the paladin CLI at shipped defaults (aes-256-gcm, argon2id `memory=65536,time=3,parallelism=1`). |
| `golden/`                 | Small format-lock ciphertexts — see `golden/README.md`.                                                                         |

## The interop ciphertexts

- **Password:** `password` (public on purpose — these files protect nothing;
  they exist only to be decrypted by the tests).
- `tests/e2e/cases/interop_fixtures_test.rb` decrypts both on every e2e run and
  byte-compares the result against `LOREM_IPSUM.txt`; it also pins each file's
  `--info` block byte-exact and checks `--verify` and the wrong-password path.
- Unlike the `golden/` files they are full-size (a multi-chunk paladin body;
  thousands of AES Crypt CBC blocks) and the `.aes` one was minted by a
  foreign tool, so the test harness cannot regenerate them.

### Regenerating (deliberate, reviewed)

Do **not** regenerate casually: ciphertext is non-deterministic (fresh
salt/IV/nonce per run), and the `.aes` file's value is precisely that a *real*
AES Crypt build produced it. If a regeneration is ever needed:

```sh
cd tests/fixtures
aescrypt -e -p password LOREM_IPSUM.txt        # writes LOREM_IPSUM.txt.aes
PW=password paladin -e LOREM_IPSUM.txt --password-env PW   # writes LOREM_IPSUM.txt.paladin
```

Then, if the minting tool or the shipped defaults changed, update the pinned
`--info` blocks (`created_by`, KDF params) in
`tests/e2e/cases/interop_fixtures_test.rb`, and land the new bytes in their own
reviewed commit.
