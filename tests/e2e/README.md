# symcrypt CLI — end-to-end test suite

Black-box tests that drive the **real built `symcrypt` binary** the way a user
would from a shell: encrypting and decrypting real files, exercising password
and keyfile plumbing, shell pipelines, exit codes, and the on-disk format.

## Scope (and how it differs from the Rust tests)

The `symcrypt-cli` crate already has in-process `assert_cmd` integration tests
(`crates/symcrypt-cli/tests/it_*.rs`) covering cipher, flags, info, IO errors,
round-trip, secret handling, and stdio. This suite is **complementary** — it
covers what only an external, full-binary test can:

- the compiled binary as invoked from a shell (args, env vars, exit codes);
- real shell pipelines / redirection (`… | symcrypt -e - | symcrypt -d - > out`);
- password sources on the real filesystem (`--password-file`, `--password-env`);
- armored output inspected with shell tooling;
- large / binary / chunk-boundary inputs end-to-end;
- committed "golden" ciphertexts for file-format backward-compatibility;
- an exit-code matrix usable as a release smoke test.

Prefer user-visible behavior over re-proving the fine-grained Rust assertions.

## Layout

| Path                              | Purpose                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------- |
| `run.sh`                          | Build the CLI (unless `SYMCRYPT_BIN` is set), then run the suite.                |
| `runner.rb`                       | Pure-Ruby runner: loads every case and lets minitest run them.                   |
| `test_helper.rb`                  | Base `E2ETest` class: per-test temp dir, the `symcrypt` runner, and assertions.  |
| `cases/`                          | The test files (`*_test.rb`). Empty for now — fill these in.                     |
| `templates/example_test.rb.tmpl`  | Copy-me starting point (not collected as a test).                                |
| `../fixtures/`                    | Committed inputs (`LOREM_IPSUM.txt`) and `golden/` ciphertexts.                  |

There is no Rakefile on purpose: this environment ships no `rake` gem. The runner
is plain Ruby and needs only stdlib — `minitest`, `open3`, `tmpdir`, `fileutils`.

## Running

```sh
make e2e                          # build + run everything (from the repo root)
make e2e ARGS="-n /round_trip/"   # filter by test name

# …or call the runner directly:
tests/e2e/run.sh                  # build + run everything
tests/e2e/run.sh -n /round_trip/  # filter by test name (minitest passthrough)
SYMCRYPT_BIN=target/release/symcrypt tests/e2e/run.sh   # test a release build
```

## Adding a case

1. `cp templates/example_test.rb.tmpl cases/<area>_test.rb`
2. Subclass `E2ETest` and write `test_*` methods.
3. Use the provided helpers instead of re-rolling them:
   - `symcrypt(*args, stdin:, env:)` → `Result(status, stdout, stderr)`
   - `tmp(name)`, `write_input`, `make_input(name, size)`, `make_keyfile`
   - `flip_byte`, `truncate_input` (tamper / truncate cases)
   - `assert_size_grew`, `assert_identical`, `assert_status`
   - constants: `Symcrypt::LOREM`, `Symcrypt::GOLDEN_DIR`, `DEFAULT_PASSWORD`, `CHUNK`
4. Each test gets a fresh temp dir (`@tmpdir`), removed automatically on teardown.

## Conventions

- Supply passwords non-interactively (`--password-env`, `--password-file`, `-p`).
  Prefer `--password-env` so secrets never appear in the process argument list.
- Never write outputs next to committed fixtures; use `tmp(...)`. On decrypt,
  pass `--output` so the filename restored from the header can't clobber one.
- Generate sized / binary inputs at runtime; commit only small `golden/` files.

## Planned cases

`roundtrip · cipher · kdf · armor · password_sources · keyfile · streaming ·
info_verify · clobber_remove · failures (exit-code matrix) · backward_compat`

`cases/roundtrip_test.rb` will absorb the assertions currently in the top-level
`tests/roundtrip_cli.sh`; once it does, that standalone script can be removed.
