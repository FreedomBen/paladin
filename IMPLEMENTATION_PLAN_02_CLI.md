# symcrypt — Implementation plan 02: CLI (`symcrypt`)

**Status:** Stub. Not yet expanded — [DESIGN.md](DESIGN.md) is still being
iterated on. This file collects the implementation-checklist items for the
command-line front-end, copied verbatim from DESIGN.md so no planning work is
lost. It will be turned into detailed, ordered steps once the design stabilizes.

**Scope.** The `symcrypt` binary — a thin front-end that parses arguments,
resolves the password, opens streams, calls `symcrypt-core`, and maps results to
exit codes (DESIGN §6). It holds no crypto or format logic.

**Depends on:** [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)
— `symcrypt-core` and the `symcrypt-common` terminal glue.

---

## Checklist

- [ ] `symcrypt` (cli): arg parsing (clap) and mode dispatch.
- [ ] `symcrypt` (cli): password resolution (flag/file/env/prompt + confirm) and keyfile.
- [ ] `symcrypt` (cli): encrypt/decrypt/info/verify; output defaults; clobber; remove.
- [ ] `symcrypt` (cli): progress bar; verbosity; exit codes.
- [ ] `symcrypt` (cli): integration tests.
- [ ] Docs: `symcrypt` `--help` text and man page.
- [ ] Packaging: `cargo install` for `symcrypt`.
