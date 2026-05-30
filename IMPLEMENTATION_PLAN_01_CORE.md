# symcrypt — Implementation plan 01: core & shared libraries

**Status:** Stub. Not yet expanded — [DESIGN.md](DESIGN.md) is still being
iterated on. This file collects the implementation-checklist items for the
non-UI foundation (the Cargo workspace, `symcrypt-core`, and `symcrypt-common`),
copied verbatim from DESIGN.md so no planning work is lost. It will be turned
into detailed, ordered steps once the design stabilizes.

**Scope.** The Cargo workspace and the two library crates the front-ends build
on: `symcrypt-core` — all crypto, file format, streaming, and pure helpers
(DESIGN §2–§5, §10, §12) — and `symcrypt-common` — terminal glue shared by the
CLI and TUI (DESIGN §2.2, §6.6).

**Sibling plans:** [`IMPLEMENTATION_PLAN_02_CLI.md`](IMPLEMENTATION_PLAN_02_CLI.md),
[`IMPLEMENTATION_PLAN_03_TUI.md`](IMPLEMENTATION_PLAN_03_TUI.md),
[`IMPLEMENTATION_PLAN_04_GTK.md`](IMPLEMENTATION_PLAN_04_GTK.md) — all three
depend on the crates planned here.

---

## Checklist

- [x] Scaffold Cargo workspace + five crates; pin dependencies.
- [x] `core`: error types (`SymError`, `Result`).
- [x] `core`: `Secret` (password + keyfile) with zeroization.
- [x] `core`: cipher dispatch (AES-256-GCM, ChaCha20-Poly1305).
- [x] `core`: KDF dispatch (Argon2id, scrypt, PBKDF2) + param encoding + defaults.
- [x] `core`: header serialize / parse (+ optional filename, flags, versioning).
- [x] `core`: STREAM chunked encrypt/decrypt with progress + cancellation.
- [x] `core`: ASCII armor wrap/unwrap + auto-detect.
- [ ] `core`: pure helpers — default output paths, cipher/KDF name parsing.
- [ ] `core`: unit, round-trip, tamper, and KAT tests.
- [ ] `symcrypt-common`: path-or-stdin I/O, clobber check, best-effort
      remove, password-source resolution, exit-code mapping (+ unit tests).
- [ ] Docs: project `README`.
