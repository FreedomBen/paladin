# symcrypt — Implementation plan 03: TUI (`symcrypt-tui`)

**Status:** Stub. Not yet expanded — [DESIGN.md](DESIGN.md) is still being
iterated on. This file collects the implementation-checklist items for the
terminal front-end, copied verbatim from DESIGN.md so no planning work is lost.
It will be turned into detailed, ordered steps once the design stabilizes.

**Scope.** The `symcrypt-tui` binary — an interactive ratatui/crossterm
front-end over `symcrypt-core` (DESIGN §7). It holds no crypto or format logic
and reuses `symcrypt-common` for terminal glue.

**Depends on:** [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)
— `symcrypt-core` and the `symcrypt-common` terminal glue.

---

## Checklist

- [ ] `symcrypt-tui`: ratatui/crossterm scaffold, event loop, form widgets.
- [ ] `symcrypt-tui`: masked password capture, advanced options, path prefill.
- [ ] `symcrypt-tui`: worker thread + progress gauge + cancellation.
- [ ] Docs: `symcrypt-tui` man page.
- [ ] Packaging: `cargo install` for `symcrypt-tui`.
