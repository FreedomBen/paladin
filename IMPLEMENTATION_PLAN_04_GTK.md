# symcrypt — Implementation plan 04: GTK (`symcrypt-gtk`)

**Status:** Stub. Not yet expanded — [DESIGN.md](DESIGN.md) is still being
iterated on. This file collects the implementation-checklist items for the GTK
desktop front-end, copied verbatim from DESIGN.md so no planning work is lost.
It will be turned into detailed, ordered steps once the design stabilizes.

**Scope.** The `symcrypt-gtk` binary — a relm4 (gtk4-rs + libadwaita) desktop
front-end over `symcrypt-core` (DESIGN §8). It holds no crypto or format logic.

**Depends on:** [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md)
— `symcrypt-core`. Note: `symcrypt-gtk` does **not** use `symcrypt-common`; it
relies on the core plus GTK-native file handling (DESIGN §2.2).

---

## Checklist

- [ ] `symcrypt-gtk`: relm4 component (model/inputs/view), libadwaita widgets, `gtk::FileDialog`, drag-and-drop.
- [ ] `symcrypt-gtk`: relm4 Command/Worker for off-thread crypto; progress + cancellation; encrypt/decrypt/info flows.
- [ ] Docs: `.desktop` file for `symcrypt-gtk`.
- [ ] Packaging: GTK build/run notes (needs GTK4 + libadwaita dev libs).
