//! `paladin-gtk` binary entry point. All logic lives in the library crate
//! (`paladin_gtk`); this is a thin launcher. See
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md`.

fn main() -> gtk::glib::ExitCode {
    paladin_gtk::run()
}
