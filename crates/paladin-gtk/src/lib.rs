//! `paladin-gtk` — relm4 (gtk4-rs + libadwaita) desktop front-end over
//! `paladin-core`. It is a thin view: it gathers input through widgets, builds
//! a `Secret` and `EncryptOptions`, calls the four core operations, and renders
//! progress and results. It holds no crypto or format logic.
//!
//! Per DESIGN §2.2/§8 and `docs/IMPLEMENTATION_PLAN_04_GTK.md`, medium-independent
//! logic is pushed out of the relm4 `view!`/`update` wiring into small, pure,
//! unit-tested modules so it can be tested without a display. The crate is a
//! library plus a thin binary so those helpers form a public surface (and so are
//! not spuriously flagged as dead code while the UI is wired up incrementally).

pub mod app;
pub mod editor;
pub mod fsio;
pub mod info;
pub mod message;
pub mod mode;
pub mod options;
pub mod task;

use gtk::glib;
use relm4::RelmApp;

/// Application id used for the GApplication and (eventually) the desktop file.
pub const APP_ID: &str = "org.paladin.Gtk";

/// Bootstrap libadwaita and run the relm4 [`app::AppModel`] component,
/// returning its exit code.
pub fn run() -> glib::ExitCode {
    let app = RelmApp::new(APP_ID);
    app.run::<app::AppModel>(());
    glib::ExitCode::SUCCESS
}
