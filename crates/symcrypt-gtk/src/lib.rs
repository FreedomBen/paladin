//! `symcrypt-gtk` — relm4 (gtk4-rs + libadwaita) desktop front-end over
//! `symcrypt-core`. It is a thin view: it gathers input through widgets, builds
//! a `Secret` and `EncryptOptions`, calls the four core operations, and renders
//! progress and results. It holds no crypto or format logic.
//!
//! Per DESIGN §2.2/§8 and `docs/IMPLEMENTATION_PLAN_04_GTK.md`, medium-independent
//! logic is pushed out of the relm4 `view!`/`update` wiring into small, pure,
//! unit-tested modules so it can be tested without a display. The crate is a
//! library plus a thin binary so those helpers form a public surface (and so are
//! not spuriously flagged as dead code while the UI is wired up incrementally).

pub mod info;
pub mod message;
pub mod mode;

use adw::prelude::*;
use gtk::glib;

/// Application id used for the GApplication and (eventually) the desktop file.
pub const APP_ID: &str = "org.symcrypt.Gtk";

/// Bootstrap libadwaita and run the application, returning its exit code.
///
/// Step 1 (scaffold) opens an empty window; later steps replace this with the
/// relm4 `AppModel` component (see the implementation plan).
pub fn run() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_window);
    app.run()
}

fn build_window(app: &adw::Application) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("symcrypt")
        .default_width(480)
        .default_height(360)
        .build();
    window.present();
}
