//! Key handling and focus navigation.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::App;

/// Handle a single key event, mutating the app state.
pub fn handle_key(app: &mut App, key: KeyEvent) {
    match (key.code, key.modifiers) {
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => app.should_quit = true,
        (KeyCode::Esc, _) => app.should_quit = true,
        (KeyCode::Left, _) => app.prev_mode(),
        (KeyCode::Right, _) => app.next_mode(),
        _ => {}
    }
}
