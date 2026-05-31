//! Key handling and focus navigation. Thin: it routes keys to the state
//! transitions on [`App`]; all the logic lives there.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Focus};

/// Handle a single key event, mutating the app state.
pub fn handle_key(app: &mut App, key: KeyEvent) {
    // The help overlay swallows input except its own dismissal and quit.
    if app.help {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => app.should_quit = true,
            (KeyCode::Char('?'), _) | (KeyCode::Esc, _) => app.help = false,
            _ => {}
        }
        return;
    }

    let target = app.focus_target();
    match (key.code, key.modifiers) {
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => app.should_quit = true,
        // Esc quits while idle; cancels a run once the worker lands.
        (KeyCode::Esc, _) => app.should_quit = true,
        (KeyCode::Tab, _) => app.focus_next(),
        (KeyCode::BackTab, _) => app.focus_prev(),
        _ if target.is_text() => text_key(app, target, key.code),
        _ => widget_key(app, target, key.code),
    }
}

/// Editing keys for a focused text field.
fn text_key(app: &mut App, target: Focus, code: KeyCode) {
    let mut edited = false;
    if let Some(editor) = app.editor_mut(target) {
        match code {
            KeyCode::Char(c) => {
                editor.insert(c);
                edited = true;
            }
            KeyCode::Backspace => {
                editor.backspace();
                edited = true;
            }
            KeyCode::Delete => {
                editor.delete();
                edited = true;
            }
            KeyCode::Left => editor.move_left(),
            KeyCode::Right => editor.move_right(),
            KeyCode::Home => editor.home(),
            KeyCode::End => editor.end(),
            _ => {}
        }
    }
    // A manual edit of the output path pins it against prefill.
    if edited && target == Focus::Output {
        app.output_dirty = true;
    }
}

/// Keys for tabs, selectors, checkboxes, and the advanced expander.
fn widget_key(app: &mut App, target: Focus, code: KeyCode) {
    match (target, code) {
        (Focus::Mode, KeyCode::Left) => app.prev_mode(),
        (Focus::Mode, KeyCode::Right) => app.next_mode(),
        // `?` opens help only off a text field (so '?' can be typed into paths).
        (_, KeyCode::Char('?')) => app.help = true,
        (Focus::Advanced, KeyCode::Enter) => app.toggle(Focus::Advanced),
        (_, KeyCode::Char(' ')) => app.toggle(target),
        _ => {}
    }
}
