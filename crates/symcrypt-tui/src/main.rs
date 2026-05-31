//! `symcrypt-tui` — interactive terminal front-end for symcrypt.
//!
//! A thin view over `symcrypt-core` (crypto/format) and `symcrypt-common`
//! (terminal glue). See `docs/IMPLEMENTATION_PLAN_03_TUI.md`.

mod app;
mod event;
mod ui;

use anyhow::Result;
use crossterm::event::{read, Event, KeyEventKind};

use app::App;

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("symcrypt-tui: {e}");
            std::process::exit(1);
        }
    }
}

/// Set up the terminal (raw mode + alternate screen + panic-safe restore via
/// `ratatui::try_init`), run the event loop, then restore the terminal.
fn run() -> Result<i32> {
    let mut terminal = ratatui::try_init()?;
    let result = run_loop(&mut terminal);
    ratatui::restore();
    result
}

fn run_loop(terminal: &mut ratatui::DefaultTerminal) -> Result<i32> {
    let mut app = App::new();
    while !app.should_quit {
        terminal.draw(|f| ui::draw(f, &app))?;
        if let Event::Key(key) = read()? {
            if key.kind == KeyEventKind::Press {
                event::handle_key(&mut app, key);
            }
        }
    }
    Ok(app.exit_code())
}
