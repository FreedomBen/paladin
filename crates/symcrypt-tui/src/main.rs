//! `symcrypt-tui` — interactive terminal front-end for symcrypt.
//!
//! A thin view over `symcrypt-core` (crypto/format) and `symcrypt-common`
//! (terminal glue). See `docs/IMPLEMENTATION_PLAN_03_TUI.md`.

mod app;
mod event;
mod field;
mod ui;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{read, Event, KeyEventKind};

use app::App;

/// Optional launch path; the rest of the form is filled in interactively.
#[derive(Parser)]
#[command(
    name = "symcrypt-tui",
    version,
    about = "Interactive terminal front-end for symcrypt"
)]
struct Args {
    /// Input file to prefill the form with.
    file: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    let initial = args.file.map(|p| p.to_string_lossy().into_owned());
    match run(initial) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("symcrypt-tui: {e}");
            std::process::exit(1);
        }
    }
}

/// Set up the terminal (raw mode + alternate screen + panic-safe restore via
/// `ratatui::try_init`), run the event loop, then restore the terminal.
fn run(initial: Option<String>) -> Result<i32> {
    let mut terminal = ratatui::try_init()?;
    let result = run_loop(&mut terminal, initial);
    ratatui::restore();
    result
}

fn run_loop(terminal: &mut ratatui::DefaultTerminal, initial: Option<String>) -> Result<i32> {
    let mut app = App::new(initial);
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
