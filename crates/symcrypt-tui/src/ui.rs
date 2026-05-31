//! ratatui rendering for the symcrypt TUI.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use ratatui::Frame;

use crate::app::{App, Mode};

/// Render the whole UI for the current frame.
pub fn draw(f: &mut Frame, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(f.area());

    let titles: Vec<Line> = Mode::ALL.iter().map(|m| Line::from(m.title())).collect();
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("symcrypt"))
        .select(app.mode.index())
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(tabs, rows[0]);

    let body = Paragraph::new("").block(Block::default().borders(Borders::ALL));
    f.render_widget(body, rows[1]);

    let footer = Paragraph::new(
        "Tab: move  ·  \u{2190}/\u{2192}: mode  ·  Enter: run  ·  Esc: quit  ·  ?: help",
    );
    f.render_widget(footer, rows[2]);
}
