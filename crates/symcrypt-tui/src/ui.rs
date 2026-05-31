//! ratatui rendering for the symcrypt TUI. Kept thin: it reads [`App`] state and
//! draws; all decision logic lives in `app`, `field`, and `options`.

use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Clear, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use crate::app::{App, Focus, Mode, RunStatus};

/// Column where field values begin (after the padded label).
const LABEL_W: u16 = 11;

/// Render the whole UI for the current frame.
pub fn draw(f: &mut Frame, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(3), // tabs
        Constraint::Min(1),    // form / results
        Constraint::Length(1), // status / inline error
        Constraint::Length(1), // footer hints
    ])
    .split(f.area());

    draw_tabs(f, app, rows[0]);
    let cursor = draw_body(f, app, rows[1]);
    draw_status(f, app, rows[2]);
    draw_footer(f, rows[3]);

    if app.help {
        draw_help(f, f.area());
    } else if let Some(pos) = cursor {
        f.set_cursor_position(pos);
    }
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus_target() == Focus::Mode;
    let border = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let titles: Vec<Line> = Mode::ALL.iter().map(|m| Line::from(m.title())).collect();
    let tabs = Tabs::new(titles)
        .block(Block::bordered().title("symcrypt").border_style(border))
        .select(app.mode.index())
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(tabs, area);
}

/// Draw the form rows (and, in Info mode, the results pane). Returns the screen
/// position of the caret for the focused text field, if any.
fn draw_body(f: &mut Frame, app: &App, area: Rect) -> Option<(u16, u16)> {
    let block = Block::bordered();
    let inner = block.inner(area);
    f.render_widget(block, area);

    let focused = app.focus_target();
    let mut lines: Vec<Line> = Vec::new();
    let mut cursor = None;
    let mut row: u16 = 0;

    for fcs in app.ring() {
        if fcs == Focus::Mode {
            continue;
        }
        let is_focused = fcs == focused;
        let (text, caret) = row_content(app, fcs);
        if is_focused {
            if let Some(col) = caret {
                cursor = Some((inner.x + col, inner.y + row));
            }
        }
        let style = if is_focused {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        lines.push(Line::styled(text, style));
        row += 1;
    }

    if app.mode == Mode::Info && !app.info_lines.is_empty() {
        lines.push(Line::from(""));
        for l in &app.info_lines {
            lines.push(Line::from(l.clone()));
        }
    }

    f.render_widget(Paragraph::new(lines), inner);
    cursor
}

/// The rendered text for a focusable row, plus the caret column for text fields.
fn row_content(app: &App, focus: Focus) -> (String, Option<u16>) {
    let field = |label: &str, value: &str| {
        format!("{:<w$}{value}", format!("{label}:"), w = LABEL_W as usize)
    };
    let check = |label: &str, on: bool| format!("[{}] {label}", if on { 'x' } else { ' ' });
    let caret = |e: &crate::field::Editor| Some(LABEL_W + e.cursor() as u16);

    match focus {
        Focus::Input => (field("Input", app.input.text()), caret(&app.input)),
        Focus::Output => (field("Output", app.output.text()), caret(&app.output)),
        Focus::Password => (
            field("Password", &app.password.display()),
            caret(&app.password),
        ),
        Focus::Confirm => (
            field("Confirm", &app.confirm.display()),
            caret(&app.confirm),
        ),
        Focus::Keyfile => (field("Keyfile", app.keyfile.text()), caret(&app.keyfile)),
        Focus::ShowPassword => (check("Show password", app.show_password), None),
        Focus::KeyfileOnly => (check("Keyfile-only (no password)", app.keyfile_only), None),
        Focus::Advanced => (
            format!(
                "[{}] Advanced options",
                if app.advanced { '-' } else { '+' }
            ),
            None,
        ),
        Focus::Name => (check("Store filename in header (--name)", app.name), None),
        Focus::Armor => (check("ASCII armor (--armor)", app.armor), None),
        Focus::Remove => (check("Remove input after success", app.remove_input), None),
        Focus::Overwrite => (check("Overwrite existing output (-f)", app.overwrite), None),
        Focus::Mode => (String::new(), None),
    }
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let (text, style) = if let Some(err) = &app.field_error {
        (err.clone(), Style::default().fg(Color::Red))
    } else {
        match &app.status {
            RunStatus::Idle => (String::new(), Style::default()),
        }
    };
    f.render_widget(Paragraph::new(text).style(style), area);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let hint = "Tab/\u{21e7}Tab move \u{b7} \u{2190}/\u{2192} change \u{b7} Space toggle \u{b7} Enter run \u{b7} Esc quit \u{b7} ? help";
    f.render_widget(
        Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn draw_help(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("symcrypt-tui key bindings"),
        Line::from(""),
        Line::from("Tab / Shift-Tab   move focus"),
        Line::from("\u{2190} / \u{2192}             switch mode tab / change a selector"),
        Line::from("Space             toggle a checkbox"),
        Line::from("Enter             run the selected operation"),
        Line::from("Esc               cancel a run, or quit when idle"),
        Line::from("Ctrl-C            quit (restores the terminal)"),
        Line::from("?                 toggle this help"),
    ];
    let popup = centered_rect(60, 55, area);
    f.render_widget(Clear, popup);
    let block = Block::bordered().title("Help");
    f.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        popup,
    );
}

/// A rectangle centered in `area`, sized as a percentage of it.
fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let [area] = Layout::horizontal([Constraint::Percentage(pct_x)])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::vertical([Constraint::Percentage(pct_y)])
        .flex(Flex::Center)
        .areas(area);
    area
}
