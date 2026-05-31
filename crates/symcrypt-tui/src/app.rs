//! Application state for the symcrypt TUI. `event` mutates it; `ui` renders it.

/// The operation the user is performing; rendered as tabs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Info,
    Verify,
}

impl Mode {
    /// All modes in tab order.
    pub const ALL: [Mode; 4] = [Mode::Encrypt, Mode::Decrypt, Mode::Info, Mode::Verify];

    /// Tab label.
    pub fn title(self) -> &'static str {
        match self {
            Mode::Encrypt => "Encrypt",
            Mode::Decrypt => "Decrypt",
            Mode::Info => "Info",
            Mode::Verify => "Verify",
        }
    }

    /// Index into [`Mode::ALL`].
    pub fn index(self) -> usize {
        Mode::ALL.iter().position(|&m| m == self).unwrap_or(0)
    }
}

/// Top-level application state.
pub struct App {
    pub mode: Mode,
    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            mode: Mode::Encrypt,
            should_quit: false,
        }
    }

    /// Process exit code for a normal quit (refined as operations land).
    pub fn exit_code(&self) -> i32 {
        0
    }

    /// Switch to the previous mode tab (wrapping).
    pub fn prev_mode(&mut self) {
        let i = self.mode.index();
        let n = Mode::ALL.len();
        self.mode = Mode::ALL[(i + n - 1) % n];
    }

    /// Switch to the next mode tab (wrapping).
    pub fn next_mode(&mut self) {
        let i = self.mode.index();
        self.mode = Mode::ALL[(i + 1) % Mode::ALL.len()];
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_index_round_trips() {
        for (i, &m) in Mode::ALL.iter().enumerate() {
            assert_eq!(m.index(), i);
        }
    }

    #[test]
    fn mode_cycles_forward_and_back() {
        let mut app = App::new();
        assert_eq!(app.mode, Mode::Encrypt);
        app.next_mode();
        assert_eq!(app.mode, Mode::Decrypt);
        app.prev_mode();
        assert_eq!(app.mode, Mode::Encrypt);
        app.prev_mode();
        assert_eq!(app.mode, Mode::Verify); // wraps
    }
}
