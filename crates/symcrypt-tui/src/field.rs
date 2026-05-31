//! A single-line text editor: cursor movement, insert/delete, Home/End, and
//! optional masking for password fields. Pure and unit-tested; the UI renders
//! [`Editor::display`] and positions the cursor with [`Editor::cursor`].

use zeroize::Zeroize;

/// Character used to mask a hidden password field.
const MASK_CHAR: char = '\u{2022}'; // BULLET '•'

/// One line of editable text. The cursor is a *character* index in `0..=len`.
///
/// Editors created with [`Editor::masked`] are *sensitive*: their backing
/// buffer is zeroized on clear, on replacement, and on drop, so a typed
/// password does not linger in freed heap (DESIGN §7.2).
#[derive(Clone, Debug, Default)]
pub struct Editor {
    text: String,
    /// Character index of the caret (not a byte offset).
    cursor: usize,
    masked: bool,
    /// Zeroize the buffer on clear/replace/drop (set for password fields).
    sensitive: bool,
}

impl Editor {
    /// Empty, unmasked editor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty editor that renders masked (for passwords). The buffer is marked
    /// sensitive (zeroized on clear/replace/drop) and pre-reserves capacity so a
    /// typical password does not reallocate and scatter copies across the heap.
    pub fn masked() -> Self {
        Self {
            text: String::with_capacity(256),
            cursor: 0,
            masked: true,
            sensitive: true,
        }
    }

    /// Editor prefilled with `text`, caret at the end.
    pub fn with_text(text: impl Into<String>) -> Self {
        let text = text.into();
        let cursor = text.chars().count();
        Self {
            text,
            cursor,
            masked: false,
            sensitive: false,
        }
    }

    /// Logical contents.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// `true` when the field has no characters.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Caret position as a character index.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Toggle masking (show/hide a password).
    pub fn set_masked(&mut self, masked: bool) {
        self.masked = masked;
    }

    /// Replace the contents and move the caret to the end.
    pub fn set_text(&mut self, text: impl Into<String>) {
        if self.sensitive {
            self.text.zeroize();
        }
        self.text = text.into();
        self.cursor = self.len();
    }

    /// Clear the contents and caret.
    pub fn clear(&mut self) {
        if self.sensitive {
            self.text.zeroize();
        }
        self.text.clear();
        self.cursor = 0;
    }

    /// Number of characters.
    fn len(&self) -> usize {
        self.text.chars().count()
    }

    /// Byte offset of character index `idx` (== `text.len()` past the end).
    fn byte_offset(&self, idx: usize) -> usize {
        self.text
            .char_indices()
            .nth(idx)
            .map(|(b, _)| b)
            .unwrap_or(self.text.len())
    }

    /// Insert a character at the caret and advance it.
    pub fn insert(&mut self, c: char) {
        let at = self.byte_offset(self.cursor);
        self.text.insert(at, c);
        self.cursor += 1;
    }

    /// Delete the character before the caret (Backspace).
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let at = self.byte_offset(self.cursor);
        self.text.remove(at);
    }

    /// Delete the character at the caret (Delete).
    pub fn delete(&mut self) {
        if self.cursor >= self.len() {
            return;
        }
        let at = self.byte_offset(self.cursor);
        self.text.remove(at);
    }

    /// Move the caret one character left.
    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Move the caret one character right.
    pub fn move_right(&mut self) {
        if self.cursor < self.len() {
            self.cursor += 1;
        }
    }

    /// Move the caret to the start.
    pub fn home(&mut self) {
        self.cursor = 0;
    }

    /// Move the caret to the end.
    pub fn end(&mut self) {
        self.cursor = self.len();
    }

    /// Rendered string: bullets when masked, otherwise the text.
    pub fn display(&self) -> String {
        if self.masked {
            MASK_CHAR.to_string().repeat(self.len())
        } else {
            self.text.clone()
        }
    }
}

impl Drop for Editor {
    fn drop(&mut self) {
        if self.sensitive {
            self.text.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_advances_cursor_and_appends() {
        let mut e = Editor::new();
        for c in "abc".chars() {
            e.insert(c);
        }
        assert_eq!(e.text(), "abc");
        assert_eq!(e.cursor(), 3);
        assert!(!e.is_empty());
    }

    #[test]
    fn insert_in_middle() {
        let mut e = Editor::with_text("ac");
        e.home();
        e.move_right(); // between a and c
        e.insert('b');
        assert_eq!(e.text(), "abc");
        assert_eq!(e.cursor(), 2);
    }

    #[test]
    fn backspace_removes_before_cursor() {
        let mut e = Editor::with_text("abc");
        e.backspace();
        assert_eq!(e.text(), "ab");
        assert_eq!(e.cursor(), 2);
    }

    #[test]
    fn backspace_at_start_is_noop() {
        let mut e = Editor::with_text("abc");
        e.home();
        e.backspace();
        assert_eq!(e.text(), "abc");
        assert_eq!(e.cursor(), 0);
    }

    #[test]
    fn delete_removes_at_cursor() {
        let mut e = Editor::with_text("abc");
        e.home();
        e.delete();
        assert_eq!(e.text(), "bc");
        assert_eq!(e.cursor(), 0);
    }

    #[test]
    fn delete_at_end_is_noop() {
        let mut e = Editor::with_text("abc");
        e.end();
        e.delete();
        assert_eq!(e.text(), "abc");
        assert_eq!(e.cursor(), 3);
    }

    #[test]
    fn cursor_moves_clamp_at_bounds() {
        let mut e = Editor::with_text("ab");
        e.move_right(); // already at end
        assert_eq!(e.cursor(), 2);
        e.home();
        e.move_left(); // already at start
        assert_eq!(e.cursor(), 0);
    }

    #[test]
    fn home_and_end() {
        let mut e = Editor::with_text("hello");
        e.home();
        assert_eq!(e.cursor(), 0);
        e.end();
        assert_eq!(e.cursor(), 5);
    }

    #[test]
    fn multibyte_editing_is_char_aware() {
        // 'é' is two bytes; cursor math must stay on char boundaries.
        let mut e = Editor::with_text("café");
        assert_eq!(e.cursor(), 4);
        e.backspace();
        assert_eq!(e.text(), "caf");
        assert_eq!(e.cursor(), 3);
        e.insert('é');
        assert_eq!(e.text(), "café");
        assert_eq!(e.cursor(), 4);
    }

    #[test]
    fn masking_renders_bullets_but_keeps_text() {
        let mut e = Editor::masked();
        for c in "pw".chars() {
            e.insert(c);
        }
        assert_eq!(e.display(), "\u{2022}\u{2022}");
        assert_eq!(e.text(), "pw"); // underlying value preserved
        e.set_masked(false);
        assert_eq!(e.display(), "pw");
    }

    #[test]
    fn set_text_moves_cursor_to_end_and_clear_resets() {
        let mut e = Editor::new();
        e.set_text("/tmp/file.txt");
        assert_eq!(e.cursor(), 13);
        e.clear();
        assert!(e.is_empty());
        assert_eq!(e.cursor(), 0);
    }
}
