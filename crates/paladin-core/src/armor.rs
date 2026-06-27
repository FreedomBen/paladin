//! Optional ASCII-armor outer layer (DESIGN §5.6).
//!
//! Armor is a PEM-style base64 wrapping of the binary container. It streams in
//! both directions so memory stays bounded regardless of file size.
//!
//! - [`ArmorWriter`] wraps a `Write`: it emits the BEGIN marker, base64 wrapped
//!   at exactly 64 columns with LF endings, and the END marker, ending with a
//!   single newline.
//! - [`ArmorReader`] wraps a `Read`: it strips the markers, accepts LF/CRLF and
//!   surrounding whitespace, decodes base64 across line boundaries, and rejects
//!   junk outside the markers, invalid base64, an over-long line, and a missing
//!   END marker as [`SymError::MalformedHeader`].
//! - [`auto_dearmor`] peeks the input and returns a [`DearmorReader`] that is
//!   either the raw stream (binary) or an [`ArmorReader`] (armored).
//!
//! Framing errors discovered mid-stream are wrapped in `io::Error::other` so
//! they surface through the `Read` interface; the header/stream read paths
//! recover them with [`crate::error::recover_symerror`].

use std::io::{self, Read, Write};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::{Result, SymError};

const BEGIN_MARKER: &str = "-----BEGIN PALADIN MESSAGE-----";
const END_MARKER: &str = "-----END PALADIN MESSAGE-----";
/// Input bytes per armored line: 48 bytes encode to exactly 64 base64 columns.
const LINE_INPUT: usize = 48;
/// Output base64 columns per line.
const LINE_COLUMNS: usize = 64;
/// Maximum accepted length of a single armored line; bounds reader memory.
const MAX_LINE: usize = 8192;
/// Bytes peeked to distinguish armored from binary input.
const DETECT_PEEK: usize = 512;

/// Streaming armor encoder. Construct with [`ArmorWriter::new`] (which emits the
/// BEGIN marker), write the binary container through it, then call
/// [`ArmorWriter::finish`] to flush the trailing line and the END marker.
pub(crate) struct ArmorWriter<W: Write> {
    inner: W,
    /// Pending input bytes that have not yet formed a complete 48-byte line.
    buf: Vec<u8>,
}

impl<W: Write> ArmorWriter<W> {
    pub(crate) fn new(mut inner: W) -> io::Result<Self> {
        inner.write_all(BEGIN_MARKER.as_bytes())?;
        inner.write_all(b"\n")?;
        Ok(Self {
            inner,
            buf: Vec::with_capacity(LINE_INPUT),
        })
    }

    /// Flush the final (possibly short) line and the END marker, ending the
    /// output with exactly one newline.
    pub(crate) fn finish(mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let encoded = STANDARD.encode(&self.buf);
            self.inner.write_all(encoded.as_bytes())?;
            self.inner.write_all(b"\n")?;
        }
        self.inner.write_all(END_MARKER.as_bytes())?;
        self.inner.write_all(b"\n")?;
        self.inner.flush()
    }
}

impl<W: Write> Write for ArmorWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        let complete = (self.buf.len() / LINE_INPUT) * LINE_INPUT;
        if complete > 0 {
            // 48-byte groups encode to 64-column lines with no padding.
            let encoded = STANDARD.encode(&self.buf[..complete]);
            for line in encoded.as_bytes().chunks(LINE_COLUMNS) {
                self.inner.write_all(line)?;
                self.inner.write_all(b"\n")?;
            }
            self.buf.drain(..complete);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Do not flush a partial base64 group mid-stream; finish() handles the
        // tail. Only forward the inner flush.
        self.inner.flush()
    }
}

/// Reader state: looking for the BEGIN line, decoding the body, or draining and
/// validating trailing whitespace after the END line.
#[derive(PartialEq, Eq)]
enum Phase {
    Header,
    Body,
    Drain,
}

/// Streaming armor decoder. Yields the decoded binary container; framing errors
/// surface as `io::Error::other(SymError::MalformedHeader(..))`.
pub(crate) struct ArmorReader<R: Read> {
    inner: R,
    phase: Phase,
    /// Current partial line (bytes since the last newline).
    line: Vec<u8>,
    /// Pending base64 characters that have not yet formed a complete 4-char group.
    carry: Vec<u8>,
    /// Decoded bytes ready to serve.
    out: Vec<u8>,
    out_pos: usize,
    eof: bool,
}

impl<R: Read> ArmorReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            phase: Phase::Header,
            line: Vec::new(),
            carry: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            eof: false,
        }
    }

    /// Ensure `out` holds unread bytes, or that we have reached a clean end.
    fn refill(&mut self) -> Result<()> {
        while self.out_pos >= self.out.len() {
            self.out.clear();
            self.out_pos = 0;
            if self.eof {
                return Ok(());
            }
            let mut block = [0u8; 4096];
            let n = self.inner.read(&mut block).map_err(SymError::Io)?;
            if n == 0 {
                self.eof = true;
                self.finish_eof()?;
                return Ok(());
            }
            self.feed(&block[..n])?;
        }
        Ok(())
    }

    /// Process a block of raw input one byte at a time.
    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        for &b in bytes {
            if self.phase == Phase::Drain {
                if !b.is_ascii_whitespace() {
                    return Err(SymError::MalformedHeader(
                        "unexpected data after END marker",
                    ));
                }
                continue;
            }
            if b == b'\n' {
                self.process_line()?;
                self.line.clear();
            } else {
                if self.line.len() >= MAX_LINE {
                    return Err(SymError::MalformedHeader("armor line too long"));
                }
                self.line.push(b);
            }
        }
        Ok(())
    }

    /// Interpret the accumulated `line` according to the current phase. The line
    /// is copied out first so the body decoder can borrow `self` mutably.
    fn process_line(&mut self) -> Result<()> {
        let trimmed = self.line.trim_ascii().to_vec();
        match self.phase {
            Phase::Header => {
                if trimmed.is_empty() {
                    return Ok(()); // leading blank lines are allowed
                }
                if trimmed.as_slice() == BEGIN_MARKER.as_bytes() {
                    self.phase = Phase::Body;
                    Ok(())
                } else {
                    Err(SymError::MalformedHeader(
                        "expected the BEGIN PALADIN MESSAGE marker",
                    ))
                }
            }
            Phase::Body => {
                if trimmed.as_slice() == END_MARKER.as_bytes() {
                    if !self.carry.is_empty() {
                        return Err(SymError::MalformedHeader(
                            "truncated base64 before END marker",
                        ));
                    }
                    self.phase = Phase::Drain;
                    Ok(())
                } else if trimmed.is_empty() {
                    Ok(()) // blank lines within the body are ignored
                } else {
                    self.decode_body_line(&trimmed)
                }
            }
            Phase::Drain => Ok(()),
        }
    }

    /// Append a body line's base64 characters and decode any complete groups.
    fn decode_body_line(&mut self, content: &[u8]) -> Result<()> {
        for &c in content {
            if !c.is_ascii_whitespace() {
                self.carry.push(c);
            }
        }
        let take = (self.carry.len() / 4) * 4;
        if take > 0 {
            let decoded = STANDARD
                .decode(&self.carry[..take])
                .map_err(|_| SymError::MalformedHeader("invalid base64 in armor body"))?;
            self.out.extend_from_slice(&decoded);
            self.carry.drain(..take);
        }
        Ok(())
    }

    /// Validate framing at end of input, processing the trailing partial line.
    fn finish_eof(&mut self) -> Result<()> {
        match self.phase {
            Phase::Header => Err(SymError::MalformedHeader("missing BEGIN marker")),
            Phase::Body => {
                // Process the trailing partial line (it has no newline).
                self.process_line()?;
                self.line.clear();
                if self.phase == Phase::Body {
                    Err(SymError::MalformedHeader("missing END marker"))
                } else {
                    Ok(())
                }
            }
            Phase::Drain => Ok(()),
        }
    }
}

impl<R: Read> Read for ArmorReader<R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.refill().map_err(io::Error::other)?;
        let available = self.out.len() - self.out_pos;
        if available == 0 {
            return Ok(0);
        }
        let n = available.min(dst.len());
        dst[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        Ok(n)
    }
}

/// Either the raw (binary) input or an armor-decoding wrapper, both prefixed by
/// the bytes consumed during detection.
pub(crate) enum DearmorReader<R: Read> {
    Binary(io::Chain<io::Cursor<Vec<u8>>, R>),
    Armored(ArmorReader<io::Chain<io::Cursor<Vec<u8>>, R>>),
}

impl<R: Read> Read for DearmorReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            DearmorReader::Binary(r) => r.read(buf),
            DearmorReader::Armored(r) => r.read(buf),
        }
    }
}

/// Detect armor by peeking past leading whitespace: the first non-whitespace
/// byte is `-` for armored input and the binary magic `S` otherwise. The peeked
/// bytes are preserved by chaining them ahead of the rest of the stream.
pub(crate) fn auto_dearmor<R: Read>(mut input: R) -> Result<DearmorReader<R>> {
    let mut peek = Vec::new();
    let mut byte = [0u8; 1];
    let armored = loop {
        match input.read(&mut byte) {
            Ok(0) => break false, // empty or all-whitespace: treat as binary
            Ok(_) => {
                peek.push(byte[0]);
                if byte[0].is_ascii_whitespace() {
                    if peek.len() >= DETECT_PEEK {
                        break false;
                    }
                    continue;
                }
                break byte[0] == b'-';
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(SymError::Io(e)),
        }
    };
    let combined = io::Cursor::new(peek).chain(input);
    if armored {
        Ok(DearmorReader::Armored(ArmorReader::new(combined)))
    } else {
        Ok(DearmorReader::Binary(combined))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn armor(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = ArmorWriter::new(&mut out).unwrap();
        w.write_all(bytes).unwrap();
        w.finish().unwrap();
        out
    }

    fn dearmor(armored: &[u8]) -> Result<Vec<u8>> {
        let mut r = auto_dearmor(io::Cursor::new(armored.to_vec()))?;
        let mut out = Vec::new();
        r.read_to_end(&mut out)
            .map_err(|e| crate::error::recover_symerror(e).unwrap_or_else(SymError::Io))?;
        Ok(out)
    }

    #[test]
    fn writer_emits_well_formed_framing() {
        let out = armor(&[0xABu8; 100]);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines[0], BEGIN_MARKER);
        // Exactly one trailing newline => last split element is empty.
        assert_eq!(*lines.last().unwrap(), "");
        assert_eq!(lines[lines.len() - 2], END_MARKER);
        // Base64 body lines are at most 64 columns.
        for line in &lines[1..lines.len() - 2] {
            assert!(line.len() <= LINE_COLUMNS, "line too long: {line:?}");
        }
    }

    #[test]
    fn round_trip_across_sizes() {
        for n in [0usize, 1, 2, 3, 47, 48, 49, 64, 1000, 5000] {
            let data: Vec<u8> = (0..n).map(|i| (i % 256) as u8).collect();
            let armored = armor(&data);
            assert_eq!(dearmor(&armored).unwrap(), data, "size {n}");
        }
    }

    #[test]
    fn auto_detect_distinguishes_binary_from_armored() {
        // Binary input (begins with the magic) is passed through unchanged.
        let binary = b"PALADIN\x00\x01rest-of-container";
        let mut r = auto_dearmor(io::Cursor::new(binary.to_vec())).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, binary);

        // Armored input decodes.
        let armored = armor(b"hello world");
        assert_eq!(dearmor(&armored).unwrap(), b"hello world");
    }

    #[test]
    fn accepts_crlf_and_surrounding_whitespace() {
        let armored = String::from_utf8(armor(b"some binary payload here")).unwrap();
        let crlf = armored.replace('\n', "\r\n");
        let padded = format!("\n  \r\n{crlf}\n\t\n");
        assert_eq!(
            dearmor(padded.as_bytes()).unwrap(),
            b"some binary payload here"
        );
    }

    #[test]
    fn rejects_junk_before_begin_marker() {
        // Detection keys on the first non-whitespace byte, so junk that starts
        // with '-' is treated as armor and the first line must be the exact
        // BEGIN marker. (Junk starting with another byte is classified as binary
        // and rejected downstream as a bad magic.)
        let armored = String::from_utf8(armor(b"payload")).unwrap();
        let bad = format!("--- not the marker ---\n{armored}");
        assert!(matches!(
            dearmor(bad.as_bytes()),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn rejects_missing_end_marker() {
        let armored = String::from_utf8(armor(b"payload")).unwrap();
        let without_end = armored.replace(&format!("{END_MARKER}\n"), "");
        assert!(matches!(
            dearmor(without_end.as_bytes()),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn rejects_invalid_base64_in_body() {
        let bad = format!("{BEGIN_MARKER}\n!!!!not base64!!!!\n{END_MARKER}\n");
        assert!(matches!(
            dearmor(bad.as_bytes()),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn rejects_data_after_end_marker() {
        let armored = String::from_utf8(armor(b"payload")).unwrap();
        let trailing = format!("{armored}this should not be here\n");
        assert!(matches!(
            dearmor(trailing.as_bytes()),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn rejects_overlong_line() {
        let mut bad = format!("{BEGIN_MARKER}\n");
        bad.push_str(&"A".repeat(MAX_LINE + 10));
        bad.push('\n');
        bad.push_str(&format!("{END_MARKER}\n"));
        assert!(matches!(
            dearmor(bad.as_bytes()),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn trailing_whitespace_after_end_is_allowed() {
        let armored = String::from_utf8(armor(b"payload")).unwrap();
        let trailing = format!("{armored}   \n\t\n");
        assert_eq!(dearmor(trailing.as_bytes()).unwrap(), b"payload");
    }

    /// Read through `auto_dearmor` over owned bytes, mapping framing errors as
    /// the `dearmor` helper does.
    fn auto_read(bytes: Vec<u8>) -> Result<Vec<u8>> {
        let mut r = auto_dearmor(io::Cursor::new(bytes))?;
        let mut out = Vec::new();
        r.read_to_end(&mut out)
            .map_err(|e| crate::error::recover_symerror(e).unwrap_or_else(SymError::Io))?;
        Ok(out)
    }

    #[test]
    fn auto_dearmor_treats_empty_and_whitespace_as_binary() {
        // Empty input: binary passthrough, no missing-BEGIN-marker error.
        assert_eq!(auto_read(Vec::new()).unwrap(), b"");

        // All-whitespace input is binary, returned unchanged. If it were treated
        // as armored it would error on the missing BEGIN marker.
        let ws = b"   \n\t\n".to_vec();
        assert_eq!(auto_read(ws.clone()).unwrap(), ws);

        // More than DETECT_PEEK leading whitespace bytes still classify binary.
        let mut long_ws = vec![b' '; DETECT_PEEK + 10];
        long_ws.push(b'X');
        assert_eq!(auto_read(long_ws.clone()).unwrap(), long_ws);
    }

    #[test]
    fn writer_buffers_across_many_small_writes() {
        let payload: Vec<u8> = (0..200u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut out = Vec::new();
        let mut w = ArmorWriter::new(&mut out).unwrap();
        // Chunk sizes straddle the 48-byte line boundary to exercise the carry.
        let mut off = 0;
        for size in [1usize, 7, 40, 48, 49] {
            let end = (off + size).min(payload.len());
            w.write_all(&payload[off..end]).unwrap();
            off = end;
        }
        w.write_all(&payload[off..]).unwrap(); // the rest
        w.finish().unwrap();

        assert_eq!(dearmor(&out).unwrap(), payload);

        // Framing remains well-formed.
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines[0], BEGIN_MARKER);
        assert_eq!(*lines.last().unwrap(), "");
        assert_eq!(lines[lines.len() - 2], END_MARKER);
        for line in &lines[1..lines.len() - 2] {
            assert!(line.len() <= LINE_COLUMNS, "line too long: {line:?}");
        }
    }

    /// A `Read` that yields at most one byte per call. The first call returns an
    /// `Interrupted` error (without consuming input) to exercise the retry arm in
    /// `auto_dearmor`'s detection loop; later reads deliver one byte each.
    /// `ArmorReader::refill` does not retry `Interrupted`, so we only inject it
    /// during the single-byte detection phase.
    struct Drip<R> {
        inner: R,
        calls: usize,
    }

    impl<R> Drip<R> {
        fn new(inner: R) -> Self {
            Self { inner, calls: 0 }
        }
    }

    impl<R: Read> Read for Drip<R> {
        fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if dst.is_empty() {
                return Ok(0);
            }
            self.inner.read(&mut dst[..1])
        }
    }

    #[test]
    fn dearmor_round_trips_with_byte_at_a_time_reader() {
        let payload: Vec<u8> = (0..300u32).map(|i| (i % 256) as u8).collect();
        let armored = armor(&payload);
        let mut r = auto_dearmor(Drip::new(armored.as_slice())).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn writer_flush_midstream_is_safe() {
        // A mid-stream flush over a short write must not emit a partial body
        // line: only the BEGIN marker and its newline appear so far. The shared
        // `Vec` is captured via a raw-byte snapshot after the flush.
        let snapshot;
        let mut out = Vec::new();
        {
            let mut w = ArmorWriter::new(&mut out).unwrap();
            w.write_all(&[0x5Au8; 10]).unwrap(); // fewer than one full 48-byte line
            w.flush().unwrap();
            snapshot = w.inner.clone();

            // Writing the rest and finishing still yields a clean round-trip.
            w.write_all(&[0xA5u8; 90]).unwrap();
            w.finish().unwrap();
        }
        assert_eq!(snapshot, format!("{BEGIN_MARKER}\n").into_bytes());
        let mut expected = vec![0x5Au8; 10];
        expected.extend_from_slice(&[0xA5u8; 90]);
        assert_eq!(dearmor(&out).unwrap(), expected);
    }
}
