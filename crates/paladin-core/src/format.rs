//! Container-format detection and dispatch (PLAN_05 §3.1, §5.4).
//!
//! After the optional ASCII-armor layer is stripped, the core peeks the leading
//! magic to choose between the native paladin path and the AES Crypt read path.
//! The peeked bytes are re-chained ahead of the rest of the stream so the chosen
//! parser sees the whole input from byte 0.

use std::io::{self, Read};

use crate::error::{PalError, Result};

/// Native paladin magic (DESIGN §5.2): ASCII "PALADIN" plus a NUL pad (8 bytes).
const PALADIN_MAGIC: &[u8] = b"PALADIN\0";
/// AES Crypt magic (PLAN_05 §2.1).
const AESCRYPT_MAGIC: &[u8] = b"AES";

/// Which container the input is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// A paladin container (`header::parse` + `stream::*`).
    Paladin,
    /// An AES Crypt container (`aescrypt::*`).
    AesCrypt,
}

/// Peek the leading magic and return the [`Format`] plus a reader that still
/// yields the peeked bytes (PLAN_05 §3.1). A fully-read prefix matching neither
/// magic is [`PalError::BadMagic`]; a short input that is a proper prefix of a
/// supported magic is [`PalError::MalformedHeader`] (a truncated header). The
/// AES Crypt magic is only 3 bytes, so an `"AES"` prefix dispatches to the AES
/// parser regardless of the following bytes (it reports any unsupported version
/// itself).
pub(crate) fn detect<R: Read>(mut input: R) -> Result<(Format, impl Read)> {
    let peek = read_up_to(&mut input, PALADIN_MAGIC.len())?;

    let format = if peek.starts_with(AESCRYPT_MAGIC) {
        Format::AesCrypt
    } else if peek == PALADIN_MAGIC {
        Format::Paladin
    } else if is_proper_prefix_of_magic(&peek) {
        return Err(PalError::MalformedHeader(
            "input ends before the file magic is complete",
        ));
    } else {
        return Err(PalError::BadMagic);
    };

    Ok((format, io::Cursor::new(peek).chain(input)))
}

/// Whether `peek` is a proper (shorter-than-magic) prefix of either supported
/// magic — i.e. the input may be a truncated header rather than a foreign file.
fn is_proper_prefix_of_magic(peek: &[u8]) -> bool {
    (peek.len() < PALADIN_MAGIC.len() && PALADIN_MAGIC.starts_with(peek))
        || (peek.len() < AESCRYPT_MAGIC.len() && AESCRYPT_MAGIC.starts_with(peek))
}

/// Read up to `max` bytes, returning fewer only at end of input. Mirrors
/// `stream::read_up_to`: retries `Interrupted` and recovers a framing error the
/// armor layer wrapped in an `io::Error`.
fn read_up_to<R: Read>(reader: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; max];
    let mut filled = 0;
    while filled < max {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(match crate::error::recover_palerror(e) {
                    Ok(sym) => sym,
                    Err(e) => PalError::Io(e),
                })
            }
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run detection over `bytes` and return the format plus everything the
    /// re-chained reader yields, proving no peeked byte is lost.
    fn detect_and_drain(bytes: &[u8]) -> Result<(Format, Vec<u8>)> {
        let (format, mut reader) = detect(io::Cursor::new(bytes.to_vec()))?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).map_err(PalError::Io)?;
        Ok((format, out))
    }

    #[test]
    fn paladin_magic_is_detected_and_rechained() {
        let input = b"PALADIN\x00\x01the rest of the container";
        let (format, drained) = detect_and_drain(input).unwrap();
        assert_eq!(format, Format::Paladin);
        assert_eq!(drained, input, "re-chained reader reproduces the input");
    }

    #[test]
    fn aescrypt_magic_is_detected_and_rechained() {
        // Both a v2 and an (unsupported) version byte route to the AES parser;
        // detection does not look at the version.
        for version in [0x01u8, 0x02, 0x03, 0x7f] {
            let input = [b"AES".as_slice(), &[version, 0x00], b"more bytes"].concat();
            let (format, drained) = detect_and_drain(&input).unwrap();
            assert_eq!(format, Format::AesCrypt, "version {version:#04x}");
            assert_eq!(drained, input, "re-chained reader reproduces the input");
        }
    }

    #[test]
    fn foreign_magic_is_bad_magic() {
        // A full 8-byte prefix matching neither magic.
        assert!(matches!(
            detect_and_drain(b"GARBAGE!and more"),
            Err(PalError::BadMagic)
        ));
        // Eight bytes that share the PALADIN prefix but differ in the 8th byte.
        assert!(matches!(
            detect_and_drain(b"PALADINxtail"),
            Err(PalError::BadMagic)
        ));
    }

    #[test]
    fn short_prefix_of_a_magic_is_malformed_not_bad() {
        // Proper prefixes of PALADIN and of AES are treated as truncated headers.
        for short in [b"".as_slice(), b"P", b"PAL", b"PALADIN", b"A", b"AE"] {
            assert!(
                matches!(detect_and_drain(short), Err(PalError::MalformedHeader(_))),
                "prefix {short:?} should be MalformedHeader"
            );
        }
    }

    #[test]
    fn exactly_aes_magic_routes_to_aescrypt() {
        // The 3-byte magic alone is enough to dispatch; the AES parser then
        // reports the truncation itself.
        let (format, drained) = detect_and_drain(b"AES").unwrap();
        assert_eq!(format, Format::AesCrypt);
        assert_eq!(drained, b"AES");
    }
}
