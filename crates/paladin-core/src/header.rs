//! Binary header serialize/parse (DESIGN §5.2–§5.4, §5.7).
//!
//! The serialized header — `magic` through the optional `name` — is also the
//! AEAD associated data for chunk 0, so [`parse`] reads exactly those bytes and
//! retains them. Parsing operates on the de-armored binary stream; the armor
//! layer is stripped before the header is read.
//!
//! Unauthenticated header values are validated against the §5.4 ranges before
//! any allocation or key derivation. The magic is checked first, then the
//! version, then the cipher/KDF ids and flags, then the variable-length fields.

use std::io::{self, Read};

use crate::cipher::CipherId;
use crate::error::{Result, SymError};
use crate::kdf::{KdfId, KdfParams};

/// File magic (DESIGN §5.2): ASCII "PALADIN" plus a NUL pad to a fixed 8 bytes.
const MAGIC: &[u8; 8] = b"PALADIN\0";
/// The only format version this build writes or reads (DESIGN §5.2).
const VERSION: u8 = 0x01;
/// Allowed `flags` bits: bit0 filename-present, bit1 keyfile-used (DESIGN §5.3).
const FLAG_FILENAME: u8 = 0x01;
const FLAG_KEYFILE: u8 = 0x02;
const FLAGS_ALLOWED: u8 = FLAG_FILENAME | FLAG_KEYFILE;

// §5.4 ranges owned by the header (KDF cost ranges live in kdf.rs).
const SALT_LEN: std::ops::RangeInclusive<usize> = 16..=64;
const NONCE_PREFIX_LEN: usize = 7;
/// Valid `chunk_size` range (DESIGN §5.4); shared with encrypt-option validation.
pub(crate) const CHUNK_SIZE: std::ops::RangeInclusive<u32> = 4096..=16_777_216;
const NAME_LEN: std::ops::RangeInclusive<usize> = 1..=255;

/// Whether and how a stored original filename can be used (DESIGN §5.2, §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameStatus {
    /// No filename was stored (flag bit0 clear).
    Absent,
    /// A well-formed basename is stored and may be used for the output path.
    Present,
    /// A name is stored but fails the basename safety rules, so it is ignored
    /// and the output path is derived from the input instead.
    IgnoredUnsafe,
}

/// Parsed, **unauthenticated** header metadata (DESIGN §2.3). Carries no key
/// material and is only trustworthy once decrypt/verify succeeds. Produced by
/// the core; the `pub(crate)` fields keep front-ends from fabricating one.
#[derive(Debug, Clone)]
pub struct Header {
    /// Format version (always [`VERSION`] for a successfully parsed header).
    pub version: u8,
    /// Selected AEAD cipher.
    pub cipher: CipherId,
    /// Validated KDF parameters (their variant names the KDF).
    pub kdf_params: KdfParams,
    /// Raw `flags` byte (DESIGN §5.3); decode with the accessors.
    pub flags: u8,
    /// Plaintext bytes per STREAM chunk.
    pub chunk_size: u32,
    /// Stored filename when present and valid UTF-8 (regardless of safety).
    pub name: Option<String>,
    /// Whether/how `name` may be used (DESIGN §6.2).
    pub name_status: NameStatus,
    pub(crate) salt: Vec<u8>,
    pub(crate) nonce_prefix: [u8; NONCE_PREFIX_LEN],
    /// The exact serialized header bytes, reused as chunk-0 AAD.
    pub(crate) serialized: Vec<u8>,
}

impl Header {
    /// The KDF named by the parameter variant.
    pub fn kdf(&self) -> KdfId {
        self.kdf_params.kdf_id()
    }

    /// Whether the filename field is present (flag bit0).
    pub fn filename_present(&self) -> bool {
        self.flags & FLAG_FILENAME != 0
    }

    /// The advisory keyfile-used hint (flag bit1). Unauthenticated until
    /// decrypt/verify succeeds; never an authorization or format decision.
    pub fn keyfile_hint(&self) -> bool {
        self.flags & FLAG_KEYFILE != 0
    }

    /// Length of the stored salt in bytes.
    pub fn salt_len(&self) -> usize {
        self.salt.len()
    }

    /// Length of the stored nonce prefix in bytes (7 in v1).
    pub fn nonce_prefix_len(&self) -> usize {
        self.nonce_prefix.len()
    }

    /// The serialized header bytes used as chunk-0 AAD (DESIGN §5.1).
    pub(crate) fn aad(&self) -> &[u8] {
        &self.serialized
    }
}

/// Whether `name` is a well-formed basename per DESIGN §5.2: 1..=255 bytes, no
/// `/`, `\`, `:`, or any Unicode control character (which includes NUL), and
/// neither `.` nor `..`. Interior dots (e.g. `report.pdf`) are allowed.
///
/// Shared by header parsing (to classify a stored name) and by encrypt-option
/// validation (to reject an unsafe `--name`).
pub(crate) fn is_safe_basename(name: &str) -> bool {
    if !NAME_LEN.contains(&name.len()) || name == "." || name == ".." {
        return false;
    }
    !name
        .chars()
        .any(|c| matches!(c, '/' | '\\' | ':') || c.is_control())
}

/// Serialize a header from already-validated components (DESIGN §5.2). The
/// encrypt path validates everything first, so this performs no checks; the
/// returned bytes are both written to the output and used as chunk-0 AAD.
pub(crate) fn serialize(
    cipher: CipherId,
    kdf_params: KdfParams,
    salt: &[u8],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    chunk_size: u32,
    filename: Option<&str>,
    keyfile_used: bool,
) -> Vec<u8> {
    let mut flags = 0u8;
    if filename.is_some() {
        flags |= FLAG_FILENAME;
    }
    if keyfile_used {
        flags |= FLAG_KEYFILE;
    }
    let (p1, p2, p3) = kdf_params.to_words();

    let mut h = Vec::with_capacity(25 + salt.len() + 1 + NONCE_PREFIX_LEN + 4 + 2 + 255);
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    h.push(cipher.id());
    h.push(kdf_params.kdf_id().id());
    h.push(flags);
    h.extend_from_slice(&p1.to_be_bytes());
    h.extend_from_slice(&p2.to_be_bytes());
    h.extend_from_slice(&p3.to_be_bytes());
    h.push(salt.len() as u8);
    h.extend_from_slice(salt);
    h.push(NONCE_PREFIX_LEN as u8);
    h.extend_from_slice(nonce_prefix);
    h.extend_from_slice(&chunk_size.to_be_bytes());
    if let Some(name) = filename {
        h.extend_from_slice(&(name.len() as u16).to_be_bytes());
        h.extend_from_slice(name.as_bytes());
    }
    h
}

/// Parse and validate a header from `reader`, leaving it positioned at the first
/// body byte. The returned [`Header`] retains the serialized bytes for use as
/// chunk-0 AAD (DESIGN §5.1).
pub(crate) fn parse<R: Read>(reader: &mut R) -> Result<Header> {
    let mut h: Vec<u8> = Vec::with_capacity(64);

    read_field(reader, &mut h, 8)?;
    if &h[0..8] != MAGIC {
        return Err(SymError::BadMagic);
    }

    read_field(reader, &mut h, 1)?;
    let version = h[8];
    if version != VERSION {
        return Err(SymError::UnsupportedVersion(version));
    }

    // cipher_id, kdf_id, flags
    read_field(reader, &mut h, 3)?;
    let cipher = CipherId::from_id(h[9])?;
    let kdf = KdfId::from_id(h[10])?;
    let flags = h[11];
    if flags & !FLAGS_ALLOWED != 0 {
        return Err(SymError::ReservedFlags(flags));
    }

    // kdf_p1, kdf_p2, kdf_p3
    read_field(reader, &mut h, 12)?;
    let p1 = u32::from_be_bytes(h[12..16].try_into().unwrap());
    let p2 = u32::from_be_bytes(h[16..20].try_into().unwrap());
    let p3 = u32::from_be_bytes(h[20..24].try_into().unwrap());
    let kdf_params = KdfParams::from_words(kdf, p1, p2, p3).map_err(SymError::MalformedHeader)?;

    // salt_len then salt
    read_field(reader, &mut h, 1)?;
    let salt_len = usize::from(h[24]);
    if !SALT_LEN.contains(&salt_len) {
        return Err(SymError::MalformedHeader("salt_len out of range (16..=64)"));
    }
    read_field(reader, &mut h, salt_len)?;
    let salt = h[25..25 + salt_len].to_vec();

    // nonce_prefix_len then nonce_prefix
    let npl_off = 25 + salt_len;
    read_field(reader, &mut h, 1)?;
    let nonce_prefix_len = usize::from(h[npl_off]);
    if nonce_prefix_len != NONCE_PREFIX_LEN {
        return Err(SymError::MalformedHeader("nonce_prefix_len must be 7"));
    }
    let np_off = npl_off + 1;
    read_field(reader, &mut h, nonce_prefix_len)?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&h[np_off..np_off + NONCE_PREFIX_LEN]);

    // chunk_size
    let cs_off = np_off + NONCE_PREFIX_LEN;
    read_field(reader, &mut h, 4)?;
    let chunk_size = u32::from_be_bytes(h[cs_off..cs_off + 4].try_into().unwrap());
    if !CHUNK_SIZE.contains(&chunk_size) {
        return Err(SymError::MalformedHeader(
            "chunk_size out of range (4096..=16777216)",
        ));
    }

    // optional name
    let (name, name_status) = if flags & FLAG_FILENAME != 0 {
        let nl_off = cs_off + 4;
        read_field(reader, &mut h, 2)?;
        let name_len = usize::from(u16::from_be_bytes(
            h[nl_off..nl_off + 2].try_into().unwrap(),
        ));
        if !NAME_LEN.contains(&name_len) {
            return Err(SymError::MalformedHeader("name_len out of range (1..=255)"));
        }
        let n_off = nl_off + 2;
        read_field(reader, &mut h, name_len)?;
        let name = std::str::from_utf8(&h[n_off..n_off + name_len])
            .map_err(|_| SymError::MalformedHeader("stored name is not valid UTF-8"))?;
        let status = if is_safe_basename(name) {
            NameStatus::Present
        } else {
            NameStatus::IgnoredUnsafe
        };
        (Some(name.to_owned()), status)
    } else {
        (None, NameStatus::Absent)
    };

    Ok(Header {
        version,
        cipher,
        kdf_params,
        flags,
        chunk_size,
        name,
        name_status,
        salt,
        nonce_prefix,
        serialized: h,
    })
}

/// Read exactly `n` bytes from `reader`, appending them to `sink`. A short read
/// (truncated header) becomes [`SymError::MalformedHeader`]; a framing error
/// from the armor layer is recovered with its original variant; other I/O errors
/// propagate as [`SymError::Io`].
fn read_field<R: Read>(reader: &mut R, sink: &mut Vec<u8>, n: usize) -> Result<()> {
    let start = sink.len();
    sink.resize(start + n, 0);
    reader
        .read_exact(&mut sink[start..])
        .map_err(|e| match crate::error::recover_symerror(e) {
            Ok(sym) => sym,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                SymError::MalformedHeader("unexpected end of input before header was complete")
            }
            Err(e) => SymError::Io(e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT16: [u8; 16] = [0xAB; 16];
    const NPREFIX: [u8; 7] = [0xCD; 7];

    fn argon() -> KdfParams {
        KdfParams::default_for(KdfId::Argon2id)
    }

    /// A valid default header (no name, no keyfile bit).
    fn default_bytes() -> Vec<u8> {
        serialize(
            CipherId::Aes256Gcm,
            argon(),
            &SALT16,
            &NPREFIX,
            65536,
            None,
            false,
        )
    }

    fn parse_bytes(bytes: &[u8]) -> Result<Header> {
        parse(&mut io::Cursor::new(bytes.to_vec()))
    }

    #[test]
    fn round_trip_over_cipher_kdf_and_flag_combinations() {
        for cipher in [CipherId::Aes256Gcm, CipherId::ChaCha20Poly1305] {
            for kdf in [KdfId::Argon2id, KdfId::Scrypt, KdfId::Pbkdf2] {
                for name in [None, Some("report.pdf")] {
                    for keyfile in [false, true] {
                        let params = KdfParams::default_for(kdf);
                        let bytes =
                            serialize(cipher, params, &SALT16, &NPREFIX, 65536, name, keyfile);
                        let h = parse_bytes(&bytes).unwrap();
                        assert_eq!(h.version, VERSION);
                        assert_eq!(h.cipher, cipher);
                        assert_eq!(h.kdf(), kdf);
                        assert_eq!(h.kdf_params, params);
                        assert_eq!(h.chunk_size, 65536);
                        assert_eq!(h.salt, SALT16);
                        assert_eq!(h.nonce_prefix, NPREFIX);
                        assert_eq!(h.filename_present(), name.is_some());
                        assert_eq!(h.keyfile_hint(), keyfile);
                        assert_eq!(h.name.as_deref(), name);
                        // Serialized bytes (AAD) reproduce the input exactly.
                        assert_eq!(h.aad(), &bytes[..]);
                    }
                }
            }
        }
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = default_bytes();
        bytes[0] = b'X';
        assert!(matches!(parse_bytes(&bytes), Err(SymError::BadMagic)));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut bytes = default_bytes();
        bytes[8] = 0x02;
        assert!(matches!(
            parse_bytes(&bytes),
            Err(SymError::UnsupportedVersion(0x02))
        ));
    }

    #[test]
    fn unknown_cipher_and_kdf_ids_are_rejected() {
        let mut c = default_bytes();
        c[9] = 0x09;
        assert!(matches!(
            parse_bytes(&c),
            Err(SymError::UnknownCipher(0x09))
        ));

        let mut k = default_bytes();
        k[10] = 0x09;
        assert!(matches!(parse_bytes(&k), Err(SymError::UnknownKdf(0x09))));
    }

    #[test]
    fn reserved_flag_bits_are_rejected() {
        for bit in [0x04u8, 0x08, 0x80] {
            let mut bytes = default_bytes();
            bytes[11] |= bit;
            assert!(matches!(
                parse_bytes(&bytes),
                Err(SymError::ReservedFlags(_))
            ));
        }
    }

    #[test]
    fn out_of_range_lengths_are_malformed() {
        // salt_len at offset 24
        for bad_salt_len in [0u8, 15, 65] {
            let mut bytes = default_bytes();
            bytes[24] = bad_salt_len;
            assert!(
                matches!(parse_bytes(&bytes), Err(SymError::MalformedHeader(_))),
                "salt_len {bad_salt_len}"
            );
        }
        // nonce_prefix_len at offset 25+16 = 41
        let mut np = default_bytes();
        np[41] = 8;
        assert!(matches!(
            parse_bytes(&np),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn out_of_range_chunk_size_is_malformed() {
        // chunk_size at offset 25+16+1+7 = 49
        for bad in [0u32, 4095, 16_777_217] {
            let mut bytes = default_bytes();
            bytes[49..53].copy_from_slice(&bad.to_be_bytes());
            assert!(
                matches!(parse_bytes(&bytes), Err(SymError::MalformedHeader(_))),
                "chunk_size {bad}"
            );
        }
    }

    #[test]
    fn out_of_range_kdf_cost_in_header_is_malformed() {
        // Argon2id memory (kdf_p1 at 12..16) set below the minimum.
        let mut bytes = default_bytes();
        bytes[12..16].copy_from_slice(&100u32.to_be_bytes());
        assert!(matches!(
            parse_bytes(&bytes),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn non_utf8_stored_name_is_malformed() {
        // Build a header with a name flag and invalid UTF-8 name bytes.
        let bytes = serialize(
            CipherId::Aes256Gcm,
            argon(),
            &SALT16,
            &NPREFIX,
            65536,
            Some("ok"),
            false,
        );
        // Replace the 2-byte name "ok" (offset 55..57) with invalid UTF-8.
        let mut bytes = bytes;
        let n_off = 25 + 16 + 1 + 7 + 4 + 2; // = 55
        bytes[n_off] = 0xFF;
        bytes[n_off + 1] = 0xFE;
        assert!(matches!(
            parse_bytes(&bytes),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn unsafe_but_valid_utf8_name_is_ignored_not_rejected() {
        // A name with a path separator parses, but is classified IgnoredUnsafe.
        let bytes = serialize(
            CipherId::Aes256Gcm,
            argon(),
            &SALT16,
            &NPREFIX,
            65536,
            Some("a/b"),
            false,
        );
        let h = parse_bytes(&bytes).unwrap();
        assert_eq!(h.name_status, NameStatus::IgnoredUnsafe);
        assert_eq!(h.name.as_deref(), Some("a/b"));
    }

    #[test]
    fn safe_name_is_present() {
        let bytes = serialize(
            CipherId::Aes256Gcm,
            argon(),
            &SALT16,
            &NPREFIX,
            65536,
            Some("report.final.pdf"),
            false,
        );
        let h = parse_bytes(&bytes).unwrap();
        assert_eq!(h.name_status, NameStatus::Present);
        assert_eq!(h.name.as_deref(), Some("report.final.pdf"));
    }

    #[test]
    fn truncated_header_is_malformed_not_a_panic() {
        let full = default_bytes();
        // Every proper prefix that stops mid-header must be MalformedHeader.
        for cut in [0usize, 3, 8, 9, 12, 24, 30, 49, full.len() - 1] {
            assert!(
                matches!(parse_bytes(&full[..cut]), Err(SymError::MalformedHeader(_))),
                "prefix len {cut}"
            );
        }
    }

    #[test]
    fn is_safe_basename_rules() {
        for ok in [
            "report.pdf",
            "a",
            "café.txt",
            "..hidden",
            "name with spaces",
        ] {
            assert!(is_safe_basename(ok), "{ok:?} should be safe");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "a:b",
            "a\0b",
            "tab\tname",
            "del\x7f",
        ] {
            assert!(!is_safe_basename(bad), "{bad:?} should be unsafe");
        }
        // 255 bytes is the limit; 256 is too long.
        assert!(is_safe_basename(&"x".repeat(255)));
        assert!(!is_safe_basename(&"x".repeat(256)));
    }
}
