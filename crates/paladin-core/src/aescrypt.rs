//! AES Crypt (`.aes`) read interop: header parse, the v1/v2 KDF, `hmac1` key
//! unwrap, and the streaming CBC+`hmac2` body (PLAN_05 §2, §5).
//!
//! AES Crypt is **encrypt-then-MAC**: AES-256-CBC for confidentiality and
//! HMAC-SHA256 for integrity, with a two-level key hierarchy. This module reads
//! **Stream Format 1 and 2** (current `aescrypt` 3.x output and older files).
//! **Format 3** (PBKDF2-HMAC-SHA512) is not yet implemented — its version byte
//! is rejected as [`PalError::UnsupportedAesCryptVersion`] (PLAN_05 v3 deferral).
//!
//! This legacy format is **only ever read**; paladin never writes it. The
//! header, extensions, and the `fsmod` byte are **unauthenticated** (outside both
//! HMACs); see PLAN_05 §4. A wrong password is caught early at `hmac1`, before
//! any body byte; tampering/truncation is reported as the single
//! [`PalError::Auth`] condition, never distinguished from a wrong password.

use std::io::{self, Read, Write};
use std::ops::ControlFlow;

use cbc::cipher::generic_array::GenericArray;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{PalError, Result};
use crate::secret::Secret;
use crate::stream::{OnProgress, Progress};

/// AES Crypt file magic (PLAN_05 §2.1).
const MAGIC: &[u8; 3] = b"AES";
/// Iterated-SHA-256 count for the v1/v2 KDF (PLAN_05 §2.4).
const KDF_ITERATIONS: u32 = 8192;
/// Field sizes (PLAN_05 §2.1).
const IV_LEN: usize = 16;
const ENC_KEYS_LEN: usize = 48;
const HMAC_LEN: usize = 32;
const FSMOD_LEN: usize = 1;
const BLOCK_LEN: usize = 16;
/// v1/v2 body trailer = `fsmod(1) ‖ hmac2(32)` (PLAN_05 §5.7).
const TRAILER_LEN: usize = FSMOD_LEN + HMAC_LEN;
/// Resource bounds on the unauthenticated extension block (PLAN_05 §5.6).
const MAX_EXT_TOTAL_BYTES: usize = 256 * 1024;
const MAX_EXT_COUNT: usize = 1024;
/// Conventional `CREATED_BY` extension identifier (PLAN_05 §2.3).
const CREATED_BY_ID: &[u8] = b"CREATED_BY";
/// Max `char`s of a sanitized `CREATED_BY` value surfaced by `inspect`.
const CREATED_BY_MAX_CHARS: usize = 256;
/// Body read granularity, matching the STREAM path (PLAN_05 §5.5).
const BODY_READ_CHUNK: usize = 64 * 1024;
/// v1 plaintext size cap: 64 GiB, identical to the STREAM path (DESIGN §4.3).
const MAX_PLAINTEXT: u64 = 64 * 1024 * 1024 * 1024;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Public, unauthenticated metadata (powers `inspect`).
// ---------------------------------------------------------------------------

/// Unauthenticated AES Crypt header metadata (PLAN_05 §5.8). Carries no key
/// material and is only a *description*: nothing here is authenticated, even
/// after a successful decrypt (the AES Crypt header is outside both HMACs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCryptHeader {
    /// Stream-format version (1 or 2).
    pub version: u8,
    /// The KDF the container uses.
    pub kdf: AesCryptKdf,
    /// Number of extensions present (v2; always 0 for v1).
    pub extension_count: usize,
    /// Sanitized `CREATED_BY` value, when present and decodable.
    pub created_by: Option<String>,
}

/// The KDF an AES Crypt container uses (PLAN_05 §5.8). Stream Format 3 will add
/// a `Pbkdf2HmacSha512` variant; until then only the v1/v2 KDF exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesCryptKdf {
    /// v1/v2: iterated SHA-256 (always 8192 iterations).
    Sha256 { iterations: u32 },
}

impl AesCryptKdf {
    /// The display name for `--info` (PLAN_05 §5.8).
    pub fn name(&self) -> &'static str {
        match self {
            AesCryptKdf::Sha256 { .. } => "aescrypt-sha256",
        }
    }

    /// The iteration count for `--info` (PLAN_05 §5.8).
    pub fn iterations(&self) -> u32 {
        match self {
            AesCryptKdf::Sha256 { iterations } => *iterations,
        }
    }
}

// ---------------------------------------------------------------------------
// Header parsing (unauthenticated).
// ---------------------------------------------------------------------------

/// The parsed, unauthenticated header plus the raw key-wrap material needed to
/// derive keys and verify `hmac1`.
struct ParsedHeader {
    version: u8,
    iv1: [u8; IV_LEN],
    enc_keys: [u8; ENC_KEYS_LEN],
    hmac1: [u8; HMAC_LEN],
    extension_count: usize,
    created_by: Option<String>,
    /// Total header bytes consumed (magic..hmac1), for progress reporting.
    header_len: u64,
}

/// Parse magic through `hmac1`, leaving `reader` positioned at the first body
/// byte. Validates the magic, the supported version, the reserved byte, and the
/// extension framing; derives no key and authenticates nothing.
fn parse_header<R: Read>(reader: &mut R) -> Result<ParsedHeader> {
    let magic: [u8; 3] = read_array(reader)?;
    if &magic != MAGIC {
        // format::detect already classified this as AES Crypt; a mismatch here
        // means the stream changed under us. Treat as a malformed header.
        return Err(PalError::MalformedHeader("not an AES Crypt file"));
    }
    let version = read_array::<_, 1>(reader)?[0];
    if version != 0x01 && version != 0x02 {
        return Err(PalError::UnsupportedAesCryptVersion(version));
    }
    let reserved = read_array::<_, 1>(reader)?[0];
    if reserved != 0x00 {
        return Err(PalError::MalformedHeader(
            "AES Crypt reserved byte must be zero",
        ));
    }

    // Extensions exist only in v2; v1 jumps straight to iv1.
    let (extension_count, created_by, ext_bytes) = if version == 0x02 {
        parse_extensions(reader)?
    } else {
        (0, None, 0)
    };

    let iv1: [u8; IV_LEN] = read_array(reader)?;
    let enc_keys: [u8; ENC_KEYS_LEN] = read_array(reader)?;
    let hmac1: [u8; HMAC_LEN] = read_array(reader)?;

    let header_len = (3 + 1 + 1 + IV_LEN + ENC_KEYS_LEN + HMAC_LEN + ext_bytes) as u64;
    Ok(ParsedHeader {
        version,
        iv1,
        enc_keys,
        hmac1,
        extension_count,
        created_by,
        header_len,
    })
}

/// Parse the v2 extension block: repeated `(u16 len, len bytes)` until a
/// `len == 0` terminator. Bounds the total content bytes and the count so a
/// hostile file cannot force unbounded buffering (PLAN_05 §5.6, implication #7).
/// Returns `(count, sanitized CREATED_BY, total bytes consumed by the block)`.
fn parse_extensions<R: Read>(reader: &mut R) -> Result<(usize, Option<String>, usize)> {
    let mut count = 0usize;
    let mut total = 0usize;
    let mut bytes = 0usize; // includes the length prefixes and terminator
    let mut created_by: Option<String> = None;
    let mut created_by_seen = false;
    loop {
        let len = u16::from_be_bytes(read_array(reader)?) as usize;
        bytes += 2;
        if len == 0 {
            break; // terminator
        }
        count += 1;
        if count > MAX_EXT_COUNT {
            return Err(PalError::MalformedHeader("too many AES Crypt extensions"));
        }
        total += len;
        if total > MAX_EXT_TOTAL_BYTES {
            return Err(PalError::MalformedHeader(
                "AES Crypt extensions exceed the size bound",
            ));
        }
        let content = read_vec(reader, len)?;
        bytes += len;
        if !created_by_seen {
            if let Some(value) = classify_created_by(&content) {
                created_by_seen = true; // honor only the first CREATED_BY
                created_by = value;
            }
        }
    }
    Ok((count, created_by, bytes))
}

/// Classify an extension's content as a `CREATED_BY` value. Returns `None` if the
/// identifier is not `CREATED_BY`; `Some(None)` if it is but the data is absent
/// or not valid UTF-8; `Some(Some(value))` for a sanitized value (PLAN_05 §5.6).
/// Content is `identifier ‖ 0x00 ‖ data`; control characters are replaced with
/// `?` and the value is capped at [`CREATED_BY_MAX_CHARS`]. Extension contents
/// are never interpreted as paths or commands.
fn classify_created_by(content: &[u8]) -> Option<Option<String>> {
    let (identifier, data) = match content.iter().position(|&b| b == 0) {
        Some(nul) => (&content[..nul], Some(&content[nul + 1..])),
        None => (content, None),
    };
    if identifier != CREATED_BY_ID {
        return None;
    }
    let value = data
        .and_then(|d| std::str::from_utf8(d).ok())
        .map(sanitize_created_by);
    Some(value)
}

/// Replace Unicode control characters with `?` and cap the length (PLAN_05 §5.6).
fn sanitize_created_by(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(CREATED_BY_MAX_CHARS)
        .collect()
}

// ---------------------------------------------------------------------------
// `inspect` — describe without a password.
// ---------------------------------------------------------------------------

/// Parse the unauthenticated header and return its metadata (PLAN_05 §5.8). No
/// password is needed and nothing is authenticated.
pub(crate) fn inspect<R: Read>(mut reader: R) -> Result<AesCryptHeader> {
    let h = parse_header(&mut reader)?;
    Ok(AesCryptHeader {
        version: h.version,
        kdf: AesCryptKdf::Sha256 {
            iterations: KDF_ITERATIONS,
        },
        extension_count: h.extension_count,
        created_by: h.created_by,
    })
}

// ---------------------------------------------------------------------------
// decrypt / verify.
// ---------------------------------------------------------------------------

/// Decrypt an AES Crypt container to `output`, verifying both HMACs.
pub(crate) fn decrypt<R: Read, W: Write>(
    input: R,
    output: W,
    secret: &Secret,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
) -> Result<()> {
    decrypt_impl(input, output, secret, input_len, on_progress, MAX_PLAINTEXT)
}

/// Verify integrity by decrypting and discarding the plaintext (DESIGN §6.2).
pub(crate) fn verify<R: Read>(
    input: R,
    secret: &Secret,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
) -> Result<()> {
    decrypt_impl(
        input,
        io::sink(),
        secret,
        input_len,
        on_progress,
        MAX_PLAINTEXT,
    )
}

fn decrypt_impl<R: Read, W: Write>(
    mut reader: R,
    mut output: W,
    secret: &Secret,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
    max_plaintext: u64,
) -> Result<()> {
    let h = parse_header(&mut reader)?;
    report(on_progress, h.header_len, input_len)?; // after header, before KDF

    // Reject secrets incompatible with the AES Crypt format (implication #8): no
    // paladin-style keyfile component exists, and a password is required.
    if secret.has_keyfile() {
        return Err(PalError::InvalidOptions(
            "AES Crypt files do not use a paladin keyfile; pass the password directly (a UTF-8 --password-file may hold an AES Crypt key file)",
        ));
    }
    if secret.password_bytes().is_empty() {
        return Err(PalError::InvalidOptions(
            "AES Crypt files require a password",
        ));
    }
    // Validate the password as UTF-8 text and re-encode it UTF-16LE (PLAN_05 §2.4).
    let pw16 = password_utf16le(secret.password_bytes())?;

    let key1 = derive_key1(&pw16, &h.iv1);
    report(on_progress, h.header_len, input_len)?; // after KDF (no output yet)

    // Verify hmac1 before touching the body: this is the early wrong-password
    // gate (implication #5). For v1/v2 the input is enc_keys (no 0x03 suffix).
    verify_one_shot(&key1[..], &h.enc_keys, &h.hmac1)?;
    let (iv2, key2) = unwrap_keys(&key1, &h.iv1, &h.enc_keys);

    // Stream the body, holding back the last TRAILER_LEN bytes as the trailer
    // candidate and deferring the final plaintext block for fsmod truncation.
    let mut body = Body::new(&key2, &iv2, max_plaintext)?;
    let mut window: Vec<u8> = Vec::with_capacity(BODY_READ_CHUNK + TRAILER_LEN);
    let mut consumed = h.header_len;
    loop {
        let chunk = read_up_to(&mut reader, BODY_READ_CHUNK)?;
        if chunk.is_empty() {
            break;
        }
        consumed = consumed.saturating_add(chunk.len() as u64);
        window.extend_from_slice(&chunk);
        if window.len() > TRAILER_LEN {
            let release = window.len() - TRAILER_LEN;
            body.push(&window[..release], &mut output)?;
            window.drain(..release);
        }
        report(on_progress, consumed, input_len)?;
    }

    // At EOF the window holds exactly the trailer; anything shorter is a
    // truncated body (indistinguishable from tampering -> Auth).
    if window.len() < TRAILER_LEN {
        return Err(PalError::Auth);
    }
    let fsmod = window[0];
    let mut hmac2 = [0u8; HMAC_LEN];
    hmac2.copy_from_slice(&window[FSMOD_LEN..TRAILER_LEN]);
    body.finish(fsmod, &hmac2, &mut output)
}

/// Streaming state for the CBC+`hmac2` body. Holds the running HMAC, the CBC
/// decryptor, a sub-block ciphertext carry, and the most recently decrypted
/// plaintext block (whose write is deferred by one block so the final block can
/// be `fsmod`-truncated — the core's `Write` is not seekable, PLAN_05 §5.7).
struct Body {
    cbc: Aes256CbcDec,
    mac2: HmacSha256,
    ct_carry: Vec<u8>,
    held: Option<[u8; BLOCK_LEN]>,
    plaintext_len: u64,
    max_plaintext: u64,
}

impl Body {
    fn new(key2: &[u8; 32], iv2: &[u8; IV_LEN], max_plaintext: u64) -> Result<Self> {
        Ok(Self {
            cbc: Aes256CbcDec::new_from_slices(key2, iv2)
                .map_err(|_| PalError::MalformedHeader("invalid AES Crypt body key/iv length"))?,
            mac2: HmacSha256::new_from_slice(key2).expect("HMAC accepts any key length"),
            ct_carry: Vec::with_capacity(2 * BLOCK_LEN),
            held: None,
            plaintext_len: 0,
            max_plaintext,
        })
    }

    /// Feed confirmed-ciphertext bytes: authenticate and CBC-decrypt each
    /// complete 16-byte block, deferring the newest plaintext block by one.
    fn push<W: Write>(&mut self, bytes: &[u8], output: &mut W) -> Result<()> {
        self.ct_carry.extend_from_slice(bytes);
        while self.ct_carry.len() >= BLOCK_LEN {
            self.mac2.update(&self.ct_carry[..BLOCK_LEN]);
            let mut block = GenericArray::clone_from_slice(&self.ct_carry[..BLOCK_LEN]);
            self.cbc.decrypt_block_mut(&mut block);
            self.ct_carry.drain(..BLOCK_LEN);
            let mut pt = [0u8; BLOCK_LEN];
            pt.copy_from_slice(&block);
            if let Some(prev) = self.held.replace(pt) {
                self.emit(&prev, BLOCK_LEN, output)?;
            }
        }
        Ok(())
    }

    /// Write `n` plaintext bytes from `block`, enforcing the size cap.
    fn emit<W: Write>(&mut self, block: &[u8; BLOCK_LEN], n: usize, output: &mut W) -> Result<()> {
        self.plaintext_len += n as u64;
        if self.plaintext_len > self.max_plaintext {
            return Err(PalError::InputTooLarge);
        }
        output.write_all(&block[..n]).map_err(PalError::Io)
    }

    /// At EOF: verify `hmac2` over all ciphertext, then finalize the held block
    /// per the unauthenticated `fsmod` (PLAN_05 §5.5 steps 8–9). `hmac2` is
    /// checked **before** the final block is truncated, so no unverified
    /// plaintext is ever produced.
    fn finish<W: Write>(self, fsmod: u8, hmac2: &[u8; HMAC_LEN], output: &mut W) -> Result<()> {
        let Body {
            mac2,
            ct_carry,
            held,
            plaintext_len,
            max_plaintext,
            ..
        } = self;
        // Leftover sub-block ciphertext means the run is not a multiple of 16.
        if !ct_carry.is_empty() {
            return Err(PalError::Auth);
        }
        mac2.verify_slice(hmac2).map_err(|_| PalError::Auth)?;

        match held {
            Some(block) => {
                // The legacy format stores only fsmod; do not validate the
                // final block's filler bytes (they are not PKCS#7 in v1/v2).
                if fsmod >= BLOCK_LEN as u8 {
                    return Err(PalError::MalformedHeader("AES Crypt fsmod must be < 16"));
                }
                let n = if fsmod == 0 {
                    BLOCK_LEN
                } else {
                    fsmod as usize
                };
                if plaintext_len + n as u64 > max_plaintext {
                    return Err(PalError::InputTooLarge);
                }
                output.write_all(&block[..n]).map_err(PalError::Io)?;
            }
            None => {
                // Zero ciphertext blocks: fsmod must be 0 and nothing is written.
                if fsmod != 0 {
                    return Err(PalError::MalformedHeader(
                        "AES Crypt fsmod is nonzero but the body is empty",
                    ));
                }
            }
        }
        output.flush().map_err(PalError::Io)
    }
}

// ---------------------------------------------------------------------------
// KDF and key unwrap.
// ---------------------------------------------------------------------------

/// Re-encode the password as UTF-16LE (PLAN_05 §2.4). The paladin front-ends
/// capture passwords as UTF-8 bytes; AES Crypt v1/v2 hashes the UTF-16LE text,
/// so non-UTF-8 password bytes are rejected as [`PalError::InvalidOptions`].
fn password_utf16le(password_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(password_bytes)
        .map_err(|_| PalError::InvalidOptions("AES Crypt password must be valid UTF-8 text"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 2));
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(out)
}

/// Derive `key1` with the v1/v2 KDF (PLAN_05 §2.4): start from `iv1 ‖ 16 zero
/// bytes` and iterate `digest = SHA256(digest ‖ pw16)` 8192 times.
fn derive_key1(pw16: &[u8], iv1: &[u8; IV_LEN]) -> Zeroizing<[u8; 32]> {
    let mut digest = Zeroizing::new([0u8; 32]);
    digest[..IV_LEN].copy_from_slice(iv1);
    for _ in 0..KDF_ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(&digest[..]);
        hasher.update(pw16);
        digest.copy_from_slice(&hasher.finalize());
    }
    digest
}

/// AES-256-CBC-decrypt the 48-byte key block with `(key1, iv1)` to recover
/// `iv2 ‖ key2` (PLAN_05 §2.4). `key2` is returned zeroizing.
fn unwrap_keys(
    key1: &[u8; 32],
    iv1: &[u8; IV_LEN],
    enc_keys: &[u8; ENC_KEYS_LEN],
) -> ([u8; IV_LEN], Zeroizing<[u8; 32]>) {
    let mut dec =
        Aes256CbcDec::new_from_slices(key1, iv1).expect("key1 is 32 bytes and iv1 is 16 bytes");
    let mut buf = Zeroizing::new(*enc_keys);
    for chunk in buf.chunks_exact_mut(BLOCK_LEN) {
        dec.decrypt_block_mut(GenericArray::from_mut_slice(chunk));
    }
    let mut iv2 = [0u8; IV_LEN];
    iv2.copy_from_slice(&buf[..IV_LEN]);
    let mut key2 = Zeroizing::new([0u8; 32]);
    key2.copy_from_slice(&buf[IV_LEN..ENC_KEYS_LEN]);
    (iv2, key2)
}

/// Constant-time one-shot HMAC-SHA256 verification (PLAN_05 §5, implication #6).
fn verify_one_shot(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(tag).map_err(|_| PalError::Auth)
}

// ---------------------------------------------------------------------------
// Small I/O helpers (mirrors of the STREAM path's reads).
// ---------------------------------------------------------------------------

/// Report progress and observe cancellation. A `Break` becomes `Canceled`.
fn report(on_progress: &mut OnProgress<'_>, done: u64, total: Option<u64>) -> Result<()> {
    match on_progress(Progress { done, total }) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(()) => Err(PalError::Canceled),
    }
}

/// Read exactly `N` bytes for a fixed header field; a short read is a truncated
/// header ([`PalError::MalformedHeader`]).
fn read_array<R: Read, const N: usize>(reader: &mut R) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    fill_exact(reader, &mut buf)?;
    Ok(buf)
}

/// Read exactly `n` bytes for a variable header field.
fn read_vec<R: Read>(reader: &mut R, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    fill_exact(reader, &mut buf)?;
    Ok(buf)
}

/// Fill `buf` exactly, mapping EOF mid-field to a malformed header and recovering
/// an armor framing error wrapped by the reader.
fn fill_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(PalError::MalformedHeader(
                    "unexpected end of input before the AES Crypt header was complete",
                ))
            }
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
    Ok(())
}

/// Read up to `max` body bytes, returning fewer only at end of input.
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

    // Genuine AES Crypt fixtures minted by `aescrypt 3.16.1` (Stream Format 2);
    // v1 is mechanically derived from v2. See tests/data/aescrypt/generate.py.
    const V1_SIZE_17: &[u8] = include_bytes!("../tests/data/aescrypt/v1_size_17.aes");
    const V2_SIZE_0: &[u8] = include_bytes!("../tests/data/aescrypt/v2_size_0.aes");
    const V2_SIZE_1: &[u8] = include_bytes!("../tests/data/aescrypt/v2_size_1.aes");
    const V2_SIZE_15: &[u8] = include_bytes!("../tests/data/aescrypt/v2_size_15.aes");
    const V2_SIZE_16: &[u8] = include_bytes!("../tests/data/aescrypt/v2_size_16.aes");
    const V2_SIZE_17: &[u8] = include_bytes!("../tests/data/aescrypt/v2_size_17.aes");
    const V2_SIZE_3000: &[u8] = include_bytes!("../tests/data/aescrypt/v2_size_3000.aes");
    const V2_NONASCII: &[u8] = include_bytes!("../tests/data/aescrypt/v2_nonascii_pw_size_17.aes");

    const PASSWORD: &[u8] = b"aescrypt test password";
    const NONASCII_PW: &[u8] = "pÄsswörd".as_bytes();

    /// The deterministic fixture plaintext: byte[i] = i % 251.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn secret(pw: &[u8]) -> Secret {
        Secret::new(pw, None).unwrap()
    }

    fn noop() -> impl FnMut(Progress) -> ControlFlow<()> {
        |_| ControlFlow::Continue(())
    }

    fn dec(ct: &[u8], pw: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut cb = noop();
        decrypt(ct, &mut out, &secret(pw), None, &mut cb)?;
        Ok(out)
    }

    /// The header length (magic..hmac1) of a fixture, so offset-based tamper
    /// tests stay robust to the extension block's exact size.
    fn header_len(ct: &[u8]) -> usize {
        parse_header(&mut io::Cursor::new(ct.to_vec()))
            .unwrap()
            .header_len as usize
    }

    // --- KDF (independently anchored, see generate.py / Python cross-check) ---

    #[test]
    fn kdf_vector_is_locked() {
        // password "aescrypt test password" + the iv1 of v2_size_0.aes derive a
        // key1 computed independently with Python hashlib; locking it guards
        // against silent KDF drift (PLAN_05 §5.10 step 2).
        let iv1: [u8; IV_LEN] = hex::decode("6365a99ff7040f4da3b7190a873ea62d").unwrap()[..]
            .try_into()
            .unwrap();
        let pw16 = password_utf16le(PASSWORD).unwrap();
        let key1 = derive_key1(&pw16, &iv1);
        assert_eq!(
            hex::encode(&key1[..]),
            "be80f0d79a635328fb790105c9b14827590da02f3bbe94cd40185ab35971d472"
        );
    }

    #[test]
    fn password_is_utf16le_encoded() {
        assert_eq!(
            &password_utf16le(b"AB").unwrap()[..],
            &[0x41, 0x00, 0x42, 0x00]
        );
        // A non-ASCII char encodes as its little-endian UTF-16 code unit.
        assert_eq!(
            &password_utf16le("ä".as_bytes()).unwrap()[..],
            &[0xE4, 0x00]
        );
        // Non-UTF-8 password bytes are rejected before any derivation.
        assert!(matches!(
            password_utf16le(&[0xFF, 0xFE]),
            Err(PalError::InvalidOptions(_))
        ));
    }

    // --- Round-trip against genuine fixtures ---

    #[test]
    fn round_trip_all_v2_sizes() {
        let cases = [
            (V2_SIZE_0, 0usize),
            (V2_SIZE_1, 1),
            (V2_SIZE_15, 15),
            (V2_SIZE_16, 16),
            (V2_SIZE_17, 17),
            (V2_SIZE_3000, 3000),
        ];
        for (ct, n) in cases {
            assert_eq!(dec(ct, PASSWORD).unwrap(), pattern(n), "size {n}");
        }
    }

    #[test]
    fn round_trip_v1_fixture() {
        // v1 has no extension block; the KDF, body, and HMACs are identical.
        assert_eq!(dec(V1_SIZE_17, PASSWORD).unwrap(), pattern(17));
    }

    #[test]
    fn round_trip_non_ascii_password() {
        // Confirms the UTF-16LE re-encoding interoperates with the reference tool.
        assert_eq!(dec(V2_NONASCII, NONASCII_PW).unwrap(), pattern(17));
    }

    #[test]
    fn verify_accepts_valid_and_writes_nothing() {
        let mut cb = noop();
        assert!(verify(V2_SIZE_3000, &secret(PASSWORD), None, &mut cb).is_ok());
    }

    // --- inspect ---

    #[test]
    fn inspect_reads_v2_metadata_without_a_password() {
        let h = inspect(V2_SIZE_0).unwrap();
        assert_eq!(h.version, 2);
        assert_eq!(h.kdf, AesCryptKdf::Sha256 { iterations: 8192 });
        assert_eq!(h.kdf.name(), "aescrypt-sha256");
        assert_eq!(h.kdf.iterations(), 8192);
        assert_eq!(h.extension_count, 2); // CREATED_BY + 128-byte container
        assert_eq!(h.created_by.as_deref(), Some("aescrypt 3.16.1"));
    }

    #[test]
    fn inspect_reads_v1_metadata_with_no_extensions() {
        let h = inspect(V1_SIZE_17).unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.extension_count, 0);
        assert_eq!(h.created_by, None);
    }

    // --- Wrong password / tamper / truncate (all -> Auth) ---

    #[test]
    fn wrong_password_fails_at_hmac1_with_no_output() {
        let mut out = Vec::new();
        let mut cb = noop();
        let err = decrypt(V2_SIZE_17, &mut out, &secret(b"wrong"), None, &mut cb);
        assert!(matches!(err, Err(PalError::Auth)));
        assert!(out.is_empty(), "no plaintext before the hmac1 gate");
    }

    #[test]
    fn tampered_enc_keys_fails_auth() {
        // enc_keys ends HMAC_LEN bytes before the header end; flip a byte 5 into
        // it. enc_keys is covered by hmac1, so this fails at the hmac1 gate.
        let mut t = V2_SIZE_17.to_vec();
        let enc_keys_start = header_len(V2_SIZE_17) - HMAC_LEN - ENC_KEYS_LEN;
        t[enc_keys_start + 5] ^= 0x01;
        assert!(matches!(dec(&t, PASSWORD), Err(PalError::Auth)));
    }

    #[test]
    fn tampered_body_byte_fails_auth() {
        let mut t = V2_SIZE_3000.to_vec();
        let mid = t.len() - HMAC_LEN - 100; // a ciphertext byte well inside the body
        t[mid] ^= 0x01;
        assert!(matches!(dec(&t, PASSWORD), Err(PalError::Auth)));
    }

    #[test]
    fn truncating_the_body_fails_auth() {
        // Drop the final byte (corrupts hmac2).
        assert!(matches!(
            dec(&V2_SIZE_17[..V2_SIZE_17.len() - 1], PASSWORD),
            Err(PalError::Auth)
        ));
        // Drop the whole trailer: body shorter than fsmod+hmac2.
        assert!(matches!(
            dec(&V2_SIZE_17[..V2_SIZE_17.len() - TRAILER_LEN], PASSWORD),
            Err(PalError::Auth)
        ));
    }

    #[test]
    fn appending_bytes_fails_auth() {
        let mut t = V2_SIZE_17.to_vec();
        t.extend_from_slice(&[0u8; 16]); // shifts the trailer; hmac2 no longer matches
        assert!(matches!(dec(&t, PASSWORD), Err(PalError::Auth)));
    }

    #[test]
    fn body_not_a_multiple_of_16_fails_auth() {
        let mut t = V2_SIZE_17.to_vec();
        t.insert(t.len() - TRAILER_LEN, 0x00); // one extra ciphertext byte
        assert!(matches!(dec(&t, PASSWORD), Err(PalError::Auth)));
    }

    // --- Format / malformed (-> exit 4) ---

    #[test]
    fn unsupported_version_is_reported() {
        for bad in [0x00u8, 0x03, 0x7f] {
            let mut t = V2_SIZE_17.to_vec();
            t[3] = bad;
            assert!(
                matches!(
                    dec(&t, PASSWORD),
                    Err(PalError::UnsupportedAesCryptVersion(v)) if v == bad
                ),
                "version {bad:#04x}"
            );
        }
    }

    #[test]
    fn nonzero_reserved_byte_is_malformed() {
        let mut t = V2_SIZE_17.to_vec();
        t[4] = 0x01;
        assert!(matches!(
            dec(&t, PASSWORD),
            Err(PalError::MalformedHeader(_))
        ));
    }

    #[test]
    fn truncated_header_is_malformed() {
        // Cut off mid-header (before iv1/enc_keys/hmac1 are complete).
        assert!(matches!(
            dec(&V2_SIZE_17[..10], PASSWORD),
            Err(PalError::MalformedHeader(_))
        ));
    }

    #[test]
    fn fsmod_out_of_range_is_malformed() {
        // The fsmod byte sits TRAILER_LEN from the end. It is outside hmac2, so a
        // valid-body file with a corrupted fsmod authenticates, then fails the
        // fsmod range check.
        let mut t = V2_SIZE_17.to_vec();
        let fsmod_off = t.len() - TRAILER_LEN;
        t[fsmod_off] = 16; // >= 16 is invalid
        assert!(matches!(
            dec(&t, PASSWORD),
            Err(PalError::MalformedHeader(_))
        ));
    }

    #[test]
    fn fsmod_nonzero_with_empty_body_is_malformed() {
        // v2_size_0 has zero ciphertext blocks; fsmod must be 0. Setting it
        // nonzero (it is outside hmac2) authenticates, then fails the check.
        let mut t = V2_SIZE_0.to_vec();
        let fsmod_off = t.len() - TRAILER_LEN;
        t[fsmod_off] = 5;
        assert!(matches!(
            dec(&t, PASSWORD),
            Err(PalError::MalformedHeader(_))
        ));
    }

    #[test]
    fn extension_count_overrun_is_malformed() {
        // Build a v2 header whose extension framing never terminates within the
        // count bound: many tiny extensions and no terminator before EOF.
        let mut h = Vec::new();
        h.extend_from_slice(MAGIC);
        h.push(0x02); // version
        h.push(0x00); // reserved
        for _ in 0..(MAX_EXT_COUNT + 1) {
            h.extend_from_slice(&1u16.to_be_bytes()); // len = 1
            h.push(b'x');
        }
        assert!(matches!(
            parse_header(&mut io::Cursor::new(h)),
            Err(PalError::MalformedHeader(_))
        ));
    }

    #[test]
    fn extension_size_overrun_is_malformed() {
        // A single extension whose length exceeds the total-bytes bound.
        let mut h = Vec::new();
        h.extend_from_slice(MAGIC);
        h.push(0x02);
        h.push(0x00);
        h.extend_from_slice(&u16::MAX.to_be_bytes()); // 65535-byte ext...
        h.resize(h.len() + u16::MAX as usize, 0);
        // ...repeated enough to cross MAX_EXT_TOTAL_BYTES (256 KiB).
        for _ in 0..4 {
            h.extend_from_slice(&u16::MAX.to_be_bytes());
            h.resize(h.len() + u16::MAX as usize, 0);
        }
        assert!(matches!(
            parse_header(&mut io::Cursor::new(h)),
            Err(PalError::MalformedHeader(_))
        ));
    }

    // --- Usage (-> exit 2) ---

    #[test]
    fn keyfile_bearing_secret_is_invalid_options() {
        let kf = Secret::new(b"aescrypt test password", Some(b"keymaterial")).unwrap();
        let mut out = Vec::new();
        let mut cb = noop();
        assert!(matches!(
            decrypt(V2_SIZE_17, &mut out, &kf, None, &mut cb),
            Err(PalError::InvalidOptions(_))
        ));
    }

    #[test]
    fn keyfile_only_secret_is_invalid_options() {
        let kf_only = Secret::new(b"", Some(b"keymaterial")).unwrap();
        let mut out = Vec::new();
        let mut cb = noop();
        assert!(matches!(
            decrypt(V2_SIZE_17, &mut out, &kf_only, None, &mut cb),
            Err(PalError::InvalidOptions(_))
        ));
    }

    #[test]
    fn non_utf8_password_is_invalid_options() {
        let pw = Secret::new(&[0xFF, 0xFE, 0x00], None).unwrap();
        let mut out = Vec::new();
        let mut cb = noop();
        assert!(matches!(
            decrypt(V2_SIZE_17, &mut out, &pw, None, &mut cb),
            Err(PalError::InvalidOptions(_))
        ));
    }

    // --- Caps & cancellation ---

    #[test]
    fn plaintext_cap_is_enforced() {
        // Decrypt the 3000-byte fixture under a 100-byte cap.
        let mut out = Vec::new();
        let mut cb = noop();
        let err = decrypt_impl(
            V2_SIZE_3000,
            &mut out,
            &secret(PASSWORD),
            None,
            &mut cb,
            100,
        );
        assert!(matches!(err, Err(PalError::InputTooLarge)));
    }

    #[test]
    fn cancellation_before_kdf_returns_canceled() {
        let mut out = Vec::new();
        let mut cb = |_: Progress| ControlFlow::Break(());
        assert!(matches!(
            decrypt(V2_SIZE_17, &mut out, &secret(PASSWORD), None, &mut cb),
            Err(PalError::Canceled)
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn cancellation_during_body_returns_canceled() {
        // Continue past the after-header and after-KDF reports, then break on the
        // first body-read report.
        let mut calls = 0;
        let mut cb = move |_: Progress| {
            calls += 1;
            if calls <= 2 {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        };
        let mut out = Vec::new();
        assert!(matches!(
            decrypt(V2_SIZE_3000, &mut out, &secret(PASSWORD), None, &mut cb),
            Err(PalError::Canceled)
        ));
    }
}
