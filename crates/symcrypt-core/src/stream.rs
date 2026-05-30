//! The STREAM construction: chunked authenticated encrypt/decrypt with progress
//! and cancellation (DESIGN §4.3, §5.5).
//!
//! These functions operate on the **binary** container. The optional ASCII-armor
//! outer layer and the public `encrypt`/`decrypt`/`inspect`/`verify` entry points
//! that compose it are added with the armor module.
//!
//! For each chunk `i` the 12-byte nonce is `prefix(7) ‖ u32be(i) ‖ final_flag(1)`.
//! Chunk 0 is sealed with the entire serialized header as AAD, binding
//! cipher/KDF/params/filename to the ciphertext; later chunks use empty AAD. The
//! per-chunk counter prevents reordering and the final flag prevents
//! truncation/appending. A failed tag, a structurally short body, or a
//! reorder/truncate/append are all reported as the single [`SymError::Auth`]
//! condition (DESIGN §4.4, §5.5).

use std::io::{self, Read, Write};
use std::ops::ControlFlow;

use crate::cipher::{Cipher, CipherId};
use crate::error::{Result, SymError};
use crate::header::{self, CHUNK_SIZE};
use crate::kdf::{KdfId, KdfParams};
use crate::secret::Secret;

/// AEAD tag length appended to every on-disk chunk (DESIGN §4.1).
const TAG_LEN: usize = 16;
/// Salt length written for new files (DESIGN §12).
const SALT_LEN: usize = 16;
/// Nonce-prefix length (DESIGN §12); the full STREAM nonce is 12 bytes.
const NONCE_PREFIX_LEN: usize = 7;
/// v1 plaintext size cap: 64 GiB (DESIGN §4.3).
const MAX_PLAINTEXT: u64 = 64 * 1024 * 1024 * 1024;

/// Progress callback payload (DESIGN §2.3). `done` is the running count of input
/// bytes consumed; `total` echoes the caller's advisory `input_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub done: u64,
    pub total: Option<u64>,
}

/// Progress/cancellation callback. Returning [`ControlFlow::Break`] aborts the
/// operation with [`SymError::Canceled`].
pub type OnProgress<'a> = dyn FnMut(Progress) -> ControlFlow<()> + 'a;

/// Options for [`encrypt`]. Construct via [`Default`] for the DESIGN §12 secure
/// defaults, then override as needed. The `kdf_params` variant must match `kdf`.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub cipher: CipherId,
    pub kdf: KdfId,
    pub kdf_params: KdfParams,
    pub chunk_size: u32,
    pub filename: Option<String>,
    pub armor: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            cipher: CipherId::Aes256Gcm,
            kdf: KdfId::Argon2id,
            kdf_params: KdfParams::default_for(KdfId::Argon2id),
            chunk_size: 65536,
            filename: None,
            armor: false,
        }
    }
}

impl EncryptOptions {
    /// Validate the options before any output is written (DESIGN §5.4). Any
    /// problem is [`SymError::InvalidOptions`] (exit 2), so programmatic options
    /// can never produce a file that fails its own read validation.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.kdf_params.kdf_id() != self.kdf {
            return Err(SymError::InvalidOptions(
                "kdf_params variant does not match kdf",
            ));
        }
        self.kdf_params
            .validate()
            .map_err(SymError::InvalidOptions)?;
        if !CHUNK_SIZE.contains(&self.chunk_size) {
            return Err(SymError::InvalidOptions(
                "chunk_size out of range (4096..=16777216)",
            ));
        }
        if let Some(name) = &self.filename {
            if !header::is_safe_basename(name) {
                return Err(SymError::InvalidOptions(
                    "stored filename is not a safe basename",
                ));
            }
        }
        Ok(())
    }
}

/// Report progress and observe cancellation. A `Break` becomes `Canceled`.
fn report(on_progress: &mut OnProgress<'_>, done: u64, total: Option<u64>) -> Result<()> {
    match on_progress(Progress { done, total }) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(()) => Err(SymError::Canceled),
    }
}

/// Build the 12-byte STREAM nonce for chunk `counter` (DESIGN §4.3).
fn make_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u32, final_flag: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(final_flag);
    nonce
}

/// Fill `buf` with OS randomness. An RNG failure makes safe encryption
/// impossible, so it is surfaced as a general error.
fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| SymError::Io(io::Error::other("OS RNG failure")))
}

/// Read up to `max` bytes, returning fewer only at end of input. `Interrupted`
/// is retried; other I/O errors propagate.
fn read_up_to<R: Read>(reader: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; max];
    let mut filled = 0;
    while filled < max {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // Recover an armor framing error (e.g. MalformedHeader) wrapped by
            // the reader; otherwise it is a genuine I/O error.
            Err(e) => {
                return Err(match crate::error::recover_symerror(e) {
                    Ok(sym) => sym,
                    Err(e) => SymError::Io(e),
                })
            }
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Encrypt `input` to `output` (binary container) with the DESIGN §12 default
/// 64 GiB plaintext cap, generating a fresh OS-random salt and nonce prefix.
pub(crate) fn encrypt<R: Read, W: Write>(
    input: R,
    output: W,
    secret: &Secret,
    opts: &EncryptOptions,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    fill_random(&mut nonce_prefix)?;
    encrypt_deterministic(
        input,
        output,
        secret,
        opts,
        input_len,
        on_progress,
        MAX_PLAINTEXT,
        &salt,
        &nonce_prefix,
    )
}

/// The core encrypt path with an explicit salt, nonce prefix, and plaintext cap.
/// Production ([`encrypt`]) supplies OS-random values; tests supply fixed values
/// to produce reproducible known-answer vectors and to exercise the size cap
/// cheaply. A real file always uses fresh randomness.
#[allow(clippy::too_many_arguments)]
fn encrypt_deterministic<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    secret: &Secret,
    opts: &EncryptOptions,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
    max_plaintext: u64,
    salt: &[u8; SALT_LEN],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
) -> Result<()> {
    opts.validate()?;
    report(on_progress, 0, input_len)?; // cancel before key derivation

    // Serialize the header (also chunk-0 AAD) before deriving the key, so a
    // cancellation during the expensive KDF leaves the output untouched.
    let header_bytes = header::serialize(
        opts.cipher,
        opts.kdf_params,
        salt,
        nonce_prefix,
        opts.chunk_size,
        opts.filename.as_deref(),
        secret.has_keyfile(),
    );

    let key = opts.kdf_params.derive_key(&secret.kdf_input(), salt)?;
    report(on_progress, 0, input_len)?; // cancel after key derivation (output still empty)

    output.write_all(&header_bytes).map_err(SymError::Io)?;

    let cipher = Cipher::new(opts.cipher, &key);
    let chunk_size = opts.chunk_size as usize;
    let mut counter: u32 = 0;
    let mut done: u64 = 0;

    let mut cur = read_up_to(&mut input, chunk_size)?;
    loop {
        let next = read_up_to(&mut input, chunk_size)?;
        let is_final = next.is_empty();

        done += cur.len() as u64;
        if done > max_plaintext {
            return Err(SymError::InputTooLarge);
        }

        let nonce = make_nonce(nonce_prefix, counter, is_final);
        let aad: &[u8] = if counter == 0 { &header_bytes } else { &[] };
        let sealed = cipher.seal(&nonce, aad, &cur)?;
        output.write_all(&sealed).map_err(SymError::Io)?;
        report(on_progress, done, input_len)?;

        if is_final {
            break;
        }
        // Refuse a stream needing more than 2^32 chunks (DESIGN §4.3).
        counter = counter.checked_add(1).ok_or(SymError::InputTooLarge)?;
        cur = next;
    }
    output.flush().map_err(SymError::Io)?;
    Ok(())
}

/// Decrypt the binary container in `input` to `output`, verifying every tag.
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
    mut input: R,
    mut output: W,
    secret: &Secret,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
    max_plaintext: u64,
) -> Result<()> {
    let header = header::parse(&mut input)?;
    report(on_progress, 0, input_len)?; // cancel before key derivation

    let key = header
        .kdf_params
        .derive_key(&secret.kdf_input(), &header.salt)?;
    report(on_progress, 0, input_len)?; // cancel after key derivation

    let cipher = Cipher::new(header.cipher, &key);
    let on_disk_max = header.chunk_size as usize + TAG_LEN;
    let mut counter: u32 = 0;
    let mut input_done: u64 = header.aad().len() as u64;
    let mut plaintext_len: u64 = 0;

    let mut cur = read_up_to(&mut input, on_disk_max)?;
    if cur.is_empty() {
        // No body after a complete header (DESIGN §5.5): an auth failure,
        // indistinguishable from truncation.
        return Err(SymError::Auth);
    }
    loop {
        let next = read_up_to(&mut input, on_disk_max)?;
        let is_final = next.is_empty();

        if cur.len() < TAG_LEN {
            return Err(SymError::Auth); // trailing fragment shorter than a tag
        }

        let nonce = make_nonce(&header.nonce_prefix, counter, is_final);
        let aad: &[u8] = if counter == 0 { header.aad() } else { &[] };
        let plaintext = cipher.open(&nonce, aad, &cur)?;

        plaintext_len += plaintext.len() as u64;
        if plaintext_len > max_plaintext {
            return Err(SymError::InputTooLarge);
        }
        output.write_all(&plaintext).map_err(SymError::Io)?;

        input_done += cur.len() as u64;
        report(on_progress, input_done, input_len)?;

        if is_final {
            break;
        }
        // A stream exceeding 2^32 chunks is rejected as an auth failure on
        // decrypt rather than wrapping the counter (DESIGN §4.3).
        counter = counter.checked_add(1).ok_or(SymError::Auth)?;
        cur = next;
    }
    output.flush().map_err(SymError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::new(b"correct horse battery staple", None).unwrap()
    }

    fn cheap_params(kdf: KdfId) -> KdfParams {
        match kdf {
            KdfId::Argon2id => KdfParams::Argon2id {
                memory_kib: 8192,
                time_cost: 1,
                parallelism: 1,
            },
            KdfId::Scrypt => KdfParams::Scrypt {
                log_n: 10,
                r: 1,
                p: 1,
            },
            KdfId::Pbkdf2 => KdfParams::Pbkdf2 { iterations: 10_000 },
        }
    }

    /// Fast options (PBKDF2) with the smallest legal chunk size so small inputs
    /// still exercise multi-chunk streams (DESIGN §5.4).
    fn fast_opts(cipher: CipherId) -> EncryptOptions {
        EncryptOptions {
            cipher,
            kdf: KdfId::Pbkdf2,
            kdf_params: cheap_params(KdfId::Pbkdf2),
            chunk_size: 4096,
            filename: None,
            armor: false,
        }
    }

    fn noop() -> impl FnMut(Progress) -> ControlFlow<()> {
        |_| ControlFlow::Continue(())
    }

    fn enc(data: &[u8], opts: &EncryptOptions) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cb = noop();
        encrypt(
            data,
            &mut out,
            &secret(),
            opts,
            Some(data.len() as u64),
            &mut cb,
        )
        .unwrap();
        out
    }

    fn dec(ct: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut cb = noop();
        decrypt(ct, &mut out, &secret(), None, &mut cb)?;
        Ok(out)
    }

    #[test]
    fn round_trip_across_sizes_and_ciphers() {
        let sizes = [0usize, 1, 4095, 4096, 4097, 8192, 20_000];
        for cipher in [CipherId::Aes256Gcm, CipherId::ChaCha20Poly1305] {
            let opts = fast_opts(cipher);
            for &n in &sizes {
                let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
                let ct = enc(&data, &opts);
                assert_eq!(dec(&ct).unwrap(), data, "{cipher} size {n}");
            }
        }
    }

    #[test]
    fn round_trip_for_each_kdf() {
        let data = b"a modest secret that spans a little data".to_vec();
        for kdf in [KdfId::Argon2id, KdfId::Scrypt, KdfId::Pbkdf2] {
            let opts = EncryptOptions {
                cipher: CipherId::Aes256Gcm,
                kdf,
                kdf_params: cheap_params(kdf),
                chunk_size: 4096,
                filename: None,
                armor: false,
            };
            let ct = enc(&data, &opts);
            assert_eq!(dec(&ct).unwrap(), data, "kdf {kdf}");
        }
    }

    #[test]
    fn empty_plaintext_is_one_tag_only_chunk() {
        let ct = enc(b"", &fast_opts(CipherId::Aes256Gcm));
        // header + a single 16-byte (tag-only) final chunk.
        assert_eq!(dec(&ct).unwrap(), b"");
        // Dropping the 16-byte body leaves a header with no body -> Auth.
        let header_only = &ct[..ct.len() - TAG_LEN];
        assert!(matches!(dec(header_only), Err(SymError::Auth)));
    }

    #[test]
    fn invalid_options_are_rejected_before_output() {
        // kdf_params variant disagrees with kdf.
        let mut opts = fast_opts(CipherId::Aes256Gcm);
        opts.kdf = KdfId::Argon2id; // params are still PBKDF2
        let mut out = Vec::new();
        let mut cb = noop();
        assert!(matches!(
            encrypt(b"x".as_ref(), &mut out, &secret(), &opts, None, &mut cb),
            Err(SymError::InvalidOptions(_))
        ));
        assert!(out.is_empty());

        // out-of-range chunk size.
        let mut opts = fast_opts(CipherId::Aes256Gcm);
        opts.chunk_size = 1024;
        let mut cb = noop();
        assert!(matches!(
            encrypt(
                b"x".as_ref(),
                &mut Vec::new(),
                &secret(),
                &opts,
                None,
                &mut cb
            ),
            Err(SymError::InvalidOptions(_))
        ));

        // unsafe stored filename.
        let mut opts = fast_opts(CipherId::Aes256Gcm);
        opts.filename = Some("../etc/passwd".to_string());
        let mut cb = noop();
        assert!(matches!(
            encrypt(
                b"x".as_ref(),
                &mut Vec::new(),
                &secret(),
                &opts,
                None,
                &mut cb
            ),
            Err(SymError::InvalidOptions(_))
        ));
    }

    #[test]
    fn flipped_body_byte_fails_auth() {
        let ct = enc(b"important data here", &fast_opts(CipherId::Aes256Gcm));
        let mut t = ct.clone();
        let last = t.len() - 1;
        t[last] ^= 0x01;
        assert!(matches!(dec(&t), Err(SymError::Auth)));
    }

    #[test]
    fn header_byte_changed_to_valid_value_fails_auth() {
        // cipher_id 0x01 -> 0x02 is a valid id, so parsing succeeds, but the
        // header is AAD so authentication fails (DESIGN §10).
        let ct = enc(b"payload", &fast_opts(CipherId::Aes256Gcm));
        let mut t = ct.clone();
        assert_eq!(t[9], 0x01);
        t[9] = 0x02;
        assert!(matches!(dec(&t), Err(SymError::Auth)));
    }

    #[test]
    fn header_byte_changed_to_unknown_id_is_unsupported() {
        let ct = enc(b"payload", &fast_opts(CipherId::Aes256Gcm));
        let mut t = ct.clone();
        t[9] = 0x7f; // unknown cipher id
        assert!(matches!(dec(&t), Err(SymError::UnknownCipher(0x7f))));
    }

    #[test]
    fn wrong_password_or_keyfile_fails_auth() {
        let ct = enc(b"payload", &fast_opts(CipherId::Aes256Gcm));

        let mut out = Vec::new();
        let mut cb = noop();
        let wrong_pw = Secret::new(b"wrong password", None).unwrap();
        assert!(matches!(
            decrypt(ct.as_slice(), &mut out, &wrong_pw, None, &mut cb),
            Err(SymError::Auth)
        ));

        // Encrypted with a keyfile; decrypting without it fails.
        let kf_secret = Secret::new(b"pw", Some(b"keymaterial")).unwrap();
        let mut kf_ct = Vec::new();
        let mut cb = noop();
        encrypt(
            b"payload".as_ref(),
            &mut kf_ct,
            &kf_secret,
            &fast_opts(CipherId::Aes256Gcm),
            None,
            &mut cb,
        )
        .unwrap();
        let no_kf = Secret::new(b"pw", None).unwrap();
        let mut cb = noop();
        assert!(matches!(
            decrypt(kf_ct.as_slice(), &mut Vec::new(), &no_kf, None, &mut cb),
            Err(SymError::Auth)
        ));
    }

    #[test]
    fn truncating_the_last_chunk_fails_auth() {
        let ct = enc(
            b"payload that is a bit longer",
            &fast_opts(CipherId::Aes256Gcm),
        );
        // Drop the final byte (corrupts the last tag).
        assert!(matches!(dec(&ct[..ct.len() - 1]), Err(SymError::Auth)));
        // Drop the whole final tag region down to a sub-tag fragment.
        assert!(matches!(
            dec(&ct[..ct.len() - TAG_LEN + 1]),
            Err(SymError::Auth)
        ));
    }

    #[test]
    fn appending_a_chunk_fails_auth() {
        let ct = enc(b"payload", &fast_opts(CipherId::Aes256Gcm));
        let mut t = ct.clone();
        t.extend_from_slice(&[0u8; 32]); // bytes after the genuine final chunk
        assert!(matches!(dec(&t), Err(SymError::Auth)));
    }

    #[test]
    fn swapping_two_chunks_fails_auth() {
        // Two full chunks => two on-disk chunks of chunk_size+16.
        let opts = fast_opts(CipherId::Aes256Gcm);
        let data: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let ct = enc(&data, &opts);
        let header_len = ct.len() - 2 * (4096 + TAG_LEN);
        let chunk = 4096 + TAG_LEN;
        let mut t = ct.clone();
        // Swap chunk 0 and chunk 1 in the body.
        let (c0_start, c1_start) = (header_len, header_len + chunk);
        let c0: Vec<u8> = ct[c0_start..c0_start + chunk].to_vec();
        let c1: Vec<u8> = ct[c1_start..c1_start + chunk].to_vec();
        t[c0_start..c0_start + chunk].copy_from_slice(&c1);
        t[c1_start..c1_start + chunk].copy_from_slice(&c0);
        assert!(matches!(dec(&t), Err(SymError::Auth)));
    }

    #[test]
    fn dropping_the_body_fails_auth() {
        let ct = enc(b"", &fast_opts(CipherId::Aes256Gcm));
        let header_only = &ct[..ct.len() - TAG_LEN];
        assert!(matches!(dec(header_only), Err(SymError::Auth)));
    }

    #[test]
    fn cancellation_before_kdf_returns_canceled() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let mut cb = |_: Progress| ControlFlow::Break(());
        let mut out = Vec::new();
        assert!(matches!(
            encrypt(b"data".as_ref(), &mut out, &secret(), &opts, None, &mut cb),
            Err(SymError::Canceled)
        ));
        // Cancelled before the key derivation, so nothing was written.
        assert!(out.is_empty());
    }

    #[test]
    fn cancellation_between_chunks_returns_canceled() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let data: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
        // Continue through the two pre/post-KDF reports, then break.
        let mut calls = 0;
        let mut cb = move |_: Progress| {
            calls += 1;
            if calls <= 3 {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        };
        let mut out = Vec::new();
        assert!(matches!(
            encrypt(data.as_slice(), &mut out, &secret(), &opts, None, &mut cb),
            Err(SymError::Canceled)
        ));
    }

    #[test]
    fn encrypt_enforces_plaintext_cap() {
        // Inject a tiny cap; 200 bytes of plaintext exceeds it.
        let opts = fast_opts(CipherId::Aes256Gcm);
        let mut out = Vec::new();
        let mut cb = noop();
        let data = [7u8; 200];
        let err = encrypt_deterministic(
            data.as_slice(),
            &mut out,
            &secret(),
            &opts,
            None,
            &mut cb,
            100,
            &[0u8; SALT_LEN],
            &[0u8; NONCE_PREFIX_LEN],
        );
        assert!(matches!(err, Err(SymError::InputTooLarge)));
    }

    #[test]
    fn decrypt_enforces_plaintext_cap() {
        // Encrypt 200 bytes normally, then decrypt under a 100-byte cap.
        let opts = fast_opts(CipherId::Aes256Gcm);
        let ct = enc(&[7u8; 200], &opts);
        let mut out = Vec::new();
        let mut cb = noop();
        let err = decrypt_impl(ct.as_slice(), &mut out, &secret(), None, &mut cb, 100);
        assert!(matches!(err, Err(SymError::InputTooLarge)));
    }

    #[test]
    fn progress_reports_total_from_input_len() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let data = vec![1u8; 5000];
        let seen_total = std::cell::Cell::new(None);
        let max_done = std::cell::Cell::new(0u64);
        {
            let mut cb = |p: Progress| {
                seen_total.set(p.total);
                max_done.set(max_done.get().max(p.done));
                ControlFlow::Continue(())
            };
            let mut out = Vec::new();
            encrypt(
                data.as_slice(),
                &mut out,
                &secret(),
                &opts,
                Some(data.len() as u64),
                &mut cb,
            )
            .unwrap();
        }
        assert_eq!(seen_total.get(), Some(5000));
        assert_eq!(max_done.get(), 5000);
    }

    #[test]
    fn make_nonce_layout() {
        let prefix = [0xAA; NONCE_PREFIX_LEN];
        let n = make_nonce(&prefix, 0x01020304, true);
        assert_eq!(&n[0..7], &prefix);
        assert_eq!(&n[7..11], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(n[11], 0x01);
        let n0 = make_nonce(&prefix, 0, false);
        assert_eq!(&n0[7..11], &[0, 0, 0, 0]);
        assert_eq!(n0[11], 0x00);
    }

    /// Known-answer vectors (DESIGN §10): committed ciphertext for fixed inputs
    /// produced with a deterministic salt/nonce source, so an accidental format
    /// change is caught across versions. Production encryption always uses OS
    /// randomness. To regenerate after an intentional format change, print
    /// `hex::encode(&out)` for each vector and paste the result below.
    #[test]
    fn known_answer_vectors_are_stable_and_decrypt() {
        let salt: [u8; SALT_LEN] = std::array::from_fn(|i| i as u8);
        let nonce: [u8; NONCE_PREFIX_LEN] = std::array::from_fn(|i| (16 + i) as u8);
        let kat_secret = Secret::new(b"symcrypt known-answer vector", None).unwrap();
        let plaintext = b"symcrypt v1 known-answer test vector";

        let vectors = [
            (
                CipherId::Aes256Gcm,
                KdfId::Pbkdf2,
                KdfParams::Pbkdf2 { iterations: 10_000 },
                "53594d43525950540101030000002710000000000000000010000102030405060708090a0b0c0d0e0f07101112131415160000100058eb65948fa7f1806823a51ae9dd50111cbe000851e4516ee3aecb7af7da6efe6748c0a0accc018c8a9cb24fa146bd8b2eef144b",
            ),
            (
                CipherId::ChaCha20Poly1305,
                KdfId::Argon2id,
                KdfParams::Argon2id {
                    memory_kib: 8192,
                    time_cost: 1,
                    parallelism: 1,
                },
                "53594d43525950540102010000002000000000010000000110000102030405060708090a0b0c0d0e0f07101112131415160000100098051afe257ade48fe282bac9e9c5a99305bcc6d7be0298034d5e6aaaae9100221546da01a20da7c590e31c806da8cd147736d7c",
            ),
        ];

        for (cipher, kdf, kdf_params, expected_hex) in vectors {
            let opts = EncryptOptions {
                cipher,
                kdf,
                kdf_params,
                chunk_size: 4096,
                filename: None,
                armor: false,
            };
            let mut out = Vec::new();
            let mut cb = noop();
            encrypt_deterministic(
                plaintext.as_ref(),
                &mut out,
                &kat_secret,
                &opts,
                None,
                &mut cb,
                MAX_PLAINTEXT,
                &salt,
                &nonce,
            )
            .unwrap();
            assert_eq!(
                hex::encode(&out),
                expected_hex,
                "format drift for {cipher}/{kdf}"
            );

            // The committed vector must also decrypt back to the plaintext,
            // proving the encrypt and decrypt paths agree on the format.
            let committed = hex::decode(expected_hex).unwrap();
            let mut dec_out = Vec::new();
            let mut cb = noop();
            decrypt(
                committed.as_slice(),
                &mut dec_out,
                &kat_secret,
                None,
                &mut cb,
            )
            .unwrap();
            assert_eq!(
                dec_out, plaintext,
                "vector did not decrypt for {cipher}/{kdf}"
            );
        }
    }
}
