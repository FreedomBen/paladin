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
        0,
    )
}

/// The core encrypt path with an explicit salt, nonce prefix, and plaintext cap.
/// Production ([`encrypt`]) supplies OS-random values and `start_counter = 0`;
/// tests supply fixed values to produce reproducible known-answer vectors, to
/// exercise the size cap cheaply, and to drive the chunk counter near its 2^32
/// limit. A real file always uses fresh randomness and starts at counter 0.
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
    start_counter: u32,
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
    let mut counter: u32 = start_counter;
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
            0,
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
        let kat_secret = Secret::new(b"paladin known-answer vector", None).unwrap();
        let plaintext = b"paladin v1 known-answer test vector";

        let vectors = [
            (
                CipherId::Aes256Gcm,
                KdfId::Pbkdf2,
                KdfParams::Pbkdf2 { iterations: 10_000 },
                "50414c4144494e000101030000002710000000000000000010000102030405060708090a0b0c0d0e0f0710111213141516000010008f94c0fd319d2dad53317abaff1a8e37c4424f580c2ff997e14edc042c2084949d78922983cc06e48a0243151eeb7d0ac7f271",
            ),
            (
                CipherId::ChaCha20Poly1305,
                KdfId::Argon2id,
                KdfParams::Argon2id {
                    memory_kib: 8192,
                    time_cost: 1,
                    parallelism: 1,
                },
                "50414c4144494e000102010000002000000000010000000110000102030405060708090a0b0c0d0e0f0710111213141516000010002000efc900a30efcebde380827c3b1254434e0de444b11662ce7cb5fc8bbe7f4b62c001626f59ecf7334f8be871056bc96c077",
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
                0,
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

    /// Armored known-answer vector (DESIGN §10, "at least one armored fixture").
    /// The binary container is the AES-256-GCM/PBKDF2 vector above; this commits
    /// its ASCII-armored form so the base64 framing (alphabet, 64-col wrap,
    /// BEGIN/END markers, single trailing LF) is locked across versions. The
    /// armor layer is applied by wrapping the writer exactly as `lib.rs::encrypt`
    /// does. To regenerate after an intentional format change, print `armored`.
    #[test]
    fn armored_known_answer_vector_is_stable_and_decrypts() {
        let salt: [u8; SALT_LEN] = std::array::from_fn(|i| i as u8);
        let nonce: [u8; NONCE_PREFIX_LEN] = std::array::from_fn(|i| (16 + i) as u8);
        let kat_secret = Secret::new(b"paladin known-answer vector", None).unwrap();
        let plaintext = b"paladin v1 known-answer test vector";

        const ARMORED_KAT: &str = concat!(
            "-----BEGIN PALADIN MESSAGE-----\n",
            "UEFMQURJTgABAQMAAAAnEAAAAAAAAAAAEAABAgMEBQYHCAkKCwwNDg8HEBESExQV\n",
            "FgAAEACPlMD9MZ0trVMxerr/Go43xEJPWAwv+ZfhTtwELCCElJ14kimDzAbkigJD\n",
            "FR7rfQrH8nE=\n",
            "-----END PALADIN MESSAGE-----\n",
        );

        let opts = EncryptOptions {
            cipher: CipherId::Aes256Gcm,
            kdf: KdfId::Pbkdf2,
            kdf_params: KdfParams::Pbkdf2 { iterations: 10_000 },
            chunk_size: 4096,
            filename: None,
            armor: false, // armor is supplied by the ArmorWriter wrapper below
        };

        let mut armored: Vec<u8> = Vec::new();
        {
            let mut w = crate::armor::ArmorWriter::new(&mut armored).unwrap();
            let mut cb = noop();
            encrypt_deterministic(
                plaintext.as_ref(),
                &mut w,
                &kat_secret,
                &opts,
                None,
                &mut cb,
                MAX_PLAINTEXT,
                &salt,
                &nonce,
                0,
            )
            .unwrap();
            w.finish().unwrap();
        }
        let armored = String::from_utf8(armored).expect("armor is ASCII text");
        assert_eq!(armored, ARMORED_KAT, "armored format drift");

        // The committed armored fixture decrypts through the public auto-dearmor
        // + stream path back to the plaintext.
        let mut out = Vec::new();
        let mut cb = noop();
        crate::decrypt(armored.as_bytes(), &mut out, &kat_secret, None, &mut cb).unwrap();
        assert_eq!(out, plaintext);
    }

    /// A fresh OS-random salt and nonce prefix per encryption means encrypting
    /// the same plaintext twice never yields the same ciphertext, so no
    /// (key, nonce) pair is ever reused across files (DESIGN §4.3, §5.5).
    #[test]
    fn each_encryption_uses_fresh_salt_and_nonce() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let data = b"the same plaintext encrypted twice";
        let a = enc(data, &opts);
        let b = enc(data, &opts);
        assert_ne!(a, b, "two encryptions of one plaintext must differ");
        assert_eq!(dec(&a).unwrap(), data);
        assert_eq!(dec(&b).unwrap(), data);

        // Sharper: the per-file salt and nonce prefix themselves differ.
        let ha = header::parse(&mut io::Cursor::new(a.clone())).unwrap();
        let hb = header::parse(&mut io::Cursor::new(b.clone())).unwrap();
        assert_ne!(ha.salt, hb.salt, "per-file salt must be fresh");
        assert_ne!(
            ha.nonce_prefix, hb.nonce_prefix,
            "per-file nonce prefix must be fresh"
        );
    }

    #[test]
    fn cancellation_before_kdf_on_decrypt_returns_canceled() {
        let ct = enc(b"payload", &fast_opts(CipherId::Aes256Gcm));
        let mut cb = |_: Progress| ControlFlow::Break(());
        let mut out = Vec::new();
        assert!(matches!(
            decrypt(ct.as_slice(), &mut out, &secret(), None, &mut cb),
            Err(SymError::Canceled)
        ));
    }

    #[test]
    fn cancellation_between_chunks_on_decrypt_returns_canceled() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let data: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
        let ct = enc(&data, &opts);
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
            decrypt(ct.as_slice(), &mut out, &secret(), None, &mut cb),
            Err(SymError::Canceled)
        ));
    }

    #[test]
    fn cancellation_on_verify_returns_canceled() {
        let ct = enc(b"payload", &fast_opts(CipherId::Aes256Gcm));
        let mut cb = |_: Progress| ControlFlow::Break(());
        assert!(matches!(
            verify(ct.as_slice(), &secret(), None, &mut cb),
            Err(SymError::Canceled)
        ));
    }

    /// A reader that yields at most one byte per `read` and injects an
    /// `Interrupted` error on every other call, exercising `read_up_to`'s fill
    /// loop and its Interrupted-retry arm (DESIGN §5.5).
    struct Drip<R> {
        inner: R,
        calls: usize,
    }

    impl<R: Read> Drip<R> {
        fn new(inner: R) -> Self {
            Self { inner, calls: 0 }
        }
    }

    impl<R: Read> Read for Drip<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls.is_multiple_of(2) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "drip"));
            }
            if buf.is_empty() {
                return Ok(0);
            }
            self.inner.read(&mut buf[..1])
        }
    }

    #[test]
    fn round_trips_through_byte_at_a_time_reader() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let data: Vec<u8> = (0..(3 * 4096 + 57)).map(|i| (i % 251) as u8).collect();
        let mut out = Vec::new();
        let mut cb = noop();
        encrypt(
            Drip::new(data.as_slice()),
            &mut out,
            &secret(),
            &opts,
            None,
            &mut cb,
        )
        .unwrap();
        let mut dec_out = Vec::new();
        let mut cb = noop();
        decrypt(
            Drip::new(out.as_slice()),
            &mut dec_out,
            &secret(),
            None,
            &mut cb,
        )
        .unwrap();
        assert_eq!(dec_out, data);
    }

    /// A writer that fails every write, so the header `write_all` surfaces the
    /// I/O error as [`SymError::Io`] (DESIGN §5.5).
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_error_surfaces_as_io() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let mut cb = noop();
        assert!(matches!(
            encrypt(
                b"data".as_ref(),
                FailingWriter,
                &secret(),
                &opts,
                None,
                &mut cb
            ),
            Err(SymError::Io(_))
        ));
    }

    /// A reader that serves bytes normally until `pos >= fail_at`, then returns a
    /// genuine (non-Interrupted) I/O error, exercising `read_up_to`'s error arm.
    struct FailAfter {
        data: Vec<u8>,
        pos: usize,
        fail_at: usize,
    }

    impl Read for FailAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.fail_at {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom"));
            }
            let remaining = &self.data[self.pos..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn read_error_in_body_surfaces_as_io() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let ct = enc(b"payload that spans into the body", &opts);
        // Land the failure one byte into the body so it hits read_up_to's
        // non-Interrupted error arm rather than the header parse path. A plain
        // BrokenPipe is not a wrapped SymError, so recover_symerror returns it
        // and it maps to SymError::Io.
        let header_len = header::parse(&mut io::Cursor::new(ct.clone()))
            .unwrap()
            .aad()
            .len();
        let reader = FailAfter {
            data: ct.clone(),
            pos: 0,
            fail_at: header_len + 1,
        };
        let mut out = Vec::new();
        let mut cb = noop();
        assert!(matches!(
            decrypt(reader, &mut out, &secret(), None, &mut cb),
            Err(SymError::Io(_))
        ));
    }

    /// A several-MiB round-trip at the production default 64 KiB chunk size
    /// (DESIGN §10). The existing round-trips all use the 4096 test chunk size,
    /// so this is the only coverage of the real default chunking.
    #[test]
    fn round_trip_several_mib_at_default_chunk_size() {
        let opts = EncryptOptions {
            cipher: CipherId::Aes256Gcm,
            kdf: KdfId::Pbkdf2,
            kdf_params: cheap_params(KdfId::Pbkdf2),
            chunk_size: 65536,
            filename: None,
            armor: false,
        };
        let data: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        assert_eq!(dec(&enc(&data, &opts)).unwrap(), data);
    }

    #[test]
    fn round_trip_at_default_chunk_boundaries() {
        let opts = EncryptOptions {
            cipher: CipherId::Aes256Gcm,
            kdf: KdfId::Pbkdf2,
            kdf_params: cheap_params(KdfId::Pbkdf2),
            chunk_size: 65536,
            filename: None,
            armor: false,
        };
        for &n in &[65535usize, 65536, 65537] {
            let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let ct = enc(&data, &opts);
            assert_eq!(dec(&ct).unwrap(), data, "size {n}");
        }
    }

    /// A stream needing more than 2^32 chunks is rejected (DESIGN §4.3). The
    /// `start_counter` test seam lets us drive the encrypt counter to its limit
    /// cheaply: the first chunk seals at counter = u32::MAX (not final), then the
    /// `checked_add` for the next chunk overflows. The decrypt-side counter
    /// overflow guard is intentionally left uncovered, since reaching it would
    /// require forging 2^32 authentic chunks.
    #[test]
    fn encrypt_rejects_more_than_2_32_chunks() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let data = vec![0u8; 4096 * 2]; // exactly two full chunks
        let mut out = Vec::new();
        let mut cb = noop();
        let err = encrypt_deterministic(
            data.as_slice(),
            &mut out,
            &secret(),
            &opts,
            None,
            &mut cb,
            MAX_PLAINTEXT,
            &[0u8; SALT_LEN],
            &[0u8; NONCE_PREFIX_LEN],
            u32::MAX,
        );
        assert!(matches!(err, Err(SymError::InputTooLarge)));
    }

    #[test]
    fn progress_done_is_monotonic_and_total_none_when_unknown() {
        let opts = fast_opts(CipherId::Aes256Gcm);
        let data = vec![1u8; 4096 * 3 + 100];
        let seen: std::cell::RefCell<Vec<Progress>> = std::cell::RefCell::new(Vec::new());
        {
            let mut cb = |p: Progress| {
                seen.borrow_mut().push(p);
                ControlFlow::Continue(())
            };
            let mut out = Vec::new();
            encrypt(data.as_slice(), &mut out, &secret(), &opts, None, &mut cb).unwrap();
        }
        let seen = seen.into_inner();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(|p| p.total.is_none()), "total must be None");
        let mut prev = 0u64;
        for p in &seen {
            assert!(p.done >= prev, "done must be non-decreasing");
            prev = p.done;
        }
        assert_eq!(seen.last().unwrap().done, data.len() as u64);
    }
}
