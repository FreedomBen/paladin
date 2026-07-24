//! Editor pure logic (DESIGN §8.4): the bounded in-memory plaintext buffer the
//! open path decrypts into, the strict UTF-8 gate, and [`SaveSource`] — the
//! per-window rule for deriving each save's `EncryptOptions`, including the
//! confirm-then-migrate handling of AES Crypt sources.
//!
//! This module is pure logic: no GTK, no filesystem, no crypto calls. `task.rs`
//! runs the actual decrypt/encrypt around these types and the editor window
//! component consumes them; both stay thin (DESIGN §2.2).

use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use zeroize::Zeroizing;

use paladin_core::{EncryptOptions, Header, Metadata};

use crate::options::{derive_name, NameError};

/// Decrypted text is capped at 8 MiB in the editor (DESIGN §8.4, §12); larger
/// files belong in Decrypt mode.
pub const EDITOR_MAX_BYTES: usize = 8 * 1024 * 1024;

/// A `Write` sink that collects decrypted plaintext into a [`Zeroizing`]
/// buffer, refusing to grow past its cap. The core's decrypt aborts on the
/// write error; [`overflowed`](Self::overflowed) then distinguishes "the text
/// is too large for the editor" from a genuine I/O failure.
///
/// An overflowing write is refused whole (nothing partial is kept), so the
/// buffer only ever holds bytes that fit the cap.
pub struct BoundedPlainWriter {
    buf: Zeroizing<Vec<u8>>,
    cap: usize,
    overflowed: bool,
}

impl BoundedPlainWriter {
    /// A writer capped at [`EDITOR_MAX_BYTES`].
    pub fn new() -> Self {
        Self::with_cap(EDITOR_MAX_BYTES)
    }

    /// A writer with an explicit cap (tests use small ones).
    pub fn with_cap(cap: usize) -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            cap,
            overflowed: false,
        }
    }

    /// Whether a write was refused because it would exceed the cap.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Bytes collected so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been collected.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The collected plaintext, still zeroized on drop.
    pub fn into_buffer(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

impl Default for BoundedPlainWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for BoundedPlainWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.cap {
            self.overflowed = true;
            return Err(io::Error::other("plaintext exceeds the editor size cap"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The decrypted bytes are not valid UTF-8, so the editor cannot show them;
/// binary content belongs in Decrypt mode (DESIGN §8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotText;

impl fmt::Display for NotText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the decrypted content is not UTF-8 text")
    }
}

impl std::error::Error for NotText {}

/// The strict UTF-8 gate: convert the decrypted buffer to text via an
/// allocation-reusing conversion, so no stray plaintext copy is made (DESIGN
/// §8.4). On invalid UTF-8 the bytes are re-wrapped in a [`Zeroizing`] buffer
/// (and so wiped) before the error returns.
pub fn text_from_buffer(mut buf: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, NotText> {
    // Move the Vec out of the wrapper; `from_utf8` reuses its allocation.
    let bytes = std::mem::take(&mut *buf);
    match String::from_utf8(bytes) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(err) => {
            // Re-wrap so the rejected plaintext is zeroized on drop.
            let _wiped = Zeroizing::new(err.into_bytes());
            Err(NotText)
        }
    }
}

/// Where a save's `EncryptOptions` come from (DESIGN §8.4). One value lives in
/// each editor window and is consulted on every save.
#[derive(Debug, Clone)]
pub enum SaveSource {
    /// A paladin source: every save re-derives from its header, so cipher,
    /// KDF, parameters, chunk size, and the stored-name choice are preserved
    /// (Save As re-derives the embedded name from the new basename).
    Paladin(Header),
    /// An AES Crypt source that has not been migrated yet: the first save must
    /// be confirmed and writes the §12 defaults — an AES Crypt header carries
    /// no paladin parameters to derive from.
    AesCryptPending,
    /// Fixed options: new notes, and AES Crypt sources after their confirmed
    /// migration save (later saves reuse what was just written, no dialog).
    Fixed(EncryptOptions),
}

impl SaveSource {
    /// The source rule for a just-opened file.
    pub fn from_metadata(meta: &Metadata) -> Self {
        match meta {
            Metadata::Paladin(header) => SaveSource::Paladin(header.clone()),
            Metadata::AesCrypt(_) => SaveSource::AesCryptPending,
        }
    }

    /// The source rule for a new note: the §12 defaults (binary container, no
    /// stored name).
    pub fn new_note() -> Self {
        SaveSource::Fixed(EncryptOptions::default())
    }

    /// Whether the next save is an AES Crypt → paladin migration that needs
    /// the confirmation dialog first (DESIGN §8.4).
    pub fn needs_migration_confirm(&self) -> bool {
        matches!(self, SaveSource::AesCryptPending)
    }

    /// Derive the options for a save to `output`, applying `armored` as
    /// recorded at open. Fails only when a paladin source stored a name but
    /// `output`'s basename cannot be embedded (DESIGN §5.2).
    pub fn options_for(&self, armored: bool, output: &Path) -> Result<EncryptOptions, NameError> {
        let opts = match self {
            SaveSource::Paladin(header) => {
                let filename = if header.filename_present() {
                    Some(derive_name(output)?)
                } else {
                    None
                };
                EncryptOptions {
                    cipher: header.cipher,
                    kdf: header.kdf(),
                    kdf_params: header.kdf_params,
                    chunk_size: header.chunk_size,
                    filename,
                    armor: armored,
                }
            }
            SaveSource::AesCryptPending => EncryptOptions {
                armor: armored,
                ..EncryptOptions::default()
            },
            SaveSource::Fixed(fixed) => EncryptOptions {
                armor: armored,
                ..fixed.clone()
            },
        };
        Ok(opts)
    }

    /// Record a successful save that wrote `used`: a pending AES Crypt source
    /// becomes [`SaveSource::Fixed`] with those options, so later saves derive
    /// identically and show no migration dialog. Other sources are unchanged —
    /// a paladin source keeps re-deriving from its header.
    pub fn saved(&mut self, used: &EncryptOptions) {
        if matches!(self, SaveSource::AesCryptPending) {
            *self = SaveSource::Fixed(used.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paladin_core::{encrypt, inspect, CipherId, KdfId, KdfParams, Progress, Secret};
    use std::ops::ControlFlow;
    use std::path::PathBuf;

    // --- BoundedPlainWriter -----------------------------------------------

    #[test]
    fn writer_accepts_writes_up_to_the_exact_cap() {
        let mut w = BoundedPlainWriter::with_cap(8);
        assert_eq!(w.write(b"12345").unwrap(), 5);
        assert_eq!(w.write(b"678").unwrap(), 3); // lands exactly at the cap
        assert!(!w.overflowed());
        assert_eq!(w.len(), 8);
        assert_eq!(&**w.into_buffer(), b"12345678");
    }

    #[test]
    fn writer_refuses_a_single_overflowing_write_whole() {
        let mut w = BoundedPlainWriter::with_cap(4);
        assert!(w.write(b"12345").is_err());
        assert!(w.overflowed());
        // Nothing partial is kept.
        assert!(w.is_empty());
    }

    #[test]
    fn writer_refuses_the_write_that_crosses_the_cap() {
        let mut w = BoundedPlainWriter::with_cap(4);
        assert_eq!(w.write(b"123").unwrap(), 3);
        assert!(w.write(b"45").is_err());
        assert!(w.overflowed());
        // The earlier bytes survive; the crossing write left no partial data.
        assert_eq!(&**w.into_buffer(), b"123");
    }

    #[test]
    fn writer_allows_empty_writes_at_the_cap() {
        let mut w = BoundedPlainWriter::with_cap(2);
        assert_eq!(w.write(b"12").unwrap(), 2);
        assert_eq!(w.write(b"").unwrap(), 0);
        assert!(!w.overflowed());
        assert!(w.flush().is_ok());
    }

    #[test]
    fn writer_default_cap_is_the_editor_limit() {
        assert_eq!(EDITOR_MAX_BYTES, 8 * 1024 * 1024);
        let mut w = BoundedPlainWriter::default();
        assert_eq!(w.write(b"fits easily").unwrap(), 11);
        assert!(!w.overflowed());
    }

    // --- text_from_buffer ---------------------------------------------------

    #[test]
    fn text_gate_accepts_valid_utf8() {
        let buf = Zeroizing::new("grüße 你好\n".as_bytes().to_vec());
        let text = text_from_buffer(buf).unwrap();
        assert_eq!(&**text, "grüße 你好\n");
    }

    #[test]
    fn text_gate_accepts_empty_content() {
        let text = text_from_buffer(Zeroizing::new(Vec::new())).unwrap();
        assert_eq!(&**text, "");
    }

    #[test]
    fn text_gate_rejects_invalid_utf8() {
        let buf = Zeroizing::new(vec![0x66, 0x6f, 0xff, 0xfe]);
        assert_eq!(text_from_buffer(buf), Err(NotText));
    }

    // --- SaveSource -----------------------------------------------------------

    fn secret() -> Secret {
        Secret::new(b"pw", None).unwrap()
    }

    fn noop() -> impl FnMut(Progress) -> ControlFlow<()> {
        |_| ControlFlow::Continue(())
    }

    /// Cheap parameters for `kdf` so tests stay fast.
    fn cheap_params(kdf: KdfId) -> KdfParams {
        match kdf {
            KdfId::Argon2id => KdfParams::Argon2id {
                memory_kib: 8192,
                time_cost: 1,
                parallelism: 1,
            },
            KdfId::Scrypt => KdfParams::Scrypt {
                log_n: 10,
                r: 8,
                p: 1,
            },
            KdfId::Pbkdf2 => KdfParams::Pbkdf2 { iterations: 10_000 },
        }
    }

    /// Mint a real `Header` by encrypting in memory and inspecting the result
    /// (front-ends cannot fabricate one — its wire fields are private).
    fn mint_header(cipher: CipherId, kdf: KdfId, filename: Option<&str>) -> Header {
        let opts = EncryptOptions {
            cipher,
            kdf,
            kdf_params: cheap_params(kdf),
            chunk_size: 4096,
            filename: filename.map(str::to_owned),
            armor: false,
        };
        let mut ct = Vec::new();
        let mut cb = noop();
        encrypt(&b"body"[..], &mut ct, &secret(), &opts, None, &mut cb).unwrap();
        match inspect(ct.as_slice()).unwrap() {
            Metadata::Paladin(header) => header,
            Metadata::AesCrypt(_) => unreachable!("we just wrote a paladin container"),
        }
    }

    /// The committed AES Crypt fixture from `paladin-core`'s test data.
    const AESCRYPT_V2: &[u8] =
        include_bytes!("../../paladin-core/tests/data/aescrypt/v2_size_17.aes");

    fn aescrypt_metadata() -> Metadata {
        let meta = inspect(AESCRYPT_V2).unwrap();
        assert!(matches!(meta, Metadata::AesCrypt(_)));
        meta
    }

    /// Field-by-field equality for `EncryptOptions` (it has no `PartialEq`).
    fn assert_opts_eq(actual: &EncryptOptions, expected: &EncryptOptions) {
        assert_eq!(actual.cipher, expected.cipher);
        assert_eq!(actual.kdf, expected.kdf);
        assert_eq!(actual.kdf_params, expected.kdf_params);
        assert_eq!(actual.chunk_size, expected.chunk_size);
        assert_eq!(actual.filename, expected.filename);
        assert_eq!(actual.armor, expected.armor);
    }

    #[test]
    fn paladin_source_preserves_cipher_kdf_params_and_chunk_size() {
        let combos = [
            (CipherId::Aes256Gcm, KdfId::Argon2id),
            (CipherId::ChaCha20Poly1305, KdfId::Scrypt),
            (CipherId::ChaCha20Poly1305, KdfId::Pbkdf2),
        ];
        for (cipher, kdf) in combos {
            let header = mint_header(cipher, kdf, None);
            let source = SaveSource::Paladin(header);
            let opts = source.options_for(false, Path::new("/x/out.txt")).unwrap();
            assert_eq!(opts.cipher, cipher);
            assert_eq!(opts.kdf, kdf);
            assert_eq!(opts.kdf_params, cheap_params(kdf));
            assert_eq!(opts.chunk_size, 4096);
            assert_eq!(opts.filename, None);
            assert!(!source.needs_migration_confirm());
        }
    }

    #[test]
    fn paladin_source_with_stored_name_embeds_the_output_basename() {
        let header = mint_header(CipherId::Aes256Gcm, KdfId::Pbkdf2, Some("orig.txt"));
        let source = SaveSource::Paladin(header);
        let opts = source
            .options_for(false, Path::new("/some/dir/renamed.txt"))
            .unwrap();
        assert_eq!(opts.filename.as_deref(), Some("renamed.txt"));
    }

    #[test]
    fn paladin_source_without_stored_name_stays_nameless() {
        let header = mint_header(CipherId::Aes256Gcm, KdfId::Pbkdf2, None);
        let source = SaveSource::Paladin(header);
        let opts = source
            .options_for(false, Path::new("/some/dir/renamed.txt"))
            .unwrap();
        assert_eq!(opts.filename, None);
    }

    #[test]
    fn paladin_source_with_stored_name_rejects_an_unusable_output_basename() {
        let header = mint_header(CipherId::Aes256Gcm, KdfId::Pbkdf2, Some("orig.txt"));
        let source = SaveSource::Paladin(header);
        // No final component to embed as a name.
        assert!(source.options_for(false, Path::new("")).is_err());
    }

    #[test]
    fn armor_recorded_at_open_passes_through_every_source_kind() {
        let paladin = SaveSource::Paladin(mint_header(CipherId::Aes256Gcm, KdfId::Pbkdf2, None));
        let pending = SaveSource::from_metadata(&aescrypt_metadata());
        let fixed = SaveSource::new_note();
        for source in [paladin, pending, fixed] {
            for armored in [false, true] {
                let opts = source.options_for(armored, Path::new("/x/f")).unwrap();
                assert_eq!(opts.armor, armored, "{source:?}");
            }
        }
    }

    #[test]
    fn aes_crypt_source_needs_confirmation_and_saves_the_defaults() {
        let source = SaveSource::from_metadata(&aescrypt_metadata());
        assert!(source.needs_migration_confirm());
        let opts = source
            .options_for(false, Path::new("/x/notes.aes"))
            .unwrap();
        // An AES Crypt header carries no paladin parameters: the migration
        // writes the §12 defaults with no stored name.
        assert_opts_eq(&opts, &EncryptOptions::default());
    }

    #[test]
    fn aes_crypt_source_becomes_fixed_after_the_migration_save() {
        let mut source = SaveSource::from_metadata(&aescrypt_metadata());
        let used = source.options_for(true, Path::new("/x/notes.aes")).unwrap();
        source.saved(&used);
        assert!(!source.needs_migration_confirm());
        // Later saves derive exactly what was just written.
        let next = source.options_for(true, Path::new("/x/notes.aes")).unwrap();
        assert_opts_eq(&next, &used);
    }

    #[test]
    fn paladin_source_still_rederives_after_a_save() {
        let header = mint_header(CipherId::Aes256Gcm, KdfId::Pbkdf2, Some("orig.txt"));
        let mut source = SaveSource::Paladin(header);
        let used = source
            .options_for(false, PathBuf::from("/a/one.txt").as_path())
            .unwrap();
        source.saved(&used);
        // A later Save As re-derives the embedded name from the new basename.
        let next = source.options_for(false, Path::new("/b/two.txt")).unwrap();
        assert_eq!(next.filename.as_deref(), Some("two.txt"));
    }

    #[test]
    fn new_note_saves_the_defaults_with_no_dialog() {
        let source = SaveSource::new_note();
        assert!(!source.needs_migration_confirm());
        let opts = source
            .options_for(false, Path::new("/x/note.paladin"))
            .unwrap();
        assert_opts_eq(&opts, &EncryptOptions::default());
    }
}
