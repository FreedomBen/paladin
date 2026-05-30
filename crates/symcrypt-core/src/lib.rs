//! `symcrypt-core` — all crypto, file format, streaming, and pure helpers.
//!
//! This crate does all the work; the front-ends are thin views over it. It
//! never reads argv, never prompts, never touches the filesystem on its own,
//! never decides whether to overwrite, and never exits the process. See
//! `DESIGN.md` for the authoritative specification.
//!
//! Every front-end calls the same four operations — [`encrypt`], [`decrypt`],
//! [`inspect`], and [`verify`] — over generic `Read`/`Write`, reporting progress
//! and observing cancellation through an [`OnProgress`] callback.

use std::io::{Read, Write};

mod armor;
mod cipher;
mod error;
mod header;
mod kdf;
mod secret;
mod stream;

pub use cipher::CipherId;
pub use error::{Result, SymError};
pub use header::{Header, NameStatus};
pub use kdf::{KdfId, KdfParams};
pub use secret::{Secret, KEYFILE_MAX_BYTES};
pub use stream::{EncryptOptions, OnProgress, Progress};

/// Encrypt `input` to `output`, writing a self-describing authenticated
/// container. With `opts.armor`, the binary container is wrapped in ASCII armor
/// (DESIGN §5.6). `input_len` is an advisory hint for progress only; the §4.3
/// size cap is enforced from streamed bytes.
pub fn encrypt<R: Read, W: Write>(
    input: R,
    output: W,
    secret: &Secret,
    opts: &EncryptOptions,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
) -> Result<()> {
    if opts.armor {
        let mut writer = armor::ArmorWriter::new(output).map_err(SymError::Io)?;
        stream::encrypt(input, &mut writer, secret, opts, input_len, on_progress)?;
        writer.finish().map_err(SymError::Io)?;
        Ok(())
    } else {
        stream::encrypt(input, output, secret, opts, input_len, on_progress)
    }
}

/// Decrypt `input` to `output`, verifying every authentication tag. Armor is
/// auto-detected and stripped (DESIGN §5.6). A failed tag is reported as the
/// single [`SymError::Auth`] condition.
pub fn decrypt<R: Read, W: Write>(
    input: R,
    output: W,
    secret: &Secret,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
) -> Result<()> {
    let reader = armor::auto_dearmor(input)?;
    stream::decrypt(reader, output, secret, input_len, on_progress)
}

/// Parse and return the **unauthenticated** header metadata, auto-detecting
/// armor. Powers `--info`; needs no secret and authenticates nothing (DESIGN
/// §6.2).
pub fn inspect<R: Read>(input: R) -> Result<Header> {
    let mut reader = armor::auto_dearmor(input)?;
    header::parse(&mut reader)
}

/// Verify integrity and the secret by decrypting and discarding the plaintext
/// (DESIGN §6.2). Armor is auto-detected.
pub fn verify<R: Read>(
    input: R,
    secret: &Secret,
    input_len: Option<u64>,
    on_progress: &mut OnProgress<'_>,
) -> Result<()> {
    let reader = armor::auto_dearmor(input)?;
    stream::verify(reader, secret, input_len, on_progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::ControlFlow;

    fn secret() -> Secret {
        Secret::new(b"a strong test passphrase", None).unwrap()
    }

    /// Fast options (PBKDF2) for end-to-end tests, optionally armored/named.
    fn opts(armor: bool, filename: Option<&str>) -> EncryptOptions {
        EncryptOptions {
            cipher: CipherId::ChaCha20Poly1305,
            kdf: KdfId::Pbkdf2,
            kdf_params: KdfParams::Pbkdf2 { iterations: 10_000 },
            chunk_size: 4096,
            filename: filename.map(str::to_owned),
            armor,
        }
    }

    fn noop() -> impl FnMut(Progress) -> ControlFlow<()> {
        |_| ControlFlow::Continue(())
    }

    fn do_encrypt(data: &[u8], opts: &EncryptOptions) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cb = noop();
        encrypt(data, &mut out, &secret(), opts, None, &mut cb).unwrap();
        out
    }

    #[test]
    fn public_api_binary_and_armored_round_trip() {
        let data = b"the full public-API round trip across both layers".to_vec();
        for armored in [false, true] {
            let ct = do_encrypt(&data, &opts(armored, None));
            if armored {
                assert!(ct.starts_with(b"-----BEGIN SYMCRYPT MESSAGE-----"));
            } else {
                assert!(ct.starts_with(b"SYMCRYPT"));
            }
            let mut out = Vec::new();
            let mut cb = noop();
            decrypt(ct.as_slice(), &mut out, &secret(), None, &mut cb).unwrap();
            assert_eq!(out, data, "armored={armored}");
        }
    }

    #[test]
    fn inspect_reports_metadata_without_a_secret() {
        let ct = do_encrypt(b"data", &opts(true, Some("report.pdf")));
        // inspect auto-detects the armor and needs no password.
        let header = inspect(ct.as_slice()).unwrap();
        assert_eq!(header.cipher, CipherId::ChaCha20Poly1305);
        assert_eq!(header.kdf(), KdfId::Pbkdf2);
        assert_eq!(header.name_status, NameStatus::Present);
        assert_eq!(header.name.as_deref(), Some("report.pdf"));
        assert!(header.filename_present());
        assert!(!header.keyfile_hint());
    }

    #[test]
    fn verify_accepts_valid_and_rejects_tampered() {
        let ct = do_encrypt(b"payload to verify", &opts(false, None));
        let mut cb = noop();
        assert!(verify(ct.as_slice(), &secret(), None, &mut cb).is_ok());

        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let mut cb = noop();
        assert!(matches!(
            verify(tampered.as_slice(), &secret(), None, &mut cb),
            Err(SymError::Auth)
        ));
    }

    #[test]
    fn malformed_armor_through_public_api_maps_to_malformed_header() {
        // Invalid base64 in the armor body must surface as MalformedHeader
        // (exit 4) through the public API, proving the armor framing error is
        // recovered through the Read interface rather than mis-mapped to Io.
        let bad =
            b"-----BEGIN SYMCRYPT MESSAGE-----\n!!!!not base64!!!!\n-----END SYMCRYPT MESSAGE-----\n";
        assert!(matches!(
            inspect(bad.as_ref()),
            Err(SymError::MalformedHeader(_))
        ));
        let mut out = Vec::new();
        let mut cb = noop();
        assert!(matches!(
            decrypt(bad.as_ref(), &mut out, &secret(), None, &mut cb),
            Err(SymError::MalformedHeader(_))
        ));
    }

    #[test]
    fn keyfile_hint_is_set_when_a_keyfile_is_used() {
        let kf_secret = Secret::new(b"pw", Some(b"keyfile-bytes")).unwrap();
        let mut out = Vec::new();
        let mut cb = noop();
        encrypt(
            b"data".as_ref(),
            &mut out,
            &kf_secret,
            &opts(false, None),
            None,
            &mut cb,
        )
        .unwrap();
        assert!(inspect(out.as_slice()).unwrap().keyfile_hint());
    }
}
