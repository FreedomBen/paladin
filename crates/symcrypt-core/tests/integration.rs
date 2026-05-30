//! End-to-end integration tests against the public `symcrypt-core` API — the
//! same surface the front-ends use. Format-internal and unit coverage lives in
//! the crate's inline tests; these exercise the composed
//! armor + header + stream paths from an external crate.

use std::ops::ControlFlow;
use std::path::Path;

use symcrypt_core::{
    decrypt, default_decrypt_output, default_encrypt_output, encrypt, inspect, verify, CipherId,
    EncryptOptions, KdfId, KdfParams, NameStatus, Progress, Secret, SymError,
};

fn noop() -> impl FnMut(Progress) -> ControlFlow<()> {
    |_| ControlFlow::Continue(())
}

fn secret() -> Secret {
    Secret::new(b"integration test passphrase", None).unwrap()
}

/// Cheap, in-range parameters so each KDF runs quickly.
fn cheap(kdf: KdfId) -> KdfParams {
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

fn options(cipher: CipherId, kdf: KdfId, armor: bool, filename: Option<&str>) -> EncryptOptions {
    EncryptOptions {
        cipher,
        kdf,
        kdf_params: cheap(kdf),
        chunk_size: 4096,
        filename: filename.map(str::to_owned),
        armor,
    }
}

fn do_encrypt(data: &[u8], opts: &EncryptOptions) -> Vec<u8> {
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

fn do_decrypt(ct: &[u8]) -> Result<Vec<u8>, SymError> {
    let mut out = Vec::new();
    let mut cb = noop();
    decrypt(ct, &mut out, &secret(), None, &mut cb)?;
    Ok(out)
}

#[test]
fn round_trip_every_cipher_kdf_binary_and_armored() {
    // A payload spanning more than one 4 KiB chunk.
    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    for cipher in [CipherId::Aes256Gcm, CipherId::ChaCha20Poly1305] {
        for kdf in [KdfId::Argon2id, KdfId::Scrypt, KdfId::Pbkdf2] {
            for armor in [false, true] {
                let ct = do_encrypt(&data, &options(cipher, kdf, armor, None));
                if armor {
                    assert!(ct.starts_with(b"-----BEGIN SYMCRYPT MESSAGE-----"));
                    assert!(ct.ends_with(b"-----END SYMCRYPT MESSAGE-----\n"));
                } else {
                    assert!(ct.starts_with(b"SYMCRYPT"));
                }
                assert_eq!(
                    do_decrypt(&ct).unwrap(),
                    data,
                    "{cipher}/{kdf} armored={armor}"
                );
            }
        }
    }
}

#[test]
fn inspect_reads_metadata_from_armored_without_a_secret() {
    let ct = do_encrypt(
        b"hello",
        &options(
            CipherId::ChaCha20Poly1305,
            KdfId::Argon2id,
            true,
            Some("notes.txt"),
        ),
    );
    let header = inspect(ct.as_slice()).unwrap();
    assert_eq!(header.version, 1);
    assert_eq!(header.cipher, CipherId::ChaCha20Poly1305);
    assert_eq!(header.kdf(), KdfId::Argon2id);
    assert_eq!(header.chunk_size, 4096);
    assert_eq!(header.name_status, NameStatus::Present);
    assert_eq!(header.name.as_deref(), Some("notes.txt"));
    assert!(!header.keyfile_hint());
}

#[test]
fn verify_accepts_valid_and_rejects_tampered_and_wrong_password() {
    let ct = do_encrypt(
        b"verify me",
        &options(CipherId::Aes256Gcm, KdfId::Pbkdf2, false, None),
    );

    let mut cb = noop();
    assert!(verify(ct.as_slice(), &secret(), None, &mut cb).is_ok());

    // Flip a body byte.
    let mut tampered = ct.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let mut cb = noop();
    assert!(matches!(
        verify(tampered.as_slice(), &secret(), None, &mut cb),
        Err(SymError::Auth)
    ));

    // Wrong password.
    let wrong = Secret::new(b"not the passphrase", None).unwrap();
    let mut cb = noop();
    assert!(matches!(
        verify(ct.as_slice(), &wrong, None, &mut cb),
        Err(SymError::Auth)
    ));
}

#[test]
fn tampering_with_an_armored_file_fails_auth() {
    let ct = do_encrypt(
        b"armored secret payload",
        &options(CipherId::Aes256Gcm, KdfId::Pbkdf2, true, None),
    );
    // Corrupt a base64 character in the middle of the body (a valid base64 char
    // so it still decodes, but to different bytes).
    let mut t = ct.clone();
    let mid = t.len() / 2;
    t[mid] = if t[mid] == b'A' { b'B' } else { b'A' };
    assert!(matches!(do_decrypt(&t), Err(SymError::Auth)));
}

#[test]
fn default_output_paths_compose_with_inspect() {
    assert_eq!(
        default_encrypt_output(Path::new("report.pdf"), false),
        Path::new("report.pdf.symcrypt")
    );
    assert_eq!(
        default_encrypt_output(Path::new("report.pdf"), true),
        Path::new("report.pdf.symcrypt.asc")
    );

    // With a stored name, decrypt output uses it beside the input.
    let ct = do_encrypt(
        b"x",
        &options(CipherId::Aes256Gcm, KdfId::Pbkdf2, false, Some("real.txt")),
    );
    let header = inspect(ct.as_slice()).unwrap();
    assert_eq!(
        default_decrypt_output(Path::new("dir/secret.symcrypt"), &header),
        Path::new("dir/real.txt")
    );

    // Without a stored name, the suffix is stripped from the input path.
    let ct = do_encrypt(
        b"x",
        &options(CipherId::Aes256Gcm, KdfId::Pbkdf2, false, None),
    );
    let header = inspect(ct.as_slice()).unwrap();
    assert_eq!(
        default_decrypt_output(Path::new("dir/secret.symcrypt"), &header),
        Path::new("dir/secret")
    );
}

#[test]
fn unknown_cipher_id_is_unsupported_format() {
    let mut ct = do_encrypt(
        b"x",
        &options(CipherId::Aes256Gcm, KdfId::Pbkdf2, false, None),
    );
    // cipher_id byte lives at offset 9 in the binary header.
    ct[9] = 0x7f;
    assert!(matches!(
        do_decrypt(&ct),
        Err(SymError::UnknownCipher(0x7f))
    ));
}

#[test]
fn keyfile_round_trips_and_sets_the_hint() {
    let kf = Secret::new(b"pw", Some(b"a keyfile's bytes")).unwrap();
    let mut ct = Vec::new();
    let mut cb = noop();
    encrypt(
        b"second-factor data".as_ref(),
        &mut ct,
        &kf,
        &options(CipherId::Aes256Gcm, KdfId::Pbkdf2, false, None),
        None,
        &mut cb,
    )
    .unwrap();

    assert!(inspect(ct.as_slice()).unwrap().keyfile_hint());

    // Decryptable only with the keyfile.
    let mut out = Vec::new();
    let mut cb = noop();
    decrypt(ct.as_slice(), &mut out, &kf, None, &mut cb).unwrap();
    assert_eq!(out, b"second-factor data");

    let no_kf = Secret::new(b"pw", None).unwrap();
    let mut cb = noop();
    assert!(matches!(
        decrypt(ct.as_slice(), &mut Vec::new(), &no_kf, None, &mut cb),
        Err(SymError::Auth)
    ));
}
