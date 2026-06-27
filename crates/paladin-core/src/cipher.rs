//! AEAD cipher identity and dispatch (DESIGN §4.1, §5.3).
//!
//! [`CipherId`] is the public, front-end-facing identifier with exact-lowercase
//! `FromStr`/`Display` and the on-disk id byte. [`Cipher`] is a keyed AEAD
//! instance the stream layer constructs once and reuses across chunks; its
//! `seal`/`open` take the 12-byte STREAM nonce and the associated data that
//! binds the header.

use std::fmt;
use std::str::FromStr;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::{PalError, Result};

/// AEAD cipher selector. The default for new files is [`CipherId::Aes256Gcm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherId {
    /// AES-256-GCM (id `0x01`).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (id `0x02`).
    ChaCha20Poly1305,
}

impl CipherId {
    /// The canonical lowercase name (DESIGN §6.3). No aliases, no case folding.
    pub fn as_str(self) -> &'static str {
        match self {
            CipherId::Aes256Gcm => "aes-256-gcm",
            CipherId::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// On-disk `cipher_id` byte (DESIGN §5.3).
    pub(crate) fn id(self) -> u8 {
        match self {
            CipherId::Aes256Gcm => 0x01,
            CipherId::ChaCha20Poly1305 => 0x02,
        }
    }

    /// Parse a `cipher_id` byte read from a header. An unrecognized id is
    /// [`PalError::UnknownCipher`] (exit 4), never a guess.
    pub(crate) fn from_id(id: u8) -> Result<Self> {
        match id {
            0x01 => Ok(CipherId::Aes256Gcm),
            0x02 => Ok(CipherId::ChaCha20Poly1305),
            other => Err(PalError::UnknownCipher(other)),
        }
    }
}

impl fmt::Display for CipherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CipherId {
    type Err = PalError;

    /// Exact, lowercase match only (DESIGN §6.3). An unknown name is a usage
    /// error ([`PalError::InvalidOptions`], exit 2).
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "aes-256-gcm" => Ok(CipherId::Aes256Gcm),
            "chacha20-poly1305" => Ok(CipherId::ChaCha20Poly1305),
            _ => Err(PalError::InvalidOptions(
                "unknown cipher (expected aes-256-gcm or chacha20-poly1305)",
            )),
        }
    }
}

/// A keyed AEAD instance. Both variants are boxed so the enum stays small and
/// uniform regardless of the ciphers' differing key-schedule sizes.
pub(crate) enum Cipher {
    Aes(Box<Aes256Gcm>),
    Cha(Box<ChaCha20Poly1305>),
}

impl Cipher {
    /// Key the selected AEAD with the 32-byte derived key.
    pub(crate) fn new(id: CipherId, key: &[u8; 32]) -> Self {
        match id {
            CipherId::Aes256Gcm => Cipher::Aes(Box::new(Aes256Gcm::new(
                aes_gcm::Key::<Aes256Gcm>::from_slice(key),
            ))),
            CipherId::ChaCha20Poly1305 => Cipher::Cha(Box::new(ChaCha20Poly1305::new(
                chacha20poly1305::Key::from_slice(key),
            ))),
        }
    }

    /// Encrypt one chunk, returning `ciphertext ‖ 16-byte tag`.
    ///
    /// The only documented failure mode of AEAD encryption is a message longer
    /// than the cipher's per-message limit; paladin's chunks are bounded far
    /// below it (DESIGN §5.4), so this is unreachable in practice and mapped to
    /// [`PalError::InputTooLarge`] for safety rather than panicking.
    pub(crate) fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let out = match self {
            Cipher::Aes(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Cipher::Cha(c) => c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload),
        };
        out.map_err(|_| PalError::InputTooLarge)
    }

    /// Decrypt and authenticate one chunk (`ciphertext ‖ tag`).
    ///
    /// Any failure — wrong key, wrong nonce, altered AAD, flipped bit, or a
    /// too-short buffer — is reported as the single [`PalError::Auth`] condition
    /// (DESIGN §4.4), never distinguishing tampering from a wrong password.
    pub(crate) fn open(&self, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let out = match self {
            Cipher::Aes(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Cipher::Cha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload),
        };
        out.map_err(|_| PalError::Auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const NONCE: [u8; 12] = [3u8; 12];

    fn both() -> [CipherId; 2] {
        [CipherId::Aes256Gcm, CipherId::ChaCha20Poly1305]
    }

    #[test]
    fn fromstr_display_round_trip() {
        for id in both() {
            assert_eq!(id.as_str().parse::<CipherId>().unwrap(), id);
            assert_eq!(id.to_string(), id.as_str());
        }
        assert_eq!(
            "aes-256-gcm".parse::<CipherId>().unwrap(),
            CipherId::Aes256Gcm
        );
        assert_eq!(
            "chacha20-poly1305".parse::<CipherId>().unwrap(),
            CipherId::ChaCha20Poly1305
        );
    }

    #[test]
    fn fromstr_rejects_aliases_and_case() {
        for bad in [
            "AES-256-GCM",
            "Aes-256-Gcm",
            "aes256gcm",
            "aes-256",
            "chacha20",
            "chacha20-poly1305 ",
            "",
            "xchacha20-poly1305",
        ] {
            assert!(bad.parse::<CipherId>().is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn id_byte_round_trip_and_unknown_rejected() {
        for id in both() {
            assert_eq!(CipherId::from_id(id.id()).unwrap(), id);
        }
        assert_eq!(CipherId::Aes256Gcm.id(), 0x01);
        assert_eq!(CipherId::ChaCha20Poly1305.id(), 0x02);
        for unknown in [0x00, 0x03, 0xff] {
            assert!(matches!(
                CipherId::from_id(unknown),
                Err(PalError::UnknownCipher(_))
            ));
        }
    }

    #[test]
    fn seal_open_round_trip_for_each_cipher() {
        for id in both() {
            let c = Cipher::new(id, &KEY);
            for pt in [
                &b""[..],
                b"x",
                b"the quick brown fox jumps over the lazy dog",
            ] {
                let ct = c.seal(&NONCE, b"aad", pt).unwrap();
                assert_eq!(ct.len(), pt.len() + 16, "tag appended for {id}");
                assert_eq!(c.open(&NONCE, b"aad", &ct).unwrap(), pt);
            }
        }
    }

    #[test]
    fn altered_aad_fails_authentication() {
        // This is the property the header-as-AAD downgrade defense relies on.
        for id in both() {
            let c = Cipher::new(id, &KEY);
            let ct = c.seal(&NONCE, b"header-v1", b"secret").unwrap();
            assert!(matches!(
                c.open(&NONCE, b"header-v2", &ct),
                Err(PalError::Auth)
            ));
        }
    }

    #[test]
    fn wrong_key_nonce_or_flipped_byte_fails_as_auth() {
        for id in both() {
            let c = Cipher::new(id, &KEY);
            let ct = c.seal(&NONCE, b"aad", b"secret").unwrap();

            let wrong_key = Cipher::new(id, &[9u8; 32]);
            assert!(matches!(
                wrong_key.open(&NONCE, b"aad", &ct),
                Err(PalError::Auth)
            ));

            let wrong_nonce = [4u8; 12];
            assert!(matches!(
                c.open(&wrong_nonce, b"aad", &ct),
                Err(PalError::Auth)
            ));

            let mut tampered = ct.clone();
            tampered[0] ^= 0x01;
            assert!(matches!(
                c.open(&NONCE, b"aad", &tampered),
                Err(PalError::Auth)
            ));

            // A buffer too short to hold a tag is also just an auth failure.
            assert!(matches!(
                c.open(&NONCE, b"aad", b"short"),
                Err(PalError::Auth)
            ));
        }
    }

    #[test]
    fn ciphertexts_differ_between_ciphers() {
        let aes = Cipher::new(CipherId::Aes256Gcm, &KEY);
        let cha = Cipher::new(CipherId::ChaCha20Poly1305, &KEY);
        let a = aes.seal(&NONCE, b"aad", b"same plaintext").unwrap();
        let c = cha.seal(&NONCE, b"aad", b"same plaintext").unwrap();
        assert_ne!(a, c);
    }
}
