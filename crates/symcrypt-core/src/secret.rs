//! [`Secret`] — the password and/or keyfile material handed to the core.
//!
//! The bytes are copied into zeroizing buffers and wiped on drop. The KDF input
//! is a domain-separated, length-prefixed encoding (DESIGN §4.2) so a password
//! and a keyfile can never be confused for one another regardless of contents.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::{Result, SymError};

/// Domain-separation prefix for the KDF input (DESIGN §4.2). The trailing NUL is
/// part of the constant.
const SECRET_DOMAIN: &[u8] = b"symcrypt secret v1\0";

/// Maximum keyfile size read into memory: 1 MiB (DESIGN §4.2). Bounds memory and
/// is shared with the front-ends so they enforce the same limit.
pub const KEYFILE_MAX_BYTES: usize = 1024 * 1024;

/// Password and/or keyfile material; zeroized on drop.
///
/// Construct with [`Secret::new`]. At least one of password or keyfile must be
/// non-empty; if a keyfile is supplied it must be 1 byte..=1 MiB. The stored
/// bytes never appear in `Debug` output.
pub struct Secret {
    password: Zeroizing<Vec<u8>>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
}

impl Secret {
    /// Build a [`Secret`] from raw password bytes and an optional keyfile.
    ///
    /// Returns [`SymError::InvalidOptions`] (exit 2) if both are empty, or if a
    /// supplied keyfile is empty or larger than [`KEYFILE_MAX_BYTES`]. The
    /// caller owns zeroization of the slices it passes in; the bytes are copied
    /// into zeroizing storage here.
    pub fn new(password: &[u8], keyfile: Option<&[u8]>) -> Result<Self> {
        if let Some(kf) = keyfile {
            if kf.is_empty() {
                return Err(SymError::InvalidOptions(
                    "keyfile is empty (must be 1 byte..=1 MiB)",
                ));
            }
            if kf.len() > KEYFILE_MAX_BYTES {
                return Err(SymError::InvalidOptions("keyfile exceeds 1 MiB"));
            }
        }
        if password.is_empty() && keyfile.is_none() {
            return Err(SymError::InvalidOptions(
                "empty secret: a password or keyfile is required",
            ));
        }
        Ok(Self {
            password: Zeroizing::new(password.to_vec()),
            keyfile: keyfile.map(|kf| Zeroizing::new(kf.to_vec())),
        })
    }

    /// Whether a keyfile contributed to this secret. Used to set the advisory
    /// `keyfile-used` header flag (DESIGN §4.2, bit1).
    pub(crate) fn has_keyfile(&self) -> bool {
        self.keyfile.is_some()
    }

    /// The domain-separated, length-prefixed KDF input (DESIGN §4.2):
    /// `SECRET_DOMAIN || u64be(pw_len) || pw || u64be(kf_len) || kf`.
    ///
    /// The result is wrapped in [`Zeroizing`] so it is wiped after key
    /// derivation. The exact capacity is reserved up front so the buffer never
    /// reallocates and leaves a stale copy of secret bytes behind.
    pub(crate) fn kdf_input(&self) -> Zeroizing<Vec<u8>> {
        let pw: &[u8] = &self.password;
        let kf: &[u8] = self.keyfile.as_ref().map(|k| k.as_slice()).unwrap_or(&[]);
        let mut out = Vec::with_capacity(SECRET_DOMAIN.len() + 8 + pw.len() + 8 + kf.len());
        out.extend_from_slice(SECRET_DOMAIN);
        out.extend_from_slice(&(pw.len() as u64).to_be_bytes());
        out.extend_from_slice(pw);
        out.extend_from_slice(&(kf.len() as u64).to_be_bytes());
        out.extend_from_slice(kf);
        Zeroizing::new(out)
    }
}

impl fmt::Debug for Secret {
    /// Never print secret bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("password", &"<redacted>")
            .field("keyfile", &self.keyfile.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_password_and_no_keyfile_is_rejected() {
        assert!(matches!(
            Secret::new(b"", None),
            Err(SymError::InvalidOptions(_))
        ));
    }

    #[test]
    fn empty_keyfile_is_rejected() {
        assert!(matches!(
            Secret::new(b"pw", Some(b"")),
            Err(SymError::InvalidOptions(_))
        ));
        // Even with an otherwise-empty password.
        assert!(matches!(
            Secret::new(b"", Some(b"")),
            Err(SymError::InvalidOptions(_))
        ));
    }

    #[test]
    fn oversize_keyfile_is_rejected_and_max_is_accepted() {
        let too_big = vec![0u8; KEYFILE_MAX_BYTES + 1];
        assert!(matches!(
            Secret::new(b"pw", Some(&too_big)),
            Err(SymError::InvalidOptions(_))
        ));
        let exactly_max = vec![0u8; KEYFILE_MAX_BYTES];
        assert!(Secret::new(b"", Some(&exactly_max)).is_ok());
    }

    #[test]
    fn password_only_keyfile_only_and_both_are_accepted() {
        assert!(Secret::new(b"hunter2", None).is_ok());
        assert!(Secret::new(b"", Some(b"keymaterial")).is_ok());
        assert!(Secret::new(b"hunter2", Some(b"keymaterial")).is_ok());
    }

    #[test]
    fn has_keyfile_reflects_presence() {
        assert!(!Secret::new(b"pw", None).unwrap().has_keyfile());
        assert!(Secret::new(b"pw", Some(b"k")).unwrap().has_keyfile());
    }

    #[test]
    fn kdf_input_exact_layout_is_locked() {
        // Locks the §4.2 wire encoding so it cannot drift silently.
        let s = Secret::new(b"pw", Some(b"k")).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"symcrypt secret v1\0");
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(b"pw");
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(b"k");
        assert_eq!(&*s.kdf_input(), &expected[..]);
        // The domain prefix is exactly 19 bytes (18 ASCII + NUL).
        assert_eq!(SECRET_DOMAIN.len(), 19);
    }

    #[test]
    fn keyfile_only_encodes_zero_length_password() {
        let s = Secret::new(b"", Some(b"k")).unwrap();
        let input = s.kdf_input();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"symcrypt secret v1\0");
        expected.extend_from_slice(&0u64.to_be_bytes());
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(b"k");
        assert_eq!(&*input, &expected[..]);
    }

    #[test]
    fn length_prefixes_remove_password_keyfile_ambiguity() {
        // The classic confusion: ("ab","c") and ("a","bc") share the same
        // concatenated bytes but must derive different keys.
        let a = Secret::new(b"ab", Some(b"c")).unwrap();
        let b = Secret::new(b"a", Some(b"bc")).unwrap();
        assert_ne!(&*a.kdf_input(), &*b.kdf_input());

        // A keyfile-only secret must differ from a password-only one with the
        // same bytes.
        let pw_only = Secret::new(b"secret", None).unwrap();
        let kf_only = Secret::new(b"", Some(b"secret")).unwrap();
        assert_ne!(&*pw_only.kdf_input(), &*kf_only.kdf_input());
    }

    #[test]
    fn debug_redacts_secret_bytes() {
        let s = Secret::new(b"hunter2", Some(b"topsecretkey")).unwrap();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("topsecretkey"));
        assert!(dbg.contains("redacted"));
    }
}
