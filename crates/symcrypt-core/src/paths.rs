//! Pure output-path helpers (DESIGN §6.5). No I/O: front-ends call these so all
//! three agree on default output names. Cipher/KDF name parsing — the other pure
//! helpers — lives with the types in `cipher.rs` and `kdf.rs`.

use std::path::{Path, PathBuf};

use crate::header::{Header, NameStatus};

/// Default output path for encryption: the input path with `.symcrypt`
/// (`.symcrypt.asc` when armored) appended (DESIGN §6.5, §12). The suffix is
/// appended to the whole `OsStr`, so non-UTF-8 paths are preserved and the
/// output lands beside the input.
pub fn default_encrypt_output(input: &Path, armor: bool) -> PathBuf {
    let mut os = input.as_os_str().to_os_string();
    os.push(if armor { ".symcrypt.asc" } else { ".symcrypt" });
    PathBuf::from(os)
}

/// Default output path for decryption (DESIGN §6.5). A well-formed stored name
/// is placed beside the input; otherwise the input filename has `.symcrypt.asc`,
/// `.symcrypt`, or `.asc` stripped (in that order), falling back to appending
/// `.dec` when nothing is recognized or stripping would empty the basename. A
/// non-UTF-8 filename cannot be stripped safely, so `.dec` is appended.
pub fn default_decrypt_output(input: &Path, header: &Header) -> PathBuf {
    let dir = input.parent().unwrap_or(Path::new(""));

    if header.name_status == NameStatus::Present {
        if let Some(name) = &header.name {
            return dir.join(name);
        }
    }

    let file_name = input.file_name().unwrap_or(input.as_os_str());
    match file_name.to_str() {
        Some(name) => dir.join(strip_encrypt_suffix(name)),
        None => {
            let mut os = input.as_os_str().to_os_string();
            os.push(".dec");
            PathBuf::from(os)
        }
    }
}

/// Strip a recognized encryption suffix from a UTF-8 filename, or append `.dec`.
/// Stripping that would leave an empty basename (e.g. `.symcrypt`) instead
/// appends `.dec` to the original (DESIGN §6.5).
fn strip_encrypt_suffix(name: &str) -> String {
    for suffix in [".symcrypt.asc", ".symcrypt", ".asc"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            if stripped.is_empty() {
                return format!("{name}.dec");
            }
            return stripped.to_string();
        }
    }
    format!("{name}.dec")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::CipherId;
    use crate::header;
    use crate::kdf::{KdfId, KdfParams};

    /// Build a real parsed header carrying `name` (None => absent).
    fn header_with_name(name: Option<&str>) -> Header {
        let bytes = header::serialize(
            CipherId::Aes256Gcm,
            KdfParams::default_for(KdfId::Argon2id),
            &[0u8; 16],
            &[0u8; 7],
            65536,
            name,
            false,
        );
        header::parse(&mut std::io::Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn encrypt_output_appends_suffix() {
        assert_eq!(
            default_encrypt_output(Path::new("report.pdf"), false),
            PathBuf::from("report.pdf.symcrypt")
        );
        assert_eq!(
            default_encrypt_output(Path::new("report.pdf"), true),
            PathBuf::from("report.pdf.symcrypt.asc")
        );
        // Output lands beside the input, suffix on the filename.
        assert_eq!(
            default_encrypt_output(Path::new("dir/sub/data"), false),
            PathBuf::from("dir/sub/data.symcrypt")
        );
    }

    #[test]
    fn decrypt_output_uses_well_formed_stored_name_beside_input() {
        let header = header_with_name(Some("original.pdf"));
        assert_eq!(header.name_status, NameStatus::Present);
        assert_eq!(
            default_decrypt_output(Path::new("dir/secret.symcrypt"), &header),
            PathBuf::from("dir/original.pdf")
        );
        // With no directory component, the stored name is used as-is.
        assert_eq!(
            default_decrypt_output(Path::new("secret.symcrypt"), &header),
            PathBuf::from("original.pdf")
        );
    }

    #[test]
    fn decrypt_output_ignores_unsafe_stored_name_and_strips_input() {
        let header = header_with_name(Some("../escape"));
        assert_eq!(header.name_status, NameStatus::IgnoredUnsafe);
        assert_eq!(
            default_decrypt_output(Path::new("dir/report.pdf.symcrypt"), &header),
            PathBuf::from("dir/report.pdf")
        );
    }

    #[test]
    fn decrypt_output_strips_recognized_suffixes() {
        let header = header_with_name(None);
        assert_eq!(header.name_status, NameStatus::Absent);
        let cases = [
            ("report.pdf.symcrypt", "report.pdf"),
            ("report.pdf.symcrypt.asc", "report.pdf"),
            ("archive.asc", "archive"),
            ("dir/report.symcrypt", "dir/report"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                default_decrypt_output(Path::new(input), &header),
                PathBuf::from(expected),
                "input {input}"
            );
        }
    }

    #[test]
    fn decrypt_output_appends_dec_when_no_suffix() {
        let header = header_with_name(None);
        assert_eq!(
            default_decrypt_output(Path::new("plain.txt"), &header),
            PathBuf::from("plain.txt.dec")
        );
    }

    #[test]
    fn decrypt_output_empty_basename_fallback() {
        let header = header_with_name(None);
        let cases = [
            (".symcrypt", ".symcrypt.dec"),
            (".asc", ".asc.dec"),
            (".symcrypt.asc", ".symcrypt.asc.dec"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                default_decrypt_output(Path::new(input), &header),
                PathBuf::from(expected),
                "input {input}"
            );
        }
    }

    #[test]
    fn strip_encrypt_suffix_prefers_longest_match() {
        // .symcrypt.asc must win over the trailing .asc.
        assert_eq!(strip_encrypt_suffix("x.symcrypt.asc"), "x");
        assert_eq!(strip_encrypt_suffix("x.symcrypt"), "x");
        assert_eq!(strip_encrypt_suffix("x.asc"), "x");
    }
}
