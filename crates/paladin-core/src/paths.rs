//! Pure output-path helpers (DESIGN §6.5). No I/O: front-ends call these so all
//! three agree on default output names. Cipher/KDF name parsing — the other pure
//! helpers — lives with the types in `cipher.rs` and `kdf.rs`.

use std::path::{Path, PathBuf};

use crate::header::{Header, NameStatus};

/// Default output path for encryption: the input path with `.paladin`
/// (`.paladin.asc` when armored) appended (DESIGN §6.5, §12). The suffix is
/// appended to the whole `OsStr`, so non-UTF-8 paths are preserved and the
/// output lands beside the input.
pub fn default_encrypt_output(input: &Path, armor: bool) -> PathBuf {
    let mut os = input.as_os_str().to_os_string();
    os.push(if armor { ".paladin.asc" } else { ".paladin" });
    PathBuf::from(os)
}

/// Default output path for decryption (DESIGN §6.5). A well-formed stored name
/// is placed beside the input; otherwise the input filename has `.paladin.asc`,
/// `.paladin`, or `.asc` stripped (in that order), falling back to appending
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

/// Default output path for decrypting an AES Crypt (`.aes`) file (DESIGN §6.5).
/// The supported AES Crypt stream formats store no authenticated original
/// filename, so the output name is always derived from the input: a trailing
/// `.aes` (case-sensitive) is stripped, otherwise `.dec` is appended. Stripping
/// that would empty the basename (e.g. `.aes`) instead appends `.dec`. A
/// non-UTF-8 filename cannot be stripped safely, so `.dec` is appended.
pub fn default_aescrypt_output(input: &Path) -> PathBuf {
    let dir = input.parent().unwrap_or(Path::new(""));
    let file_name = input.file_name().unwrap_or(input.as_os_str());
    match file_name.to_str() {
        Some(name) => dir.join(strip_aescrypt_suffix(name)),
        None => {
            let mut os = input.as_os_str().to_os_string();
            os.push(".dec");
            PathBuf::from(os)
        }
    }
}

/// Strip a recognized encryption suffix from a UTF-8 filename, or append `.dec`.
/// Stripping that would leave an empty basename (e.g. `.paladin`) instead
/// appends `.dec` to the original (DESIGN §6.5). `.aes` is included so a
/// paladin file inadvertently named `*.aes` still strips sensibly.
fn strip_encrypt_suffix(name: &str) -> String {
    for suffix in [".paladin.asc", ".paladin", ".asc", ".aes"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            if stripped.is_empty() {
                return format!("{name}.dec");
            }
            return stripped.to_string();
        }
    }
    format!("{name}.dec")
}

/// Strip a trailing `.aes` (only), or append `.dec`, with the same empty-basename
/// fallback. Used by [`default_aescrypt_output`]; kept separate from
/// [`strip_encrypt_suffix`] because an AES Crypt file's name is only ever a
/// `.aes` name.
fn strip_aescrypt_suffix(name: &str) -> String {
    if let Some(stripped) = name.strip_suffix(".aes") {
        if !stripped.is_empty() {
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
            PathBuf::from("report.pdf.paladin")
        );
        assert_eq!(
            default_encrypt_output(Path::new("report.pdf"), true),
            PathBuf::from("report.pdf.paladin.asc")
        );
        // Output lands beside the input, suffix on the filename.
        assert_eq!(
            default_encrypt_output(Path::new("dir/sub/data"), false),
            PathBuf::from("dir/sub/data.paladin")
        );
    }

    #[test]
    fn decrypt_output_uses_well_formed_stored_name_beside_input() {
        let header = header_with_name(Some("original.pdf"));
        assert_eq!(header.name_status, NameStatus::Present);
        assert_eq!(
            default_decrypt_output(Path::new("dir/secret.paladin"), &header),
            PathBuf::from("dir/original.pdf")
        );
        // With no directory component, the stored name is used as-is.
        assert_eq!(
            default_decrypt_output(Path::new("secret.paladin"), &header),
            PathBuf::from("original.pdf")
        );
    }

    #[test]
    fn decrypt_output_ignores_unsafe_stored_name_and_strips_input() {
        let header = header_with_name(Some("../escape"));
        assert_eq!(header.name_status, NameStatus::IgnoredUnsafe);
        assert_eq!(
            default_decrypt_output(Path::new("dir/report.pdf.paladin"), &header),
            PathBuf::from("dir/report.pdf")
        );
    }

    #[test]
    fn decrypt_output_strips_recognized_suffixes() {
        let header = header_with_name(None);
        assert_eq!(header.name_status, NameStatus::Absent);
        let cases = [
            ("report.pdf.paladin", "report.pdf"),
            ("report.pdf.paladin.asc", "report.pdf"),
            ("archive.asc", "archive"),
            ("dir/report.paladin", "dir/report"),
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
            (".paladin", ".paladin.dec"),
            (".asc", ".asc.dec"),
            (".paladin.asc", ".paladin.asc.dec"),
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
        // .paladin.asc must win over the trailing .asc.
        assert_eq!(strip_encrypt_suffix("x.paladin.asc"), "x");
        assert_eq!(strip_encrypt_suffix("x.paladin"), "x");
        assert_eq!(strip_encrypt_suffix("x.asc"), "x");
        // A paladin file inadvertently named *.aes also strips.
        assert_eq!(strip_encrypt_suffix("x.aes"), "x");
    }

    #[test]
    fn aescrypt_output_strips_aes_or_appends_dec() {
        let cases = [
            ("secret.aes", "secret"),
            ("dir/report.pdf.aes", "dir/report.pdf"),
            ("secret", "secret.dec"),
            ("plain.txt", "plain.txt.dec"),
            // Stripping would empty the basename, so .dec is appended instead.
            (".aes", ".aes.dec"),
            // Case-sensitive: .AES is not stripped.
            ("photo.AES", "photo.AES.dec"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                default_aescrypt_output(Path::new(input)),
                PathBuf::from(expected),
                "input {input}"
            );
        }
    }

    // A non-UTF-8 filename can't be suffix-stripped safely, so `.dec` is appended.
    #[cfg(unix)]
    #[test]
    fn aescrypt_output_appends_dec_for_non_utf8_filename() {
        use std::os::unix::ffi::OsStrExt;

        let raw = [b'f', b'o', b'o', 0x80u8];
        let name = std::ffi::OsStr::from_bytes(&raw);
        let input = Path::new("dir").join(name);

        let mut expected = input.as_os_str().to_os_string();
        expected.push(".dec");
        assert_eq!(default_aescrypt_output(&input), PathBuf::from(expected));
    }

    // A non-UTF-8 filename can't be suffix-stripped safely, so `.dec` is appended
    // (DESIGN §6.5). Unix-gated: constructing a non-UTF-8 path is platform-specific.
    #[cfg(unix)]
    #[test]
    fn decrypt_output_appends_dec_for_non_utf8_filename() {
        use std::os::unix::ffi::OsStrExt;

        let raw = [b'f', b'o', b'o', 0x80u8];
        let name = std::ffi::OsStr::from_bytes(&raw);
        let input = Path::new("dir").join(name);
        let header = header_with_name(None);
        assert_eq!(header.name_status, NameStatus::Absent);

        // Expected: the whole input OsString with `.dec` pushed, as the fn does.
        let mut expected = input.as_os_str().to_os_string();
        expected.push(".dec");
        let expected = PathBuf::from(expected);

        assert_eq!(default_decrypt_output(&input, &header), expected);
    }

    // A safe Present stored name short-circuits before the `to_str()` branch, so a
    // non-UTF-8 input path still yields the stored name beside the input dir.
    #[cfg(unix)]
    #[test]
    fn decrypt_output_uses_present_name_even_with_non_utf8_input() {
        use std::os::unix::ffi::OsStrExt;

        let raw = [b'f', b'o', b'o', 0x80u8];
        let name = std::ffi::OsStr::from_bytes(&raw);
        let input = Path::new("dir").join(name);
        let header = header_with_name(Some("real.txt"));
        assert_eq!(header.name_status, NameStatus::Present);

        assert_eq!(
            default_decrypt_output(&input, &header),
            PathBuf::from("dir/real.txt")
        );
    }
}
