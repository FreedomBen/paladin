//! Format a `symcrypt_core::Header` into display rows for the Info pane,
//! matching the CLI `--info` field labels and order (DESIGN §6.2).
//!
//! This is pure formatting logic with no GTK dependency, so the parity with the
//! CLI can be verified by unit tests without a display. [`header_text`] is
//! byte-identical to the CLI's `--info` output; [`header_rows`] exposes the same
//! fields as structured key/value pairs for rendering into widgets.

use symcrypt_core::{Header, KdfParams, NameStatus};

/// A single labeled field of header metadata for the Info pane.
///
/// `key` is the stable field name (e.g. `"cipher"`); `value` is its rendered
/// string. The `key`/`value` pair maps 1:1 onto a CLI `--info` line of the form
/// `"{key}: {value}"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoRow {
    /// Stable field label, identical to the CLI `--info` key.
    pub key: &'static str,
    /// Rendered field value (already formatted; may be empty).
    pub value: String,
}

impl InfoRow {
    fn new(key: &'static str, value: impl Into<String>) -> Self {
        Self {
            key,
            value: value.into(),
        }
    }
}

/// The human-readable `name_status` token for a [`NameStatus`], matching the
/// CLI (`absent` / `present` / `ignored_unsafe`).
fn name_status_str(status: NameStatus) -> &'static str {
    match status {
        NameStatus::Absent => "absent",
        NameStatus::Present => "present",
        NameStatus::IgnoredUnsafe => "ignored_unsafe",
    }
}

/// Render KDF parameters as the comma-separated `key=value` string the CLI
/// emits (no spaces), e.g. `memory=8192,time=1,parallelism=1`.
fn format_kdf_params(params: &KdfParams) -> String {
    match params {
        KdfParams::Argon2id {
            memory_kib,
            time_cost,
            parallelism,
        } => format!("memory={memory_kib},time={time_cost},parallelism={parallelism}"),
        KdfParams::Scrypt { log_n, r, p } => format!("log_n={log_n},r={r},p={p}"),
        KdfParams::Pbkdf2 { iterations } => format!("iterations={iterations}"),
    }
}

/// The stored basename, shown only when it is present and usable; otherwise
/// empty (matching the CLI, which blanks the `name` line unless
/// `name_status == Present`).
fn name_value(header: &Header) -> &str {
    if matches!(header.name_status, NameStatus::Present) {
        header.name.as_deref().unwrap_or("")
    } else {
        ""
    }
}

/// Build the ordered Info-pane rows for `header`.
///
/// The keys, order, and value formatting are identical to the CLI's `--info`
/// output (DESIGN §6.2): twelve rows from `format` through `name`.
pub fn header_rows(header: &Header) -> Vec<InfoRow> {
    vec![
        InfoRow::new("format", "symcrypt"),
        InfoRow::new("version", header.version.to_string()),
        InfoRow::new("cipher", header.cipher.to_string()),
        InfoRow::new("kdf", header.kdf().to_string()),
        InfoRow::new("kdf_params", format_kdf_params(&header.kdf_params)),
        InfoRow::new("flags", format!("0x{:02x}", header.flags)),
        InfoRow::new("keyfile_hint", header.keyfile_hint().to_string()),
        InfoRow::new("chunk_size", header.chunk_size.to_string()),
        InfoRow::new("salt_len", header.salt_len().to_string()),
        InfoRow::new("nonce_prefix_len", header.nonce_prefix_len().to_string()),
        InfoRow::new("name_status", name_status_str(header.name_status)),
        InfoRow::new("name", name_value(header).to_string()),
    ]
}

/// Render `header` as the multi-line `--info` text: each row as `"{key}: {value}"`,
/// joined by `\n`, with a single trailing newline. Byte-identical to the CLI.
pub fn header_text(header: &Header) -> String {
    let mut out = header_rows(header)
        .iter()
        .map(|row| format!("{}: {}", row.key, row.value))
        .collect::<Vec<_>>()
        .join("\n");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::ControlFlow;
    use symcrypt_core::{
        encrypt, inspect, CipherId, EncryptOptions, Header, KdfId, KdfParams, Secret,
    };

    /// Cheapest valid Argon2id params, to keep KDF-bound tests fast.
    fn cheap_argon2id() -> KdfParams {
        KdfParams::Argon2id {
            memory_kib: 8192,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// Encrypt a small in-memory buffer under `opts` and return its parsed header.
    fn header_for(opts: EncryptOptions) -> Header {
        let secret = Secret::new(b"pw", None).unwrap();
        let mut out = Vec::new();
        let mut cb = |_p| ControlFlow::Continue(());
        encrypt(&b"hello"[..], &mut out, &secret, &opts, Some(5), &mut cb).unwrap();
        inspect(&out[..]).unwrap()
    }

    fn opts(
        cipher: CipherId,
        kdf: KdfId,
        kdf_params: KdfParams,
        filename: Option<&str>,
    ) -> EncryptOptions {
        EncryptOptions {
            cipher,
            kdf,
            kdf_params,
            chunk_size: 65536,
            filename: filename.map(str::to_string),
            armor: false,
        }
    }

    #[test]
    fn full_rows_with_present_name() {
        let header = header_for(opts(
            CipherId::Aes256Gcm,
            KdfId::Argon2id,
            cheap_argon2id(),
            Some("note.txt"),
        ));

        let rows = header_rows(&header);
        let expected = vec![
            InfoRow::new("format", "symcrypt"),
            InfoRow::new("version", header.version.to_string()),
            InfoRow::new("cipher", "aes-256-gcm"),
            InfoRow::new("kdf", "argon2id"),
            InfoRow::new("kdf_params", "memory=8192,time=1,parallelism=1"),
            InfoRow::new("flags", "0x01"),
            InfoRow::new("keyfile_hint", "false"),
            InfoRow::new("chunk_size", header.chunk_size.to_string()),
            InfoRow::new("salt_len", header.salt_len().to_string()),
            InfoRow::new("nonce_prefix_len", header.nonce_prefix_len().to_string()),
            InfoRow::new("name_status", "present"),
            InfoRow::new("name", "note.txt"),
        ];
        assert_eq!(rows, expected);

        // v1 invariants: assert the concrete values the header reports.
        assert_eq!(header.version, 1);
        assert_eq!(header.salt_len(), 16);
        assert_eq!(header.nonce_prefix_len(), 7);
        assert_eq!(header.chunk_size, 65536);

        let expected_text = "format: symcrypt\n\
             version: 1\n\
             cipher: aes-256-gcm\n\
             kdf: argon2id\n\
             kdf_params: memory=8192,time=1,parallelism=1\n\
             flags: 0x01\n\
             keyfile_hint: false\n\
             chunk_size: 65536\n\
             salt_len: 16\n\
             nonce_prefix_len: 7\n\
             name_status: present\n\
             name: note.txt\n";
        assert_eq!(header_text(&header), expected_text);
    }

    #[test]
    fn absent_name_blanks_name_and_clears_flag() {
        let header = header_for(opts(
            CipherId::Aes256Gcm,
            KdfId::Argon2id,
            cheap_argon2id(),
            None,
        ));
        let rows = header_rows(&header);

        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap().value.as_str();
        assert_eq!(by_key("name_status"), "absent");
        assert_eq!(by_key("name"), "");
        assert_eq!(by_key("flags"), "0x00");
    }

    #[test]
    fn scrypt_kdf_and_params() {
        let header = header_for(opts(
            CipherId::Aes256Gcm,
            KdfId::Scrypt,
            KdfParams::Scrypt {
                log_n: 10,
                r: 1,
                p: 1,
            },
            None,
        ));
        let rows = header_rows(&header);
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap().value.as_str();
        assert_eq!(by_key("kdf"), "scrypt");
        assert_eq!(by_key("kdf_params"), "log_n=10,r=1,p=1");
    }

    #[test]
    fn pbkdf2_kdf_and_params() {
        let header = header_for(opts(
            CipherId::Aes256Gcm,
            KdfId::Pbkdf2,
            KdfParams::Pbkdf2 { iterations: 10_000 },
            None,
        ));
        let rows = header_rows(&header);
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap().value.as_str();
        assert_eq!(by_key("kdf"), "pbkdf2");
        assert_eq!(by_key("kdf_params"), "iterations=10000");
    }

    #[test]
    fn chacha_cipher() {
        let header = header_for(opts(
            CipherId::ChaCha20Poly1305,
            KdfId::Argon2id,
            cheap_argon2id(),
            None,
        ));
        let rows = header_rows(&header);
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap().value.as_str();
        assert_eq!(by_key("cipher"), "chacha20-poly1305");
    }

    #[test]
    fn name_status_str_all_variants() {
        assert_eq!(name_status_str(NameStatus::Absent), "absent");
        assert_eq!(name_status_str(NameStatus::Present), "present");
        assert_eq!(name_status_str(NameStatus::IgnoredUnsafe), "ignored_unsafe");
    }

    #[test]
    fn rows_keys_in_exact_order() {
        let header = header_for(opts(
            CipherId::Aes256Gcm,
            KdfId::Argon2id,
            cheap_argon2id(),
            Some("note.txt"),
        ));
        let keys: Vec<&str> = header_rows(&header).iter().map(|r| r.key).collect();
        assert_eq!(
            keys,
            [
                "format",
                "version",
                "cipher",
                "kdf",
                "kdf_params",
                "flags",
                "keyfile_hint",
                "chunk_size",
                "salt_len",
                "nonce_prefix_len",
                "name_status",
                "name",
            ]
        );
    }
}
