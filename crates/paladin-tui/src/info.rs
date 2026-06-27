//! Render inspected [`Metadata`] as the stable `key: value` lines of DESIGN §6.2
//! and PLAN_05 §5.8, in the same order and display forms as the CLI's `--info`.

use paladin_core as core;

use core::{AesCryptHeader, Header, KdfParams, Metadata, NameStatus};

/// Format metadata into ordered `key: value` lines for the Info results pane,
/// branching on the recognized container format.
pub fn format_info(meta: &Metadata) -> Vec<String> {
    match meta {
        Metadata::Paladin(header) => format_paladin(header),
        Metadata::AesCrypt(header) => format_aescrypt(header),
    }
}

fn format_paladin(header: &Header) -> Vec<String> {
    let name_status = match header.name_status {
        NameStatus::Absent => "absent",
        NameStatus::Present => "present",
        NameStatus::IgnoredUnsafe => "ignored_unsafe",
    };
    let name = if matches!(header.name_status, NameStatus::Present) {
        header.name.as_deref().unwrap_or("")
    } else {
        ""
    };

    vec![
        "format: paladin".to_string(),
        format!("version: {}", header.version),
        format!("cipher: {}", header.cipher),
        format!("kdf: {}", header.kdf()),
        format!("kdf_params: {}", format_kdf_params(&header.kdf_params)),
        format!("flags: 0x{:02x}", header.flags),
        format!("keyfile_hint: {}", header.keyfile_hint()),
        format!("chunk_size: {}", header.chunk_size),
        format!("salt_len: {}", header.salt_len()),
        format!("nonce_prefix_len: {}", header.nonce_prefix_len()),
        format!("name_status: {name_status}"),
        format!("name: {name}"),
    ]
}

/// The AES Crypt block (PLAN_05 §5.8); `authenticated: false` flags the
/// unauthenticated header.
fn format_aescrypt(header: &AesCryptHeader) -> Vec<String> {
    let created_by = header.created_by.as_deref().unwrap_or("");
    vec![
        "format: aescrypt".to_string(),
        format!("version: {}", header.version),
        "cipher: aes-256-cbc".to_string(),
        format!("kdf: {}", header.kdf.name()),
        format!("kdf_iterations: {}", header.kdf.iterations()),
        format!("extensions: {}", header.extension_count),
        format!("created_by: {created_by}"),
        "authenticated: false".to_string(),
    ]
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::ControlFlow;

    /// Encrypt a tiny plaintext with cheap KDF params, then inspect it, so the
    /// test exercises `format_info` against a real header without being slow.
    fn sample_metadata() -> Metadata {
        let secret = core::Secret::new(b"pw", None).unwrap();
        let opts = core::EncryptOptions {
            kdf: core::KdfId::Pbkdf2,
            kdf_params: core::KdfParams::Pbkdf2 { iterations: 10_000 },
            ..core::EncryptOptions::default()
        };
        let mut out = Vec::new();
        let mut cb = |_p: core::Progress| ControlFlow::Continue(());
        core::encrypt(&b"hello"[..], &mut out, &secret, &opts, Some(5), &mut cb).unwrap();
        core::inspect(&out[..]).unwrap()
    }

    #[test]
    fn paladin_fields_are_ordered_and_formatted() {
        let lines = format_info(&sample_metadata());
        assert_eq!(lines.len(), 12);
        assert_eq!(lines[0], "format: paladin");
        assert_eq!(lines[2], "cipher: aes-256-gcm");
        assert_eq!(lines[3], "kdf: pbkdf2");
        assert_eq!(lines[4], "kdf_params: iterations=10000");
        assert!(lines[5].starts_with("flags: 0x"));
        assert_eq!(lines[10], "name_status: absent");
        assert_eq!(lines[11], "name: ");
    }

    #[test]
    fn aescrypt_fields_are_ordered_and_formatted() {
        let meta = Metadata::AesCrypt(AesCryptHeader {
            version: 2,
            kdf: core::AesCryptKdf::Sha256 { iterations: 8192 },
            extension_count: 2,
            created_by: Some("aescrypt 3.16.1".to_string()),
        });
        let lines = format_info(&meta);
        assert_eq!(
            lines,
            vec![
                "format: aescrypt",
                "version: 2",
                "cipher: aes-256-cbc",
                "kdf: aescrypt-sha256",
                "kdf_iterations: 8192",
                "extensions: 2",
                "created_by: aescrypt 3.16.1",
                "authenticated: false",
            ]
        );
    }
}
