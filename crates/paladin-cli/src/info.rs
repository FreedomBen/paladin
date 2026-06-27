//! `--info` formatting: `Metadata` → stable `key: value` lines (DESIGN §6.2,
//! plan §7, PLAN_05 §5.8). The order and spelling here are a contract;
//! integration tests assert it byte-for-byte for both the paladin and the AES
//! Crypt block.

use paladin_core::{AesCryptHeader, Header, KdfParams, Metadata, NameStatus};

/// Render the stable, ordered `--info` block for whichever container was
/// recognized (trailing newline included).
pub fn format_info(meta: &Metadata) -> String {
    match meta {
        Metadata::Paladin(header) => format_paladin(header),
        Metadata::AesCrypt(header) => format_aescrypt(header),
    }
}

/// The native paladin 12-line block.
fn format_paladin(header: &Header) -> String {
    let name_status = match header.name_status {
        NameStatus::Absent => "absent",
        NameStatus::Present => "present",
        NameStatus::IgnoredUnsafe => "ignored_unsafe",
    };
    // `name` is shown only when a stored basename is present and usable.
    let name = if matches!(header.name_status, NameStatus::Present) {
        header.name.as_deref().unwrap_or("")
    } else {
        ""
    };

    let lines = [
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
    ];
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The AES Crypt block (PLAN_05 §5.8). `authenticated: false` makes the
/// unauthenticated-header caveat explicit. The cipher is always AES-256-CBC.
fn format_aescrypt(header: &AesCryptHeader) -> String {
    let created_by = header.created_by.as_deref().unwrap_or("");
    let lines = [
        "format: aescrypt".to_string(),
        format!("version: {}", header.version),
        "cipher: aes-256-cbc".to_string(),
        format!("kdf: {}", header.kdf.name()),
        format!("kdf_iterations: {}", header.kdf.iterations()),
        format!("extensions: {}", header.extension_count),
        format!("created_by: {created_by}"),
        "authenticated: false".to_string(),
    ];
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Format the KDF cost parameters as documented in DESIGN §6.2. Shared with the
/// verbose encrypt summary.
pub(crate) fn format_kdf_params(params: &KdfParams) -> String {
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
    use paladin_core::AesCryptKdf;

    #[test]
    fn aescrypt_block_is_byte_exact() {
        let meta = Metadata::AesCrypt(AesCryptHeader {
            version: 2,
            kdf: AesCryptKdf::Sha256 { iterations: 8192 },
            extension_count: 2,
            created_by: Some("aescrypt 3.16.1".to_string()),
        });
        let expected = concat!(
            "format: aescrypt\n",
            "version: 2\n",
            "cipher: aes-256-cbc\n",
            "kdf: aescrypt-sha256\n",
            "kdf_iterations: 8192\n",
            "extensions: 2\n",
            "created_by: aescrypt 3.16.1\n",
            "authenticated: false\n",
        );
        assert_eq!(format_info(&meta), expected);
    }

    #[test]
    fn aescrypt_block_without_created_by_renders_empty() {
        let meta = Metadata::AesCrypt(AesCryptHeader {
            version: 1,
            kdf: AesCryptKdf::Sha256 { iterations: 8192 },
            extension_count: 0,
            created_by: None,
        });
        let expected = concat!(
            "format: aescrypt\n",
            "version: 1\n",
            "cipher: aes-256-cbc\n",
            "kdf: aescrypt-sha256\n",
            "kdf_iterations: 8192\n",
            "extensions: 0\n",
            "created_by: \n",
            "authenticated: false\n",
        );
        assert_eq!(format_info(&meta), expected);
    }
}
