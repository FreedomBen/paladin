//! Render an inspected [`Header`] as the stable `key: value` lines of DESIGN
//! §6.2, in the same order and display forms as the CLI's `--info`.

use symcrypt_core as core;

use core::{Header, KdfParams, NameStatus};

/// Format a header into ordered `key: value` lines for the Info results pane.
pub fn format_info(header: &Header) -> Vec<String> {
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
        "format: symcrypt".to_string(),
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
    fn sample_header() -> Header {
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
    fn fields_are_ordered_and_formatted() {
        let lines = format_info(&sample_header());
        assert_eq!(lines.len(), 12);
        assert_eq!(lines[0], "format: symcrypt");
        assert_eq!(lines[2], "cipher: aes-256-gcm");
        assert_eq!(lines[3], "kdf: pbkdf2");
        assert_eq!(lines[4], "kdf_params: iterations=10000");
        assert!(lines[5].starts_with("flags: 0x"));
        assert_eq!(lines[10], "name_status: absent");
        assert_eq!(lines[11], "name: ");
    }
}
