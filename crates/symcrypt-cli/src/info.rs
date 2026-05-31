//! `--info` formatting: `Header` → stable `key: value` lines (DESIGN §6.2,
//! plan §7). The order and spelling here are a contract; integration tests
//! assert it byte-for-byte.

use symcrypt_core::{Header, KdfParams, NameStatus};

/// Render the stable, ordered `--info` block (trailing newline included).
pub fn format_info(header: &Header) -> String {
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
