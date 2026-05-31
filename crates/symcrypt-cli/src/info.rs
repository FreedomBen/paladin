//! `--info` formatting: `Header` → stable `key: value` lines (DESIGN §6.2,
//! plan §7). Plan §5 step 9.
#![allow(dead_code)] // wired into run.rs in a later step

use symcrypt_core::Header;

/// Render the stable, ordered `--info` block (trailing newline included).
pub fn format_info(_header: &Header) -> String {
    todo!()
}
