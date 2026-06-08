//! Argument model (DESIGN §6.3). A single clap `Parser` struct; cipher/KDF
//! names arrive as raw strings and are parsed by the core's `FromStr` in
//! `options.rs`. Cross-flag semantic rules live in `validate.rs`.

use clap::{ArgGroup, Parser};
use std::ffi::OsString;
use std::path::PathBuf;

/// The four operating modes, derived from the mutually-exclusive mode group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Info,
    Verify,
}

/// `symcrypt` command-line arguments.
#[derive(Parser, Debug)]
#[command(
    name = "symcrypt",
    version,
    about = "Simple, safe symmetric file encryption.",
    long_about = "Simple, safe symmetric file encryption.\n\n\
        Decrypt (-d), verify (--verify), and info (-i) auto-detect both symcrypt \
        containers and foreign AES Crypt (.aes) files. Encryption (-e) always \
        writes symcrypt's own format, never AES Crypt; to migrate a .aes file, \
        decrypt it and re-encrypt with symcrypt. An AES Crypt key file may be \
        supplied via --password-file only when it is valid UTF-8 text (symcrypt \
        keyfiles, -k, do not apply to .aes files)."
)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["encrypt", "decrypt", "info", "verify"])
))]
pub struct Cli {
    /// Encrypt FILE to an output container.
    #[arg(short = 'e', long)]
    pub encrypt: bool,
    /// Decrypt FILE to its plaintext (symcrypt or AES Crypt `.aes`, auto-detected).
    #[arg(short = 'd', long)]
    pub decrypt: bool,
    /// Print unauthenticated header metadata; no password needed (symcrypt or AES Crypt).
    #[arg(short = 'i', long)]
    pub info: bool,
    /// Decrypt-and-discard to verify integrity and password (symcrypt or AES Crypt).
    #[arg(long)]
    pub verify: bool,

    /// Input file; `-` means stdin.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Output path; `-` means stdout. Defaults per DESIGN §6.5.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Password inline (discouraged; see DESIGN §11).
    #[arg(short = 'p', long, value_name = "PW")]
    pub password: Option<OsString>,
    /// Read the password from a file (one trailing newline trimmed). For an AES
    /// Crypt `.aes` file this must be valid UTF-8 text.
    #[arg(long, value_name = "FILE")]
    pub password_file: Option<PathBuf>,
    /// Read the password from an environment variable.
    #[arg(long, value_name = "VAR")]
    pub password_env: Option<OsString>,
    /// Use an empty password; valid only with `-k`.
    #[arg(long)]
    pub no_password: bool,
    /// Keyfile material combined with the password source; `-` rejected. Applies
    /// to symcrypt files only — not to AES Crypt `.aes` files.
    #[arg(short = 'k', long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,

    /// Cipher: `aes-256-gcm` (default) or `chacha20-poly1305`.
    #[arg(short = 'c', long, value_name = "NAME")]
    pub cipher: Option<String>,
    /// KDF: `argon2id` (default), `scrypt`, or `pbkdf2`.
    #[arg(long, value_name = "NAME")]
    pub kdf: Option<String>,
    /// Argon2id memory cost (KiB).
    #[arg(long, value_name = "KiB")]
    pub argon2_memory: Option<u32>,
    /// Argon2id passes.
    #[arg(long, value_name = "N")]
    pub argon2_time: Option<u32>,
    /// Argon2id lanes.
    #[arg(long, value_name = "N")]
    pub argon2_parallelism: Option<u32>,
    /// scrypt log2(N).
    #[arg(long, value_name = "N")]
    pub scrypt_log_n: Option<u32>,
    /// scrypt block-size parameter `r`.
    #[arg(long, value_name = "N")]
    pub scrypt_r: Option<u32>,
    /// scrypt parallelization parameter `p`.
    #[arg(long, value_name = "N")]
    pub scrypt_p: Option<u32>,
    /// PBKDF2-HMAC-SHA256 iteration count.
    #[arg(long, value_name = "N")]
    pub pbkdf2_iterations: Option<u32>,

    /// Write ASCII-armored (base64) output; recommended when stdout is a
    /// terminal. (Decrypt/verify/info auto-detect armor.)
    #[arg(short = 'a', long)]
    pub armor: bool,
    /// Store the input's basename in the header (off by default; sensitive).
    #[arg(long)]
    pub name: bool,
    /// Overwrite an existing output file (default: refuse).
    #[arg(short = 'f', long)]
    pub force: bool,
    /// Best-effort delete the input after success (plain delete, no secure erase).
    #[arg(long)]
    pub remove: bool,

    /// Force the progress bar on (default: auto when stderr is a TTY).
    #[arg(long, conflicts_with = "no_progress")]
    pub progress: bool,
    /// Force the progress bar off.
    #[arg(long)]
    pub no_progress: bool,

    /// More diagnostics on stderr.
    #[arg(short = 'v', long)]
    pub verbose: bool,
    /// Suppress progress and status output (not primary stdout or errors).
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

impl Cli {
    /// The selected mode. The clap group guarantees exactly one is set.
    pub fn mode(&self) -> Mode {
        if self.encrypt {
            Mode::Encrypt
        } else if self.decrypt {
            Mode::Decrypt
        } else if self.info {
            Mode::Info
        } else {
            Mode::Verify
        }
    }

    /// Tri-state progress preference: `Some(true|false)` when forced by
    /// `--progress`/`--no-progress`, else `None` for auto (stderr-TTY) detection.
    pub fn progress_pref(&self) -> Option<bool> {
        if self.progress {
            Some(true)
        } else if self.no_progress {
            Some(false)
        } else {
            None
        }
    }
}
