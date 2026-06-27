//! `paladin` command-line front-end (DESIGN §6). A thin wrapper: parse
//! arguments, validate, resolve the password, open streams, call
//! `paladin-core`, and map results to exit codes. No crypto or format logic.

mod cli;
mod info;
mod options;
mod progress;
mod run;
mod secret;
mod validate;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    let cancel = progress::cancel_flag();
    progress::install_sigint(&cancel);
    if let Err(e) = run::dispatch(&cli, cancel) {
        eprintln!("paladin: {e}");
        std::process::exit(e.exit_code());
    }
}
