//! Progress bar + SIGINT cancellation (DESIGN §6.5–§6.6).
//!
//! Crypto runs on the main thread here; the progress bar renders on stderr and
//! a SIGINT handler flips a shared cancel flag. The core observes the flag
//! through the `on_progress` callback (returning `ControlFlow::Break`), returns
//! `SymError::Canceled`, and the unfinalized temp output is dropped.

use crate::cli::Cli;
use indicatif::{ProgressBar, ProgressStyle};
use paladin_core::Progress;
use std::io::IsTerminal;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Decide whether to render a progress bar: `--progress`/`--no-progress`
/// override; otherwise on when stderr is a TTY; always off under `--quiet`.
pub fn want_progress(cli: &Cli) -> bool {
    if cli.quiet {
        return false;
    }
    match cli.progress_pref() {
        Some(forced) => forced,
        None => std::io::stderr().is_terminal(),
    }
}

/// A fresh, unset cancellation flag.
pub fn cancel_flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// Install a process-wide SIGINT handler that sets `flag`. Best-effort: failure
/// to install is ignored, since the handler is a convenience and the core stays
/// correct without it.
pub fn install_sigint(flag: &Arc<AtomicBool>) {
    let flag = Arc::clone(flag);
    let _ = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst));
}

/// Build the progress bar to render, or `None` when progress is disabled. A
/// known total renders a byte bar; an unknown total renders a spinner.
pub fn make_bar(show: bool, total: Option<u64>) -> Option<ProgressBar> {
    if !show {
        return None;
    }
    let bar = match total {
        Some(len) => {
            let bar = ProgressBar::new(len);
            bar.set_style(
                ProgressStyle::with_template("{bar:40} {bytes}/{total_bytes} ({eta})")
                    .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
            bar
        }
        None => ProgressBar::new_spinner(),
    };
    Some(bar)
}

/// Build the `on_progress` callback the core drives: advance `bar`, and return
/// `ControlFlow::Break` once `cancel` is set so the core stops cooperatively.
pub fn callback(
    bar: Option<ProgressBar>,
    cancel: Arc<AtomicBool>,
) -> impl FnMut(Progress) -> ControlFlow<()> {
    move |p: Progress| {
        if let Some(bar) = &bar {
            if let Some(total) = p.total {
                bar.set_length(total);
            }
            bar.set_position(p.done);
        }
        if cancel.load(Ordering::SeqCst) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        let mut argv = vec!["paladin"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).unwrap()
    }

    #[test]
    fn quiet_disables_progress() {
        assert!(!want_progress(&cli(&["-e", "-q", "file"])));
    }

    #[test]
    fn no_progress_flag_disables_progress() {
        assert!(!want_progress(&cli(&["-e", "--no-progress", "file"])));
    }

    #[test]
    fn progress_flag_forces_progress_on() {
        assert!(want_progress(&cli(&["-e", "--progress", "file"])));
    }

    #[test]
    fn make_bar_off_is_none() {
        assert!(make_bar(false, Some(10)).is_none());
        assert!(make_bar(false, None).is_none());
    }

    #[test]
    fn make_bar_on_is_some() {
        assert!(make_bar(true, Some(10)).is_some());
        assert!(make_bar(true, None).is_some());
    }

    #[test]
    fn callback_breaks_only_after_cancel() {
        let cancel = cancel_flag();
        let mut cb = callback(None, Arc::clone(&cancel));
        assert_eq!(
            cb(Progress {
                done: 1,
                total: Some(10)
            }),
            ControlFlow::Continue(())
        );
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(
            cb(Progress {
                done: 2,
                total: Some(10)
            }),
            ControlFlow::Break(())
        );
    }
}
