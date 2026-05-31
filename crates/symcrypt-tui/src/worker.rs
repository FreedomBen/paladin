//! Off-thread execution. A worker thread runs one core operation, streams
//! `Progress` over an mpsc channel, and observes an `AtomicBool` cancel flag.
//! The event loop drains the channel each tick and joins on completion.

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use symcrypt_common as common;
use symcrypt_core as core;

use common::{AppError, OutputSink};
use core::{EncryptOptions, Progress, Secret};

/// Which operation the worker runs (and the options it needs).
pub enum Op {
    Encrypt(EncryptOptions),
    Decrypt,
    Verify,
}

/// Everything the worker owns, moved across the thread boundary.
pub struct Job {
    pub op: Op,
    pub input: PathBuf,
    /// Output sink for Encrypt/Decrypt; `None` for Verify (writes nothing).
    pub sink: Option<OutputSink>,
    pub secret: Secret,
    pub input_len: Option<u64>,
    pub remove_input: bool,
}

/// Messages from the worker to the UI.
pub enum Msg {
    Progress { done: u64, total: Option<u64> },
    Finished(Result<(), AppError>),
}

/// A running operation: drain [`Msg`]s each tick, request cancel, join on finish.
pub struct Run {
    rx: Receiver<Msg>,
    cancel: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Run {
    /// Spawn the worker thread for `job`.
    pub fn spawn(job: Job) -> Run {
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_worker = Arc::clone(&cancel);
        let handle = thread::spawn(move || {
            let result = execute(job, &cancel_worker, &tx);
            let _ = tx.send(Msg::Finished(result));
        });
        Run {
            rx,
            cancel,
            handle: Some(handle),
        }
    }

    /// Collect any pending messages without blocking.
    pub fn drain(&self) -> Vec<Msg> {
        self.rx.try_iter().collect()
    }

    /// Signal the worker to stop at the next checkpoint.
    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// Wait for the worker thread to finish.
    pub fn join(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The worker body: open the input, run the operation, finalize or roll back.
fn execute(job: Job, cancel: &AtomicBool, tx: &Sender<Msg>) -> Result<(), AppError> {
    let Job {
        op,
        input,
        sink,
        secret,
        input_len,
        remove_input,
    } = job;

    let mut reader = common::open_input(&input)?;
    let mut on_progress = |p: Progress| {
        let _ = tx.send(Msg::Progress {
            done: p.done,
            total: p.total,
        });
        if cancel.load(Ordering::SeqCst) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };

    match op {
        Op::Encrypt(opts) => {
            let Some(mut sink) = sink else {
                return Err(AppError::usage("internal error: missing output sink"));
            };
            core::encrypt(
                &mut reader,
                sink.as_write(),
                &secret,
                &opts,
                input_len,
                &mut on_progress,
            )?;
            sink.commit()?;
        }
        Op::Decrypt => {
            let Some(mut sink) = sink else {
                return Err(AppError::usage("internal error: missing output sink"));
            };
            core::decrypt(
                &mut reader,
                sink.as_write(),
                &secret,
                input_len,
                &mut on_progress,
            )?;
            sink.commit()?;
        }
        Op::Verify => {
            core::verify(&mut reader, &secret, input_len, &mut on_progress)?;
        }
    }

    // On error or cancel the sink is dropped above, removing the temp output.
    if remove_input {
        let _ = common::best_effort_remove(&input);
    }
    Ok(())
}
