//! `pmd`, the daemon binary.
//!
//! Today this is the worker half only: `pmd --worker --fd N` re-execs into
//! itself the way the real supervisor will, reads one job off the inherited
//! socket, runs it, and exits. See [`pm::daemon::worker`] for the protocol
//! and everything the worker actually does; there is no `zbus` code
//! anywhere in this task, and this binary does not yet own `org.pm1` or
//! bind a session bus name at all - that lands in a later task, once the
//! worker this one calls into is trustworthy on its own.

use std::{os::fd::RawFd, process::ExitCode};

use clap::Parser;
use nix::{sys::prctl, sys::signal::Signal, unistd::getppid};
use pm::daemon::worker;

/// `pmd`'s command line.
///
/// `--worker` and `--fd` travel together rather than as a subcommand,
/// matching the exact invocation
/// `docs/superpowers/specs/2026-09-18-dbus-daemon-design.md` names in
/// sections 3 and 6 (`pmd --worker --fd 3`): a future supervisor re-execs
/// `/proc/self/exe` with this literal argument shape, so there is no
/// version skew to reconcile between what it writes and what this parses.
#[derive(Parser)]
#[command(name = "pmd", version, about = "The pm daemon")]
struct Args {
    /// Run as a one-shot job worker, speaking the frame protocol on `--fd`.
    #[arg(long, requires = "fd")]
    worker: bool,
    /// The inherited socketpair file descriptor to speak the frame protocol
    /// on. Meaningless without `--worker`.
    #[arg(long)]
    fd: Option<RawFd>,
}

fn main() -> ExitCode {
    // Before ANYTHING else - even argument parsing - see this module's docs
    // and design section 7, invariant 2: the window this closes is between
    // our parent's `fork` and this call, and every instruction that runs
    // first widens it.
    if let Err(code) = die_with_parent_or_exit() {
        return code;
    }

    let args = Args::parse();
    match (args.worker, args.fd) {
        (true, Some(fd)) => match worker::run(fd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(report) => {
                eprintln!("{report:?}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!(
                "pmd currently only runs as `pmd --worker --fd <N>`; the daemon service \
                 itself is a later task"
            );
            ExitCode::FAILURE
        }
    }
}

/// Arms `PR_SET_PDEATHSIG(SIGKILL)` and closes the race where our parent
/// died between its `fork()` and this call.
///
/// `PR_SET_PDEATHSIG` binds to the calling THREAD, so this has to run on
/// whatever thread ends up spawning and waiting on a hakoniwa container -
/// which, per [`pm::daemon::worker`]'s docs, is this process's main thread,
/// making `main`'s very first lines the only place this can correctly live.
///
/// Reads `getppid()` before and after arming the signal: if our parent
/// exited in that window, we have already been reparented (to init, or
/// whatever subreaper this pid namespace has) by the time the second read
/// runs, so the signal is now armed against a process that has no reason
/// to die. The daemon that was supposed to own this job is already gone,
/// so there is nothing left to build and, since we have not read a job
/// request yet, no `Completed` frame anyone is waiting on either - exiting
/// here is silent by construction, not silently wrong.
///
/// Returns `Ok(())` when it is safe to continue, or the [`ExitCode`]
/// `main` should return immediately, either because the parent already
/// died or because the syscalls themselves failed.
fn die_with_parent_or_exit() -> Result<(), ExitCode> {
    let before = getppid();
    if let Err(errno) = prctl::set_pdeathsig(Signal::SIGKILL) {
        eprintln!("pmd: cannot set PR_SET_PDEATHSIG: {errno}");
        return Err(ExitCode::FAILURE);
    }
    let after = getppid();
    if before != after {
        eprintln!(
            "pmd: parent process exited before PDEATHSIG could be armed against it; exiting"
        );
        return Err(ExitCode::FAILURE);
    }
    Ok(())
}
