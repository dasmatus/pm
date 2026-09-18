//! `pmd --worker --fd N`: one process, one job, the whole build in one stack
//! frame.
//!
//! This is deliberately not `zbus` code, and imports nothing from it beyond
//! what [`crate::wire::types`] already derives. `pmd` and the supervisor
//! that will fork this worker do not exist yet - see
//! `docs/superpowers/specs/2026-09-18-dbus-daemon-design.md` sections 3
//! (process model) and 6 (job model) for the design this module implements
//! the worker half of, and section 7 for the invariants it has to hold on
//! its own, with nobody watching, until that supervisor lands.
//!
//! # Coalescing is the reason this module exists
//!
//! A daemon has no terminal and no client watching every progress update,
//! so [`crate::progress::Task::set_message`] and
//! [`crate::progress::Task::set_bytes`] cannot each become a frame: the
//! former fires once per line of a build command's output, thousands of
//! times a second for a real compile, and the latter once per 64 KiB of a
//! download. [`run`] instead holds a [`Progress::silent`] tree and polls it
//! on a fixed [`TICK`], via [`spawn_ticker`], sending a
//! [`WorkerEvent::Progress`] snapshot only when the tree actually changed.
//! A snapshot is idempotent - it is the WHOLE current tree, not a diff - so
//! a tick that finds nothing new, or a frame that never arrives at all,
//! costs the client nothing.
//!
//! # One thread runs the job, on purpose
//!
//! Design section 7's invariant 2 - the thread that spawns a hakoniwa
//! container must be the thread that waits for it, and must not exit
//! first, because `PR_SET_PDEATHSIG` binds to the creating THREAD, not the
//! process - is why [`run`] calls [`run_build`] directly on its own
//! calling thread rather than on a spawned one. `pmd.rs`'s `main` arms
//! `PR_SET_PDEATHSIG` before anything else runs, on what becomes this same
//! thread, so running the job here - and nowhere else - is what makes the
//! invariant hold by construction. The ticker and event-writer threads this
//! module DOES spawn never spawn or wait on a child process of their own,
//! so neither carries any part of that invariant.
//!
//! # Caller context, and why mutating this process is fine here
//!
//! [`apply_caller_context`] changes this process's current directory and
//! environment to match the job's [`CallerContext`]. Task 1's
//! `BuildContext`, which would let the library accept these explicitly
//! instead, is landing in a parallel branch not yet merged into this one -
//! see that function's own docs for exactly what that leaves unwired.
//! Mutating process-global state to answer for a single caller is only
//! sound because this worker is a fresh, single-purpose process that
//! exists to run exactly one job as exactly that caller: `pmd` itself must
//! never do this, because it serves every client from one process.

use std::{
    env::{current_dir, set_current_dir},
    fs::read_dir,
    num::NonZeroUsize,
    os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use miette::{IntoDiagnostic, WrapErr};
use serde::{Deserialize, Serialize};
use tracing::{Level, warn};
use tracing_subscriber::fmt;

use crate::{
    bf::{BuildFile, BuildOptions},
    graph::Graph,
    progress::{Progress, sanitise},
    wire::{
        frame::{read_frame, write_frame},
        types::{CallerContext, Diagnostic, LogLine, PackageOutcome, ProgressNode},
    },
};

/// How often [`spawn_ticker`] polls [`Progress::nodes`].
///
/// Matches the rate `progress.rs`'s own terminal ticker redraws at
/// (`progress.rs:58`'s `TICK`, private to that module so this is a second
/// constant rather than a shared one). At most `1000 / 80 = 12.5` snapshots
/// a second follow from this alone, comfortably under the task's 13-per-
/// second gate before the change-detection in [`spawn_ticker`] even applies.
const TICK: Duration = Duration::from_millis(80);

/// Cap applied to a [`PackageOutcome::name`] this worker constructs.
///
/// A package name comes from a build file's own `name:` field, which is
/// attacker-controlled the moment `--permissive` or an unverified load is
/// in play - the same reasoning `crate::wire::error`'s caps document for
/// `Diagnostic`.
const NAME_CAP: usize = 256;
/// Cap applied to a [`PackageOutcome::archive`] path this worker constructs.
const ARCHIVE_CAP: usize = 4096;
/// Cap applied to a [`PackageOutcome::error`] this worker constructs.
///
/// [`Diagnostic`] itself already sanitises and caps its own fields; this
/// only bounds the copy of `Diagnostic::message` this module borrows for a
/// per-package error string when a whole-graph build fails.
const ERROR_CAP: usize = 8192;

/// What kind of job a [`WorkerRequest`] asks the worker to run.
///
/// Only `Build` exists today. A `run` or `audit` job needs
/// `PackageRunner::run_with`'s `RunHooks` split for `needs-input` (design
/// section 6), which has no reason to exist before `Job.Choose` does, so it
/// is out of scope for this task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobKind {
    /// Build and package the build file at [`WorkerRequest::target`].
    Build,
}

/// Everything the worker needs to run one job, read as the first frame off
/// its inherited socket.
///
/// Deliberately not one of [`crate::wire::types`]: those derive
/// `zbus::zvariant::Type` and are pinned by `tests/wire.rs` against a
/// D-Bus signature this struct has no reason to carry, because it never
/// crosses D-Bus. It only ever crosses the worker's own socketpair, framed
/// by [`crate::wire::frame`] and serialised as JSON via `serde_json`,
/// matching design section 6's "the worker to daemon protocol" verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    /// What kind of job this is.
    pub kind: JobKind,
    /// Absolute path to the build file to build.
    ///
    /// The daemon's future client canonicalises this against its OWN `cwd`
    /// before a request is ever built (design section 3), so the worker
    /// never resolves a relative path itself.
    pub target: String,
    /// The paths and identity this job's caller supplied.
    pub context: CallerContext,
    /// Allow step commands that match no built-in fingerprint.
    pub permissive: bool,
    /// Run build steps on the host instead of inside the jail.
    pub unsandboxed: bool,
    /// How many packages may build at once. `None` means the core count.
    pub jobs: Option<NonZeroUsize>,
    /// The maximum `tracing::Level` the worker's own log output should
    /// emit, as its name: `"error"`, `"warn"`, `"info"`, `"debug"` or
    /// `"trace"`.
    ///
    /// A single level rather than a full `tracing_subscriber::EnvFilter`
    /// directive string - this crate does not enable that crate's
    /// `env-filter` feature - but supplied here regardless of that, rather
    /// than read from `$RUST_LOG`: see this module's top-level docs and
    /// [`install_tracing`].
    pub log_filter: String,
}

/// One frame the worker sends back over its socket.
///
/// In the order design section 6 describes: any number of
/// [`WorkerEvent::Progress`] snapshots interleaved with the build, then one
/// [`WorkerEvent::PackageOutcome`] per package in the graph, then exactly
/// one terminal [`WorkerEvent::Completed`] and nothing after it.
///
/// `Completed` carries its two outcomes as flat, mutually-exclusive
/// `Option` fields rather than a nested `enum`. That shape is deliberate,
/// not a codec workaround: design section 6 itself writes this frame as
/// `Completed { status, result }`, a flat struct, not a tagged union, so
/// `archive`/`diagnostic` here matches the spec's own wire shape rather
/// than introducing a Rust-only abstraction the protocol never asked for.
/// It also leaves room to add a third, independent outcome later - a
/// timeout or a cancellation marker, say - as one more `Option` field,
/// without having to decide where it fits inside an existing enum.
/// [`Outcome`] stays a normal Rust enum purely for ergonomic matching
/// inside this module; [`Outcome::into_event`] is the one place it gets
/// flattened before it ever reaches [`write_frame`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkerEvent {
    /// A snapshot of the whole progress tree, coalesced onto [`TICK`]
    /// rather than sent once per update. See this module's top-level docs.
    Progress(Vec<ProgressNode>),
    /// One line of output or a `tracing` record.
    ///
    /// Defined because the task brief asks for it, but never actually sent
    /// by this worker: design section 6's own protocol list has exactly
    /// four outbound frame kinds - a progress snapshot, `PackageSettled`,
    /// `NeedsInput` and `Completed` - and no log frame at all, because
    /// ordinary output travels over the worker's real stdout and stderr
    /// pipes (section 3), which a future supervisor drains directly into
    /// the job's log. Where the brief and the spec disagree, the spec
    /// wins; this variant stays on the wire only so a later task that DOES
    /// want line-by-line log frames does not need a wire change to add it.
    Log(LogLine),
    /// One package's result, once its build has settled. The spec calls
    /// this frame `PackageSettled`; the variant is named for the payload
    /// type the brief specifies instead, since nothing pins the enum's own
    /// name.
    PackageOutcome(PackageOutcome),
    /// The job's terminal result. Nothing follows this frame. Exactly one
    /// of `archive` and `diagnostic` is ever populated - see this type's
    /// own docs for why that is two `Option` fields and not one `enum`.
    Completed {
        /// Path to the produced archive, on success.
        archive: Option<String>,
        /// Why the job failed, on failure.
        ///
        /// Never how a panic is reported: a panic unwinds out of the
        /// worker's `main` instead, and the PROCESS exits without ever
        /// sending a `Completed` frame at all - which is exactly what lets
        /// a future supervisor tell "failed" and "crashed" apart (design
        /// section 6, "panic isolation"; section 7, invariant 7).
        diagnostic: Option<Diagnostic>,
    },
}

/// [`run_build`]'s own return type for the job's terminal result.
///
/// A plain Rust enum, not part of the wire format - see [`WorkerEvent`]'s
/// docs for why `Completed` is a flat struct rather than one of these
/// nested directly, and [`Outcome::into_event`] for the one place this
/// gets flattened before it crosses the socket. Kept as an enum here
/// purely because `Succeeded`/`Failed` are mutually exclusive and matching
/// on them inside this module reads better than juggling two `Option`s by
/// hand.
enum Outcome {
    /// The build succeeded, leaving an archive at this path.
    Succeeded(PathBuf),
    /// The build failed for a reason `diagnostic` describes.
    Failed(Diagnostic),
}

impl Outcome {
    /// Flattens this into the [`WorkerEvent::Completed`] frame that reports
    /// it, sanitising the archive path the same way every other
    /// build-controlled string on this wire is sanitised.
    fn into_event(self) -> WorkerEvent {
        match self {
            Self::Succeeded(archive) => WorkerEvent::Completed {
                archive: Some(sanitise(&archive.display().to_string(), ARCHIVE_CAP)),
                diagnostic: None,
            },
            Self::Failed(diagnostic) => WorkerEvent::Completed {
                archive: None,
                diagnostic: Some(diagnostic),
            },
        }
    }
}

/// Run the one job described by the first frame read from `fd`, then return.
///
/// Reads a [`WorkerRequest`], applies its [`CallerContext`], builds it, and
/// streams [`WorkerEvent`] frames back over the same socket: progress
/// snapshots from a dedicated ticker thread while the build runs on this
/// one, then a [`WorkerEvent::PackageOutcome`] per package, then the
/// terminal [`WorkerEvent::Completed`].
///
/// # Errors
///
/// Returns an error only for a failure in the worker's OWN plumbing: the
/// request frame could not be read or parsed, or [`CallerContext`] could
/// not be applied. A failure of the BUILD ITSELF is not an error here - it
/// is reported as a `Completed { diagnostic: Some(..), .. }` frame and this
/// function still returns `Ok(())`, because the job was handled correctly
/// even though it did not succeed. `pmd.rs`'s `main` turns an `Err` here
/// into a non-zero exit with no `Completed` frame ever sent, which is
/// exactly the "crashed" signal a future supervisor needs.
pub fn run(fd: RawFd) -> miette::Result<()> {
    // SAFETY: `fd` is a socketpair endpoint our own direct parent dup2'd
    // into place for exactly this purpose before exec (today, this task's
    // own test harness; later, the supervisor's `pre_exec`), and handed to
    // us alone. We are its only owner from this point on.
    let control = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut control = UnixStream::from(control);

    let request_bytes =
        read_frame(&mut control).wrap_err("failed to read the worker's job request")?;
    let request: WorkerRequest = serde_json::from_slice(&request_bytes)
        .into_diagnostic()
        .wrap_err("the worker's job request frame was not valid JSON")?;

    install_tracing(&request.log_filter);
    apply_caller_context(&request.context)?;

    let sink = control
        .try_clone()
        .into_diagnostic()
        .wrap_err("cannot clone the worker's control socket for writing")?;
    let (tx, rx) = mpsc::channel();
    let writer = thread::spawn(move || drain_events(sink, rx));

    let progress = Progress::silent();
    let stop_ticker = Arc::new(AtomicBool::new(false));
    let ticker = spawn_ticker(progress.clone(), tx.clone(), Arc::clone(&stop_ticker));

    // The whole job runs HERE, on this thread, synchronously - see this
    // module's top-level docs on why that is what makes invariant 2 hold.
    let (outcomes, outcome) = match request.kind {
        JobKind::Build => run_build(&request, &progress),
    };

    // Stop and join the ticker BEFORE queuing the terminal frame: joining a
    // thread happens-after everything it did, including its last channel
    // send, so this is what guarantees no `Progress` frame is ever queued
    // after `Completed`.
    stop_ticker.store(true, Ordering::Relaxed);
    if ticker.join().is_err() {
        warn!("the progress ticker thread panicked; continuing without it");
    }

    for outcome in outcomes {
        // A dropped receiver means nobody is listening any more, which is
        // not this function's failure to report: the job still ran to
        // completion. See the module docs on a dropped snapshot costing
        // nothing; the same reasoning applies to every event here.
        let _ = tx.send(WorkerEvent::PackageOutcome(outcome));
    }
    let _ = tx.send(outcome.into_event());
    drop(tx);

    match writer.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(report)) => {
            warn!(error = ?report, "failed to write every worker event");
            Ok(())
        }
        Err(_) => {
            warn!("the worker event writer thread panicked");
            Ok(())
        }
    }
}

/// Makes this worker process behave as if it were its caller, for the one
/// job it is about to run.
///
/// Legitimate only here: the worker is a fresh, single-purpose process
/// whose entire reason to exist is to BE the caller's context for this one
/// job. `pmd` itself must never do this - see this module's top-level docs.
///
/// # Errors
///
/// Returns a diagnostic if `ctx.cwd` cannot be made the current directory.
///
/// # A gap this task leaves open
///
/// [`CallerContext::trust_dir`] and [`CallerContext::output_dir`] are NOT
/// applied here, because nothing in this task's library entry points -
/// [`BuildFile::load`], [`Graph::resolve`], [`Graph::build`] - takes either
/// as a parameter. `BuildFile::load` resolves its trust store from
/// `$XDG_CONFIG_HOME`/`$HOME` internally
/// (`crate::signing::default_trust_dir`), and every package's archive lands
/// in [`current_dir`] (`bf.rs`'s `build_alone`, unconditionally, for the
/// root package and every dependency alike) - which, after this function
/// runs, is `ctx.cwd`, not `ctx.output_dir`. Task 1's `BuildContext` is
/// what gives the library a seam to accept either explicitly instead of
/// leaning on process-global state; until it merges, `HOME` is the only
/// lever this worker has over where the trust store is read from, and
/// `cwd` is the only lever it has over where an archive is written.
fn apply_caller_context(ctx: &CallerContext) -> miette::Result<()> {
    set_current_dir(&ctx.cwd)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot chdir to the caller's working directory {}", ctx.cwd))?;

    // SAFETY: no other thread exists yet - `run` calls this before spawning
    // the ticker or writer threads - so mutating the process environment
    // here races with nothing that could observe it half-written.
    unsafe {
        std::env::set_var("PATH", &ctx.path);
        std::env::set_var("HOME", &ctx.home);
    }

    Ok(())
}

/// Installs a `tracing` subscriber that writes to this worker's own
/// stderr - a pipe a future supervisor drains into the job's log, per
/// design section 3 - filtered by `filter` rather than `$RUST_LOG`.
///
/// A D-Bus-activated daemon inherits systemd's activation environment, not
/// the interactive caller's shell, so reading `$RUST_LOG` here would report
/// whichever log level happened to be set for the DAEMON's own startup as
/// if the caller had asked for it. `filter` is the caller's real choice,
/// carried explicitly in [`WorkerRequest::log_filter`] instead. An
/// unparseable filter falls back to `"info"` rather than failing the job
/// over a cosmetic setting.
fn install_tracing(filter: &str) {
    let level = filter.parse::<Level>().unwrap_or(Level::INFO);
    fmt().without_time().with_max_level(level).init();
}

/// Polls `progress` on [`TICK`] and sends one [`WorkerEvent::Progress`]
/// frame per tick that actually changed - never once per
/// `set_message`/`set_bytes` call. See this module's top-level docs for why
/// this is the whole point of the module, and why this thread carries none
/// of design section 7's thread-affinity invariant for hakoniwa containers.
fn spawn_ticker(
    progress: Progress,
    tx: Sender<WorkerEvent>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut last: Option<Vec<ProgressNode>> = None;
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(TICK);
            let nodes = progress.nodes();
            if last.as_ref() != Some(&nodes) {
                if tx.send(WorkerEvent::Progress(nodes.clone())).is_err() {
                    // Nobody is listening any more; nothing left to do.
                    return;
                }
                last = Some(nodes);
            }
        }
    })
}

/// Owns the control socket for writing and serialises every event from
/// `events` onto it in receive order, so the ticker thread and the job
/// thread can both hand it events without their frames interleaving
/// mid-write - [`crate::wire::frame`] frames are not otherwise safe to
/// write from two threads at once.
///
/// Returns once every [`Sender`] for `events` has been dropped, which
/// [`run`] arranges to happen only after the terminal
/// [`WorkerEvent::Completed`] frame has already been queued.
///
/// # Errors
///
/// Returns a diagnostic if an event cannot be serialised, or if writing a
/// frame to the socket fails.
fn drain_events(mut sink: UnixStream, events: mpsc::Receiver<WorkerEvent>) -> miette::Result<()> {
    for event in events {
        let payload = serde_json::to_vec(&event)
            .into_diagnostic()
            .wrap_err("cannot serialise a worker event")?;
        write_frame(&mut sink, &payload).wrap_err("cannot write a worker event frame")?;
    }
    Ok(())
}

/// Loads, resolves and builds `request.target`, turning the result into the
/// events [`run`] sends back.
///
/// Calls the library's existing public entry points -
/// [`BuildFile::load`] and [`Graph::resolve`] / [`Graph::build`] - rather
/// than the higher-level [`BuildFile::run_with_progress`], specifically so
/// this function can read [`Graph::order`] for the package list before
/// building: `Graph`'s own per-package Built/Failed/Skipped bookkeeping
/// (`Progression`, in `graph.rs`) is private, so `order` plus `build`'s
/// return value are the only public seam this task can build
/// [`PackageOutcome`] from at all. See [`package_outcome`] for exactly what
/// that costs.
fn run_build(request: &WorkerRequest, progress: &Progress) -> (Vec<PackageOutcome>, Outcome) {
    let target = Path::new(&request.target);
    let build_file = match BuildFile::load(target) {
        Ok(build_file) => build_file,
        Err(report) => return (Vec::new(), Outcome::Failed(Diagnostic::from(&report))),
    };

    let options = BuildOptions {
        permissive: request.permissive,
        unsandboxed: request.unsandboxed,
        jobs: request.jobs,
    };

    let graph = match Graph::resolve(&build_file, options) {
        Ok(graph) => graph,
        Err(report) => return (Vec::new(), Outcome::Failed(Diagnostic::from(&report))),
    };
    let names: Vec<String> = graph.order().map(str::to_owned).collect();
    let root_name = build_file.name().to_owned();

    // Read once, before the build runs, rather than once per package below:
    // `bf.rs::build_alone` calls `current_dir()` itself for every package's
    // archive destination, and nothing between here and there changes it.
    let cwd = current_dir().ok();

    match graph.build(options, progress) {
        Ok(archive) => {
            let outcomes = names
                .iter()
                .map(|name| package_outcome(name, &root_name, Some(&archive), cwd.as_deref(), None))
                .collect();
            (outcomes, Outcome::Succeeded(archive))
        }
        Err(report) => {
            let diagnostic = Diagnostic::from(&report);
            let outcomes = names
                .iter()
                .map(|name| {
                    package_outcome(
                        name,
                        &root_name,
                        None,
                        cwd.as_deref(),
                        Some(&diagnostic.message),
                    )
                })
                .collect();
            (outcomes, Outcome::Failed(diagnostic))
        }
    }
}

/// Builds one package's [`PackageOutcome`].
///
/// `Graph`'s public API (see [`run_build`]'s docs) exposes no per-package
/// result - only names, via [`Graph::order`], and the ROOT's own archive
/// path, returned by [`Graph::build`] on success. For `name == root`, this
/// is therefore exact. For any other name it is a best-effort
/// reconstruction: every package's archive is named `<name>-<version>.cpkg`
/// and lands beside the root's, in the same [`current_dir`]
/// (`bf.rs::build_alone`), so [`find_archive`] looks for one. A
/// whole-graph failure with no such file present is reported as `"failed"`
/// even for a package that was merely skipped, because `Graph` gives this
/// function no way to tell the two apart. Exposing `Progression` (or an
/// equivalent) from `graph.rs` would let a future task report this
/// exactly instead.
fn package_outcome(
    name: &str,
    root: &str,
    root_archive: Option<&Path>,
    cwd: Option<&Path>,
    error: Option<&str>,
) -> PackageOutcome {
    let found = if name == root {
        root_archive.map(Path::to_path_buf)
    } else {
        cwd.and_then(|dir| find_archive(dir, name))
    };

    match found {
        Some(archive) => PackageOutcome {
            name: sanitise(name, NAME_CAP),
            outcome: "built".to_owned(),
            archive: sanitise(&archive.display().to_string(), ARCHIVE_CAP),
            error: String::new(),
        },
        None => PackageOutcome {
            name: sanitise(name, NAME_CAP),
            outcome: "failed".to_owned(),
            archive: String::new(),
            error: sanitise(error.unwrap_or_default(), ERROR_CAP),
        },
    }
}

/// Best-effort lookup of the `.cpkg` a package named `name` would have
/// produced in `dir`, by the naming convention `bf.rs::archive_name` uses:
/// `<name>-<version>.cpkg`. See [`package_outcome`] for why this reads the
/// directory itself instead of asking `Graph`.
fn find_archive(dir: &Path, name: &str) -> Option<PathBuf> {
    let prefix = format!("{name}-");
    read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|file_name| file_name.to_str())
                .is_some_and(|file_name| file_name.starts_with(&prefix) && file_name.ends_with(".cpkg"))
        })
}
