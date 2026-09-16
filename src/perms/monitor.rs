//! Permissions derived by watching one real execution with `ptrace`.
//!
//! [`trace`] forks, puts the child under `ptrace`, `execve`s the program and then steps
//! it with `PTRACE_SYSCALL`, decoding every syscall that names a path, starts a process
//! or reaches for a socket. What comes back is a [`TraceReport`]: the raw
//! [`Observation`]s in the order they happened, and a [`Permissions`] set folded out of
//! them with [`Provenance::RuntimeMonitor`] and one evidence line per syscall.
//!
//! Everything here is done in-process through `nix`. `strace` is not involved and is not
//! required to be installed.
//!
//! # This sees ONE execution, and only that one
//!
//! A monitor records the paths a single run happened to take. It cannot see the branch
//! that was not taken, the error handler that did not fire, the locale file that a
//! different `LANG` would have opened, or the plugin that only loads on a machine with
//! the hardware for it. **A package that works perfectly while traced will still hit an
//! unobserved path in production.** Widening a profile after the fact is a support
//! ticket; that is precisely why a derived profile is [`Enforcement::Audit`] and is never
//! promoted without a human reading [`Permissions::report`].
//!
//! Two further honesty notes about what a grant here does and does not mean:
//!
//! - A syscall that *failed* produces an [`Observation`] with
//!   [`Observation::succeeded`] false and contributes **no** grant. Dynamic linkers probe
//!   dozens of paths that do not exist; granting those would describe the loader's search
//!   order rather than the package's needs.
//! - A *metadata probe* - `stat`, `lstat`, `newfstatat`, `statx`, `access`, `faccessat`,
//!   `readlink`, `readlinkat` - on a **directory** is observed but grants nothing, so
//!   [`Observation::grants`] is false while [`Observation::succeeded`] is true.
//!   [`Permission::ReadPath`] means "this path and everything under it", and glibc's
//!   resolver alone probes `/` on the way to `/etc/resolv.conf`: folding that into a
//!   grant turns one `st_mode` lookup into read access to the whole filesystem, and the
//!   ancestor-collapsing in [`Permissions::merge`] then swallows every other read grant
//!   into it. Opening a directory still grants it - that is a deliberate `readdir`, not
//!   a probe.
//! - A relative path is resolved against its `dirfd` through `/proc/<pid>/fd` while the
//!   tracee is stopped. When that lookup fails the path is recorded **exactly as the
//!   tracee passed it** and [`Observation::path_is_resolved`] is false, with the evidence
//!   line saying so. Inventing a plausible absolute path would be worse than admitting
//!   the gap.
//!
//! [`Enforcement::Audit`]: crate::perms::Enforcement::Audit

use std::{path::PathBuf, time::Duration};

use crate::perms::{Permission, Permissions, Provenance};

/// How to run the program being traced.
///
/// [`TraceOptions::default`] gives a 30-second timeout, the current working directory,
/// an empty environment and fork following enabled.
#[derive(Debug, Clone)]
pub struct TraceOptions {
    /// Wall-clock budget for the whole traced process group. When it runs out the group
    /// is killed and [`TraceReport::timed_out`] is true.
    pub timeout: Duration,
    /// Directory to `chdir` into before `execve`. `None` inherits ours.
    pub working_dir: Option<PathBuf>,
    /// The complete environment for the tracee. This is *not* merged with ours: a
    /// monitor that inherited the developer's `$HOME` and `$LANG` would record their
    /// machine rather than the package.
    pub env: Vec<(String, String)>,
    /// Trace children too, via `PTRACE_O_TRACEFORK`/`TRACEVFORK`/`TRACECLONE`. A build
    /// tool that does its real work in a child is invisible without this.
    pub follow_forks: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            working_dir: None,
            env: Vec::new(),
            follow_forks: true,
        }
    }
}

/// One syscall the tracee made, decoded into the permission it implies.
///
/// A single syscall can yield more than one observation (`rename` names two paths,
/// `execve` implies both [`Permission::Spawn`] and [`Permission::ExecPath`]), so
/// observations are per-permission rather than per-syscall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pid: i32,
    syscall: &'static str,
    permission: Permission,
    path_resolved: bool,
    succeeded: bool,
    granting: bool,
}

impl Observation {
    /// The thread that made the call.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The syscall's name, e.g. `openat`.
    pub fn syscall(&self) -> &'static str {
        self.syscall
    }

    /// The permission this call implies.
    pub fn permission(&self) -> &Permission {
        &self.permission
    }

    /// Whether a relative path was successfully resolved against its `dirfd`.
    ///
    /// `false` means the path inside [`Observation::permission`] is verbatim what the
    /// tracee passed and is **not** an absolute path. Always `true` for a pathless
    /// permission or one that arrived absolute.
    pub fn path_is_resolved(&self) -> bool {
        self.path_resolved
    }

    /// Whether the syscall returned success. Failed calls grant nothing.
    pub fn succeeded(&self) -> bool {
        self.succeeded
    }

    /// Whether this observation contributes a grant to [`TraceReport::permissions`].
    ///
    /// A successful syscall can still grant nothing. The case that matters is a
    /// *metadata probe* - `stat`, `access`, `readlink` and friends - on a path that is a
    /// directory. [`Permission::ReadPath`] means "this path **and everything under it**",
    /// so folding a `stat("/")` into a grant would hand the package the entire
    /// filesystem on the strength of one `st_mode` lookup. Those observations are kept
    /// and reported, but they do not widen the profile. See [`trace`] for the full list.
    pub fn grants(&self) -> bool {
        self.succeeded && self.granting
    }

    /// The evidence line this observation contributes, naming the syscall and the path.
    pub fn evidence(&self) -> String {
        let subject = self
            .permission
            .path()
            .map_or_else(|| "(no path)".to_owned(), |path| path.display().to_string());
        let mut line = format!("{} {subject} (pid {})", self.syscall, self.pid);
        if !self.path_resolved {
            line.push_str(" [relative, dirfd unresolved - recorded as passed]");
        }
        line
    }
}

/// What one traced execution did.
///
/// Read [`TraceReport::permissions`] for the profile and [`TraceReport::observations`]
/// for the unfolded detail behind it. Always check [`TraceReport::timed_out`]: a report
/// from a run that was killed describes a prefix of the program's behaviour, so it is
/// even less complete than a monitor report normally is.
#[derive(Debug, Clone)]
pub struct TraceReport {
    permissions: Permissions,
    observations: Vec<Observation>,
    timed_out: bool,
    exit_status: Option<i32>,
}

impl TraceReport {
    /// The permission set folded out of the successful observations.
    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    /// Every decoded syscall, in the order it happened, failures included.
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// Whether the timeout fired and the traced process group was killed.
    pub fn timed_out(&self) -> bool {
        self.timed_out
    }

    /// The traced program's exit code, or `None` if it was killed by a signal, timed out
    /// or never got far enough to exit.
    pub fn exit_status(&self) -> Option<i32> {
        self.exit_status
    }
}

/// Build a report from raw observations, folding the successful ones into a profile.
#[cfg_attr(
    not(target_arch = "x86_64"),
    allow(dead_code, reason = "no tracer on this arch")
)]
fn report(
    observations: Vec<Observation>,
    timed_out: bool,
    exit_status: Option<i32>,
) -> TraceReport {
    let permissions: Permissions = observations
        .iter()
        .filter(|observation| observation.grants())
        .map(|observation| {
            crate::perms::Grant::new(
                observation.permission.clone(),
                Provenance::RuntimeMonitor,
                [observation.evidence()],
            )
        })
        .collect();
    TraceReport {
        permissions,
        observations,
        timed_out,
        exit_status,
    }
}

#[cfg(not(target_arch = "x86_64"))]
/// Run `program` with `args` under ptrace and record what it actually touched.
///
/// **Only implemented for `x86_64`.** Syscall numbers and the argument registers are
/// per-architecture, and a table from the wrong architecture would decode `openat` as
/// something else entirely and quietly write a wrong profile. On any other target this
/// returns a diagnostic instead.
///
/// # Errors
///
/// Always, on a non-`x86_64` target.
pub fn trace(
    program: &std::path::Path,
    args: &[String],
    options: &TraceOptions,
) -> miette::Result<TraceReport> {
    let _ = (program, args, options);
    Err(miette::miette!(
        help = "run the runtime monitor on an x86_64 host, or extend the syscall table in \
                src/perms/monitor.rs for this architecture",
        "the ptrace runtime monitor is implemented for x86_64 only (this is {})",
        std::env::consts::ARCH
    ))
}

#[cfg(target_arch = "x86_64")]
pub use x86_64::trace;

/// The x86_64 implementation: syscall table, argument decoding and the tracer loop.
///
/// Everything in here is architecture-specific by construction - see [`TABLE`].
#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use std::{
        collections::HashMap,
        ffi::{CString, OsString},
        os::unix::ffi::OsStringExt as _,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use miette::{IntoDiagnostic as _, Result, WrapErr as _, miette};
    use nix::{
        errno::Errno,
        libc,
        sys::{
            ptrace,
            signal::Signal,
            wait::{WaitPidFlag, WaitStatus, waitpid},
        },
        unistd::{ForkResult, Pid, execve, fork, setpgid},
    };
    use tracing::{debug, trace as trace_log, warn};

    use super::{Observation, TraceOptions, TraceReport, report};
    use crate::perms::Permission;

    /// What a decoded syscall argument turns into.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Shape {
        /// `open`-family: `(path, flags)`, write-ness read out of the flags.
        Open {
            dirfd: Option<u8>,
            path: u8,
            flags: u8,
        },
        /// `openat2`: flags live in a `struct open_how` rather than a register.
        OpenHow { dirfd: u8, path: u8, how: u8 },
        /// Reads metadata or contents at a path.
        Read { dirfd: Option<u8>, path: u8 },
        /// Creates, removes or renames a path.
        Write { dirfd: Option<u8>, path: u8 },
        /// Renames: two paths, both written.
        Rename {
            old_dirfd: Option<u8>,
            old_path: u8,
            new_dirfd: Option<u8>,
            new_path: u8,
        },
        /// `execve`-family: [`Permission::Spawn`] plus [`Permission::ExecPath`].
        Exec { dirfd: Option<u8>, path: u8 },
        /// `fork`/`clone`-family: [`Permission::Spawn`] and nothing else.
        Spawn,
        /// `socket(domain, ...)`: the address family is a plain register.
        SocketDomain { domain: u8 },
        /// `connect`/`bind`/`sendto`: the family lives in the `sockaddr` at `addr`.
        SockAddr { addr: u8, len: u8, binds: bool },
    }

    /// The syscalls worth decoding, by **x86_64** syscall number.
    ///
    /// The numbers come from `libc`'s `SYS_*` constants for this target rather than from
    /// memory, so the table cannot drift from the kernel ABI. It is nevertheless
    /// x86_64-only: `SYS_open` is 2 here and something else on every other architecture,
    /// and several entries (`open`, `stat`, `access`, `unlink`, `mkdir`, `rename`,
    /// `fork`, `vfork`) do not exist at all on the newer architectures that only ship
    /// the `*at` forms. The whole module is gated on `target_arch = "x86_64"` for that
    /// reason.
    ///
    /// Register order for a syscall on this ABI is `rdi, rsi, rdx, r10, r8, r9`, which is
    /// what the `u8` argument indices below mean.
    const TABLE: &[(i64, &str, Shape)] = &[
        // --- files: open ---
        (
            libc::SYS_open,
            "open",
            Shape::Open {
                dirfd: None,
                path: 0,
                flags: 1,
            },
        ),
        (
            libc::SYS_openat,
            "openat",
            Shape::Open {
                dirfd: Some(0),
                path: 1,
                flags: 2,
            },
        ),
        (
            libc::SYS_openat2,
            "openat2",
            Shape::OpenHow {
                dirfd: 0,
                path: 1,
                how: 2,
            },
        ),
        // --- files: metadata reads ---
        (
            libc::SYS_stat,
            "stat",
            Shape::Read {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_lstat,
            "lstat",
            Shape::Read {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_newfstatat,
            "newfstatat",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_statx,
            "statx",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_access,
            "access",
            Shape::Read {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_faccessat,
            "faccessat",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_faccessat2,
            "faccessat2",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_readlink,
            "readlink",
            Shape::Read {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_readlinkat,
            "readlinkat",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        // --- files: mutations ---
        (
            libc::SYS_unlink,
            "unlink",
            Shape::Write {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_unlinkat,
            "unlinkat",
            Shape::Write {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_mkdir,
            "mkdir",
            Shape::Write {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_mkdirat,
            "mkdirat",
            Shape::Write {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_rename,
            "rename",
            Shape::Rename {
                old_dirfd: None,
                old_path: 0,
                new_dirfd: None,
                new_path: 1,
            },
        ),
        (
            libc::SYS_renameat,
            "renameat",
            Shape::Rename {
                old_dirfd: Some(0),
                old_path: 1,
                new_dirfd: Some(2),
                new_path: 3,
            },
        ),
        (
            libc::SYS_renameat2,
            "renameat2",
            Shape::Rename {
                old_dirfd: Some(0),
                old_path: 1,
                new_dirfd: Some(2),
                new_path: 3,
            },
        ),
        // --- processes ---
        (
            libc::SYS_execve,
            "execve",
            Shape::Exec {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_execveat,
            "execveat",
            Shape::Exec {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (libc::SYS_fork, "fork", Shape::Spawn),
        (libc::SYS_vfork, "vfork", Shape::Spawn),
        (libc::SYS_clone, "clone", Shape::Spawn),
        (libc::SYS_clone3, "clone3", Shape::Spawn),
        // --- sockets ---
        (
            libc::SYS_socket,
            "socket",
            Shape::SocketDomain { domain: 0 },
        ),
        (
            libc::SYS_connect,
            "connect",
            Shape::SockAddr {
                addr: 1,
                len: 2,
                binds: false,
            },
        ),
        (
            libc::SYS_bind,
            "bind",
            Shape::SockAddr {
                addr: 1,
                len: 2,
                binds: true,
            },
        ),
        (
            libc::SYS_sendto,
            "sendto",
            Shape::SockAddr {
                addr: 4,
                len: 5,
                binds: false,
            },
        ),
    ];

    /// Longest path we will copy out of a tracee, matching `PATH_MAX`.
    const PATH_MAX: usize = libc::PATH_MAX as usize;

    /// How long to sleep when no tracee has an event pending. Short enough that the
    /// timeout stays sharp, long enough not to spin a core while a tracee sleeps.
    const IDLE_POLL: Duration = Duration::from_micros(200);

    /// How long to keep reaping after a timeout kill before giving up on a stuck tracee.
    const REAP_BUDGET: Duration = Duration::from_secs(2);

    /// Per-tracee bookkeeping. `PTRACE_SYSCALL` stops on both entry and exit, and only
    /// the pair together tells us both the arguments and whether the call worked.
    ///
    /// A new tracee - ours after `execve`, or a child the fork options handed us - starts
    /// outside a syscall: its first stop is an entry. See [`phase`].
    #[derive(Default)]
    struct State {
        /// Fallback for [`phase`] on a kernel without `PTRACE_GET_SYSCALL_INFO`: whether
        /// the last stop was an entry, so the next one should be its exit.
        in_syscall: bool,
        /// Observations decoded at entry, waiting for the exit stop to say if they count.
        pending: Vec<Observation>,
        /// Whether `pending` came from an `execve`, whose "exit" arrives as a plain
        /// `SIGTRAP` after the new image is in place rather than as a syscall stop.
        pending_is_exec: bool,
    }

    /// Run `program` with `args` under ptrace and record what it actually touched.
    ///
    /// The child is put in its own process group, `chdir`ed into
    /// [`TraceOptions::working_dir`], given exactly [`TraceOptions::env`] as its
    /// environment, and traced with `PTRACE_O_TRACESYSGOOD` (plus the fork options when
    /// [`TraceOptions::follow_forks`] is set) and `PTRACE_O_EXITKILL`, so nothing
    /// survives us. When [`TraceOptions::timeout`] expires the whole group is killed and
    /// the report says [`TraceReport::timed_out`].
    ///
    /// The returned profile is **incomplete by construction** - it describes the paths
    /// this one execution took and no others - which is why a profile derived from it
    /// stays in [`Enforcement::Audit`] until a human promotes it.
    ///
    /// # Errors
    ///
    /// A diagnostic if `program` or an argument contains an interior NUL, if `fork`
    /// fails, or if the child cannot be waited for at all. A tracee that exits non-zero
    /// is *not* an error: that is reported through [`TraceReport::exit_status`].
    ///
    /// [`Enforcement::Audit`]: crate::perms::Enforcement::Audit
    pub fn trace(program: &Path, args: &[String], options: &TraceOptions) -> Result<TraceReport> {
        let program_c = cstring(program.as_os_str().as_encoded_bytes())
            .wrap_err_with(|| format!("program path {}", program.display()))?;
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(program_c.clone());
        for arg in args {
            argv.push(cstring(arg.as_bytes()).wrap_err_with(|| format!("argument {arg:?}"))?);
        }
        let mut envp = Vec::with_capacity(options.env.len());
        for (key, value) in &options.env {
            envp.push(
                cstring(format!("{key}={value}").as_bytes())
                    .wrap_err_with(|| format!("environment variable {key:?}"))?,
            );
        }
        let working_dir = options
            .working_dir
            .as_deref()
            .map(|dir| cstring(dir.as_os_str().as_encoded_bytes()))
            .transpose()
            .wrap_err("working directory")?;

        debug!(
            program = %program.display(),
            args = args.len(),
            timeout_ms = options.timeout.as_millis(),
            follow_forks = options.follow_forks,
            "starting ptrace runtime monitor"
        );

        // SAFETY: the child branch below touches nothing but pre-allocated CStrings and
        // async-signal-safe syscalls before `execve` replaces the image.
        match unsafe { fork() }
            .into_diagnostic()
            .wrap_err("fork for ptrace monitor")?
        {
            ForkResult::Child => {
                child(&program_c, &argv, &envp, working_dir.as_deref());
            }
            ForkResult::Parent { child } => supervise(child, program, options),
        }
    }

    /// The child half of [`trace`]: become a process group leader, ask to be traced and
    /// exec. Never returns - every failure path is an `_exit`, because returning would
    /// leave a duplicate of the tracer running.
    fn child(
        program: &CString,
        argv: &[CString],
        envp: &[CString],
        working_dir: Option<&std::ffi::CStr>,
    ) -> ! {
        // Own process group, so the timeout can kill the whole tree with one killpg.
        if setpgid(Pid::from_raw(0), Pid::from_raw(0)).is_err() {
            // SAFETY: `_exit` is async-signal-safe and does not unwind.
            unsafe { libc::_exit(127) }
        }
        if let Some(dir) = working_dir {
            // SAFETY: `dir` is a live NUL-terminated string; `chdir` is async-signal-safe.
            // `nix::unistd::chdir` would need the crate's `fs` feature, which is not on.
            if unsafe { libc::chdir(dir.as_ptr()) } != 0 {
                unsafe { libc::_exit(127) }
            }
        }
        if ptrace::traceme().is_err() {
            unsafe { libc::_exit(127) }
        }
        let _ = execve(program, argv, envp);
        // execve only returns on failure.
        unsafe { libc::_exit(127) }
    }

    /// The tracer loop: step every tracee through its syscalls until they all exit or
    /// the timeout fires.
    fn supervise(root: Pid, program: &Path, options: &TraceOptions) -> Result<TraceReport> {
        let deadline = Instant::now() + options.timeout;
        let mut observations: Vec<Observation> = Vec::new();

        // The first stop is the SIGTRAP the kernel raises once our own execve has
        // installed the new image. Until it arrives the tracee has no options set.
        match wait_any(deadline)? {
            Wait::Event(WaitStatus::Exited(_, code)) => {
                warn!(code, "tracee exited before the initial exec trap");
                return Ok(report(observations, false, Some(code)));
            }
            Wait::Event(WaitStatus::Stopped(pid, _)) => set_options(pid, options.follow_forks)?,
            Wait::Event(other) => {
                return Err(miette!(
                    "unexpected first wait status from the tracee: {other:?}"
                ));
            }
            Wait::Timeout => {
                kill_group(root);
                drain(root);
                return Ok(report(observations, true, None));
            }
            Wait::NoChildren => {
                return Err(miette!(
                    "the traced child vanished before it could be traced - \
                     was another thread reaping our children?"
                ));
            }
        }

        // Our own execve is not visible as a syscall stop, so record it by hand.
        observations.push(Observation {
            pid: root.as_raw(),
            syscall: "execve",
            permission: Permission::Spawn,
            path_resolved: true,
            succeeded: true,
            granting: true,
        });
        observations.push(Observation {
            pid: root.as_raw(),
            syscall: "execve",
            permission: Permission::ExecPath(program.to_path_buf()),
            path_resolved: true,
            succeeded: true,
            granting: true,
        });

        let mut states: HashMap<Pid, State> = HashMap::new();
        states.insert(root, State::default());
        resume(root);

        let mut exit_status = None;
        let mut timed_out = false;

        while !states.is_empty() {
            let status = match wait_any(deadline)? {
                Wait::Event(status) => status,
                Wait::Timeout => {
                    warn!(
                        timeout_ms = options.timeout.as_millis(),
                        alive = states.len(),
                        "ptrace monitor timed out; killing the traced process group"
                    );
                    timed_out = true;
                    kill_group(root);
                    drain(root);
                    break;
                }
                // Not a timeout: there is simply nobody left to wait for, so the run is
                // over even though a pid we were tracking never reported its exit.
                Wait::NoChildren => {
                    warn!(
                        unreported = states.len(),
                        "every tracee is gone but some never reported an exit"
                    );
                    break;
                }
            };
            match status {
                WaitStatus::StillAlive => std::thread::sleep(IDLE_POLL),
                WaitStatus::Exited(pid, code) => {
                    states.remove(&pid);
                    if pid == root {
                        exit_status = Some(code);
                    }
                }
                WaitStatus::Signaled(pid, signal, _) => {
                    states.remove(&pid);
                    if pid == root {
                        warn!(%signal, "traced program was killed by a signal");
                    }
                }
                WaitStatus::PtraceSyscall(pid) => {
                    let state = states.entry(pid).or_default();
                    syscall_stop(pid, state, &mut observations);
                    resume(pid);
                }
                WaitStatus::PtraceEvent(pid, _, _) => {
                    // A fork/clone event on the parent. The new child announces itself
                    // with its own stop, handled below.
                    states.entry(pid).or_default();
                    resume(pid);
                }
                WaitStatus::Stopped(pid, signal) => {
                    stopped(pid, signal, &mut states, &mut observations);
                }
                WaitStatus::Continued(_) => {}
            }
        }

        debug!(
            observations = observations.len(),
            timed_out, exit_status, "ptrace runtime monitor finished"
        );
        Ok(report(observations, timed_out, exit_status))
    }

    /// Handle a plain signal-delivery stop.
    ///
    /// Three cases hide in here. A pid we have never seen is a child the fork options
    /// just handed us; it is stopped with `SIGSTOP` and starts its life at a syscall
    /// *exit* (the `clone` it was born from). A `SIGTRAP` is the post-`execve` trap - the
    /// only reason `PTRACE_O_TRACESYSGOOD` is set is so that it is distinguishable from a
    /// real syscall stop here, because an `execve` that succeeds never delivers a
    /// syscall-exit stop and would otherwise desynchronise entry/exit pairing for the
    /// rest of the run. Anything else is a real signal and is forwarded to the tracee.
    fn stopped(
        pid: Pid,
        signal: Signal,
        states: &mut HashMap<Pid, State>,
        observations: &mut Vec<Observation>,
    ) {
        let known = states.contains_key(&pid);
        let state = states.entry(pid).or_default();
        if !known {
            trace_log!(pid = pid.as_raw(), "new tracee joined");
            resume(pid);
            return;
        }
        if signal == Signal::SIGTRAP {
            if state.pending_is_exec {
                // The exec landed: the arguments we decoded at entry are now fact.
                for mut observation in state.pending.drain(..) {
                    observation.succeeded = true;
                    observations.push(observation);
                }
                state.pending_is_exec = false;
                state.in_syscall = false;
            }
            resume(pid);
            return;
        }
        if matches!(signal, Signal::SIGSTOP) {
            resume(pid);
            return;
        }
        resume_with(pid, signal);
    }

    /// What came back from a wait.
    ///
    /// "No children left" is deliberately not folded into "timed out". Both end the
    /// loop, but only one of them means the report is a truncated prefix, and
    /// [`TraceReport::timed_out`] would be lying if it could not tell them apart.
    enum Wait {
        /// A tracee changed state.
        Event(WaitStatus),
        /// The budget in [`TraceOptions::timeout`] ran out.
        Timeout,
        /// Every child is gone, whether or not we were still expecting one.
        NoChildren,
    }

    /// Which half of a syscall a `PTRACE_SYSCALL` stop is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Phase {
        /// The arguments are in the registers and the call has not run yet.
        Entry,
        /// The call has run and `rax` holds its result.
        Exit,
    }

    /// Ask the kernel which half of a syscall this stop is.
    ///
    /// `PTRACE_SYSCALL` reports entry and exit identically, so a tracer normally just
    /// alternates - and gets it wrong the moment the sequence is perturbed. It is: a
    /// freshly cloned child's *first* syscall stop is an entry, not the exit of the
    /// `clone` it was born from, and a successful `execve` never delivers a syscall-exit
    /// stop at all. Both were observed here, and an alternating tracer mis-pairs every
    /// syscall afterwards, decoding return values as arguments.
    ///
    /// `PTRACE_GET_SYSCALL_INFO` answers the question outright, so use it and keep the
    /// alternating flag only as a fallback for a kernel too old to have it (< 5.3).
    fn phase(pid: Pid, state: &State) -> Phase {
        match ptrace::syscall_info(pid) {
            Ok(info) if info.op == libc::PTRACE_SYSCALL_INFO_ENTRY => Phase::Entry,
            Ok(info) if info.op == libc::PTRACE_SYSCALL_INFO_EXIT => Phase::Exit,
            _ if state.in_syscall => Phase::Exit,
            _ => Phase::Entry,
        }
    }

    /// Handle one `PTRACE_SYSCALL` stop: decode arguments on entry, judge them on exit.
    fn syscall_stop(pid: Pid, state: &mut State, observations: &mut Vec<Observation>) {
        let Ok(regs) = ptrace::getregs(pid) else {
            trace_log!(
                pid = pid.as_raw(),
                "could not read registers at a syscall stop"
            );
            return;
        };
        if phase(pid, state) == Phase::Exit {
            state.in_syscall = false;
            state.pending_is_exec = false;
            let succeeded = !is_errno(regs.rax);
            for mut observation in state.pending.drain(..) {
                observation.succeeded = succeeded;
                observations.push(observation);
            }
            return;
        }
        state.in_syscall = true;
        // A pending entry still here at the next entry belongs to an `execve` whose
        // post-exec `SIGTRAP` we did not see. Reaching another syscall at all proves the
        // exec worked, so count it rather than losing it.
        if state.pending_is_exec {
            for mut observation in state.pending.drain(..) {
                observation.succeeded = true;
                observations.push(observation);
            }
        }
        state.pending.clear();
        state.pending_is_exec = false;

        #[allow(clippy::cast_possible_wrap)]
        let number = regs.orig_rax as i64;
        let Some(&(_, name, shape)) = TABLE.iter().find(|(nr, _, _)| *nr == number) else {
            return;
        };
        let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        state.pending = decode(pid, name, shape, &args);
        state.pending_is_exec = matches!(shape, Shape::Exec { .. });
    }

    /// Turn one syscall's arguments into the permissions it implies.
    fn decode(pid: Pid, name: &'static str, shape: Shape, args: &[u64; 6]) -> Vec<Observation> {
        let at = |index: u8| args[usize::from(index)];
        let make = |permission: Permission, resolved: bool| Observation {
            pid: pid.as_raw(),
            syscall: name,
            permission,
            path_resolved: resolved,
            succeeded: false,
            granting: true,
        };
        // A metadata probe reads one inode, not a subtree - see [`probe`].
        let probe = |permission: Permission, resolved: bool| Observation {
            granting: !names_a_directory(&permission),
            ..make(permission, resolved)
        };
        match shape {
            Shape::Open { dirfd, path, flags } => {
                let Some((path, resolved)) = path_arg(pid, dirfd.map(at), at(path)) else {
                    return Vec::new();
                };
                vec![make(open_permission(path, at(flags)), resolved)]
            }
            Shape::OpenHow { dirfd, path, how } => {
                let Some((path, resolved)) = path_arg(pid, Some(at(dirfd)), at(path)) else {
                    return Vec::new();
                };
                // struct open_how { __u64 flags, mode, resolve; } - flags come first.
                let flags = read_u64(pid, at(how)).unwrap_or(0);
                vec![make(open_permission(path, flags), resolved)]
            }
            Shape::Read { dirfd, path } => path_arg(pid, dirfd.map(at), at(path))
                .map(|(path, resolved)| vec![probe(Permission::ReadPath(path), resolved)])
                .unwrap_or_default(),
            Shape::Write { dirfd, path } => path_arg(pid, dirfd.map(at), at(path))
                .map(|(path, resolved)| vec![make(Permission::WritePath(path), resolved)])
                .unwrap_or_default(),
            Shape::Rename {
                old_dirfd,
                old_path,
                new_dirfd,
                new_path,
            } => [
                path_arg(pid, old_dirfd.map(at), at(old_path)),
                path_arg(pid, new_dirfd.map(at), at(new_path)),
            ]
            .into_iter()
            .flatten()
            .map(|(path, resolved)| make(Permission::WritePath(path), resolved))
            .collect(),
            Shape::Exec { dirfd, path } => {
                let mut out = vec![make(Permission::Spawn, true)];
                if let Some((path, resolved)) = path_arg(pid, dirfd.map(at), at(path)) {
                    out.push(make(Permission::ExecPath(path), resolved));
                }
                out
            }
            Shape::Spawn => vec![make(Permission::Spawn, true)],
            Shape::SocketDomain { domain } => {
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let family = at(domain) as u32 as i32;
                if is_inet(family) {
                    vec![make(Permission::Network, true)]
                } else {
                    Vec::new()
                }
            }
            Shape::SockAddr { addr, len, binds } => sockaddr(pid, at(addr), at(len))
                .map(|family| match family {
                    // AF_INET/AF_INET6 is the network. AF_UNIX is NOT: it is a path on
                    // the filesystem, and folding it into Network would silently hand
                    // every package that talks to a local daemon a network grant.
                    Family::Inet => vec![make(Permission::Network, true)],
                    Family::Unix(path) if binds => {
                        vec![make(Permission::WritePath(path), true)]
                    }
                    Family::Unix(path) => vec![make(Permission::ReadPath(path), true)],
                    Family::Other => Vec::new(),
                })
                .unwrap_or_default(),
        }
    }

    /// Whether a permission names a path that is a directory on this machine.
    ///
    /// Used to stop a metadata probe from granting a subtree. It is a question about the
    /// tracing host, asked while the tracee is stopped mid-syscall, so it is as accurate
    /// as anything else the monitor records; a path that does not exist or cannot be
    /// stat'd counts as "not a directory" and keeps its grant.
    fn names_a_directory(permission: &Permission) -> bool {
        permission
            .path()
            .and_then(|path| std::fs::metadata(path).ok())
            .is_some_and(|metadata| metadata.is_dir())
    }

    /// `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC` or `O_APPEND` make an open a write;
    /// anything else is a read.
    fn open_permission(path: PathBuf, flags: u64) -> Permission {
        #[allow(clippy::cast_sign_loss)]
        let writing = {
            let access = flags & libc::O_ACCMODE as u64;
            access == libc::O_WRONLY as u64
                || access == libc::O_RDWR as u64
                || flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u64 != 0
        };
        if writing {
            Permission::WritePath(path)
        } else {
            Permission::ReadPath(path)
        }
    }

    /// The address family behind a `sockaddr`, with the `AF_UNIX` path already extracted.
    enum Family {
        /// `AF_INET` or `AF_INET6`: this is the network.
        Inet,
        /// `AF_UNIX`: a filesystem path, not the network.
        Unix(PathBuf),
        /// Anything else - netlink, packet, bluetooth - which we do not model.
        Other,
    }

    /// Read a `sockaddr` out of the tracee and classify it.
    fn sockaddr(pid: Pid, addr: u64, len: u64) -> Option<Family> {
        if addr == 0 || len < 2 {
            return None;
        }
        let want = usize::try_from(len).unwrap_or(2).min(2 + PATH_MAX);
        let bytes = read_bytes(pid, addr, want)?;
        let family = i32::from(u16::from_ne_bytes([*bytes.first()?, *bytes.get(1)?]));
        if is_inet(family) {
            return Some(Family::Inet);
        }
        if family != libc::AF_UNIX {
            return Some(Family::Other);
        }
        let sun_path = bytes.get(2..)?;
        // An abstract socket starts with a NUL and has no filesystem path at all.
        if sun_path.first() == Some(&0) || sun_path.is_empty() {
            return Some(Family::Other);
        }
        let end = sun_path
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(sun_path.len());
        Some(Family::Unix(PathBuf::from(OsString::from_vec(
            sun_path[..end].to_vec(),
        ))))
    }

    /// Whether an address family is the actual network.
    fn is_inet(family: i32) -> bool {
        family == libc::AF_INET || family == libc::AF_INET6
    }

    /// Whether a syscall return value is a negated errno rather than a result.
    ///
    /// The kernel returns errors in `[-4095, -1]`; every other value is success, which
    /// matters for the syscalls that legitimately return large unsigned-looking numbers.
    fn is_errno(rax: u64) -> bool {
        #[allow(clippy::cast_possible_wrap)]
        let value = rax as i64;
        (-4095..0).contains(&value)
    }

    /// Read a path argument and make it absolute if we honestly can.
    ///
    /// Returns the path and whether it is resolved. An absolute path needs no work. A
    /// relative one is joined onto the directory its `dirfd` names, read out of
    /// `/proc/<pid>/cwd` for `AT_FDCWD` or `/proc/<pid>/fd/<n>` otherwise - both readable
    /// because the tracee is stopped in a syscall right now. If that readlink fails the
    /// path is returned **verbatim** with `resolved` false rather than guessed at.
    fn path_arg(pid: Pid, dirfd: Option<u64>, addr: u64) -> Option<(PathBuf, bool)> {
        let path = read_path(pid, addr)?;
        if path.is_absolute() {
            return Some((path, true));
        }
        // `execveat`/`openat` with an empty path and AT_EMPTY_PATH means "the fd itself".
        let base = match dirfd {
            None => proc_link(pid, "cwd"),
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            Some(fd) if fd as u32 as i32 == libc::AT_FDCWD => proc_link(pid, "cwd"),
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            Some(fd) => proc_link(pid, &format!("fd/{}", fd as u32 as i32)),
        };
        match base {
            Some(base) if path.as_os_str().is_empty() => Some((base, true)),
            Some(base) => Some((base.join(&path), true)),
            None => Some((path, false)),
        }
    }

    /// Read one of the tracee's `/proc` symlinks.
    fn proc_link(pid: Pid, what: &str) -> Option<PathBuf> {
        let link = format!("/proc/{}/{what}", pid.as_raw());
        let target = std::fs::read_link(link).ok()?;
        // Sockets and pipes read back as "socket:[12345]", which is not a directory.
        target.is_absolute().then_some(target)
    }

    /// Copy a NUL-terminated path out of the tracee, capped at `PATH_MAX`.
    ///
    /// A null pointer, an unreadable address or a string with no terminator inside
    /// `PATH_MAX` all yield `None` instead of a panic.
    fn read_path(pid: Pid, addr: u64) -> Option<PathBuf> {
        if addr == 0 {
            return None;
        }
        let mut out: Vec<u8> = Vec::with_capacity(64);
        let mut cursor = addr;
        while out.len() < PATH_MAX {
            // Never cross a page boundary in one read: the next page may be unmapped,
            // and a single oversized read would fail outright instead of returning the
            // bytes that *are* there.
            let page = 4096 - (cursor % 4096);
            let want = page.min((PATH_MAX - out.len()) as u64).min(256);
            let want = usize::try_from(want).ok()?;
            let chunk = read_bytes(pid, cursor, want)?;
            if chunk.is_empty() {
                return None;
            }
            if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
                out.extend_from_slice(&chunk[..end]);
                return Some(PathBuf::from(OsString::from_vec(out)));
            }
            out.extend_from_slice(&chunk);
            cursor += chunk.len() as u64;
        }
        None
    }

    /// Read a little-endian `u64` out of the tracee.
    fn read_u64(pid: Pid, addr: u64) -> Option<u64> {
        let bytes = read_bytes(pid, addr, 8)?;
        Some(u64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?))
    }

    /// Copy `len` bytes out of the tracee's address space.
    ///
    /// `process_vm_readv` is the cheap path - one syscall for the whole buffer. When it
    /// is unavailable or refuses (a hardened kernel, a partially mapped range) this falls
    /// back to word-at-a-time `PTRACE_PEEKDATA`, which reaches anything ptrace itself
    /// can. A short read is returned as-is; an unreadable first word gives `None`.
    fn read_bytes(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        let mut buffer = vec![0u8; len];
        let local = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: usize::try_from(addr).ok()? as *mut libc::c_void,
            iov_len: len,
        };
        // SAFETY: both iovecs describe live, correctly sized buffers; the remote one is
        // only ever dereferenced by the kernel, which validates it and returns EFAULT.
        let read = unsafe { libc::process_vm_readv(pid.as_raw(), &local, 1, &remote, 1, 0) };
        if read > 0 {
            buffer.truncate(usize::try_from(read).ok()?);
            return Some(buffer);
        }
        peek_bytes(pid, addr, len)
    }

    /// `PTRACE_PEEKDATA` fallback for [`read_bytes`], a machine word at a time.
    fn peek_bytes(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
        let word = size_of::<libc::c_long>();
        let mut out: Vec<u8> = Vec::with_capacity(len);
        while out.len() < len {
            let at = addr.checked_add(out.len() as u64)?;
            let value = match ptrace::read(pid, usize::try_from(at).ok()? as ptrace::AddressType) {
                Ok(value) => value,
                Err(Errno::EFAULT | Errno::EIO) if !out.is_empty() => break,
                Err(_) => return None,
            };
            let take = word.min(len - out.len());
            out.extend_from_slice(&value.to_ne_bytes()[..take]);
        }
        Some(out)
    }

    /// Turn a byte string into a `CString`, rejecting an interior NUL with a diagnostic
    /// rather than truncating silently.
    fn cstring(bytes: &[u8]) -> Result<CString> {
        CString::new(bytes)
            .into_diagnostic()
            .wrap_err("cannot pass a string containing a NUL byte to the traced program")
    }

    /// Ask the kernel for distinguishable syscall stops, child tracing and a dead-man
    /// switch that kills the tracees if we die.
    fn set_options(pid: Pid, follow_forks: bool) -> Result<()> {
        let mut options =
            ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_EXITKILL;
        if follow_forks {
            options |= ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACECLONE;
        }
        ptrace::setoptions(pid, options)
            .into_diagnostic()
            .wrap_err("could not set ptrace options on the tracee")
    }

    /// Let a tracee run to its next syscall stop. A tracee that died between the stop and
    /// here is not an error worth failing the whole trace over.
    fn resume(pid: Pid) {
        if let Err(errno) = ptrace::syscall(pid, None) {
            trace_log!(pid = pid.as_raw(), %errno, "could not resume tracee");
        }
    }

    /// Resume a tracee, delivering the signal that stopped it.
    fn resume_with(pid: Pid, signal: Signal) {
        if let Err(errno) = ptrace::syscall(pid, signal) {
            trace_log!(pid = pid.as_raw(), %errno, "could not resume tracee with signal");
        }
    }

    /// Wait for any tracee, returning `None` once `deadline` has passed.
    ///
    /// `WNOHANG` plus a short sleep is what makes the timeout real: a blocking `waitpid`
    /// on a tracee that sleeps forever would hang the build, which is worse than having
    /// no monitor at all.
    fn wait_any(deadline: Instant) -> Result<Wait> {
        let flags = WaitPidFlag::WNOHANG | WaitPidFlag::__WALL;
        loop {
            if Instant::now() >= deadline {
                return Ok(Wait::Timeout);
            }
            match waitpid(Pid::from_raw(-1), Some(flags)) {
                Ok(WaitStatus::StillAlive) => std::thread::sleep(IDLE_POLL),
                Ok(status) => return Ok(Wait::Event(status)),
                Err(Errno::EINTR) => {}
                Err(Errno::ECHILD) => return Ok(Wait::NoChildren),
                Err(errno) => {
                    return Err(miette!("waitpid failed while tracing: {errno}"));
                }
            }
        }
    }

    /// Kill the traced process group, and the leader directly in case it never managed
    /// its own `setpgid`.
    fn kill_group(root: Pid) {
        let _ = nix::sys::signal::killpg(root, Signal::SIGKILL);
        let _ = nix::sys::signal::kill(root, Signal::SIGKILL);
    }

    /// Reap everything left after a kill so the tracer leaves no zombies behind.
    fn drain(root: Pid) {
        let until = Instant::now() + REAP_BUDGET;
        let flags = WaitPidFlag::WNOHANG | WaitPidFlag::__WALL;
        while Instant::now() < until {
            match waitpid(Pid::from_raw(-1), Some(flags)) {
                Ok(WaitStatus::StillAlive) => std::thread::sleep(IDLE_POLL),
                // A tracee stopped in ptrace-stop has to be resumed to notice the SIGKILL.
                Ok(status) => {
                    if let Some(pid) = status.pid()
                        && matches!(
                            status,
                            WaitStatus::Stopped(..)
                                | WaitStatus::PtraceSyscall(_)
                                | WaitStatus::PtraceEvent(..)
                        )
                    {
                        let _ = ptrace::kill(pid);
                        let _ = ptrace::cont(pid, Signal::SIGKILL);
                    }
                }
                Err(Errno::EINTR) => {}
                Err(_) => return,
            }
        }
        warn!(
            root = root.as_raw(),
            "gave up reaping the traced process group"
        );
    }
}
