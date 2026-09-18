//! Extracting a `.cpkg` archive and running one of its entrypoints in a jail.
//!
//! A package is untrusted input: both the archive and the metadata inside it
//! were written by whoever built it. Three things follow, and all three are
//! enforced here rather than left to the caller.
//!
//! 1. **The signature is checked before the archive is opened.** `foo.cpkg` is
//!    verified against `foo.cpkg.sig` and the local trust store *before* `tar`
//!    ever reads it, so an untrusted archive is never unpacked.
//! 2. **Entrypoint paths are validated, not trusted.** The metadata ships
//!    inside the package, so `entrypoints:` can say anything at all -
//!    `../../../../bin/echo` included. Every entrypoint is checked twice: once
//!    structurally, and once by canonicalising the joined host path and
//!    requiring it to still live under the package root.
//! 3. **The sandbox has no network.** A packaged binary cannot phone home
//!    unless the caller opts in with [`PackageRunner::allow_network`].
//! 4. **The recorded permission profile is applied, never invented.** A package
//!    carries the [`Permissions`] its build derived (see [`crate::perms`]) and
//!    the [`Enforcement`] a human chose for them. [`Enforcement::Enforce`]
//!    becomes a landlock ruleset; [`Enforcement::Audit`] stays audit - nothing
//!    here ever promotes a profile by itself.
//!
//! # Why audit is a `ptrace` run and not a permissive ruleset
//!
//! Landlock has no log-only mode: a ruleset either denies or it is not there,
//! and the kernel offers no violation feed to log from. Attaching a permissive
//! ruleset and calling it "audit" would produce a sandbox that looks configured
//! and enforces nothing, which is the worst failure mode a security feature has
//! because it passes inspection. So [`PackageRunner::audit`] runs the entrypoint
//! under the `ptrace` monitor in [`crate::perms::monitor`] instead, diffs what it
//! really touched against the recorded profile, and reports every access that
//! falls outside it. **That traced run is not jailed** - see
//! [`PackageRunner::audit`].

use std::{
    collections::BTreeMap,
    env,
    fs::{File, read_to_string},
    io::{IsTerminal, stdin},
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};

use crate::{
    metadata::Metadata,
    perms::{
        Enforcement, Grant, Permission, Permissions, Provenance,
        elf::{interpreter, needed_libraries, runpath},
        monitor::{TraceOptions, TraceReport, trace},
    },
    signing::{TrustStore, default_trust_dir, verify_file},
    workspace::{SandboxedChild, Workspace},
};
use dialoguer::{Select, console::Term};
use hakoniwa::{
    Container, ExitStatus, MountOptions, Namespace, Runctl, Stdio,
    landlock::{CompatMode, FsAccess, Resource, Ruleset},
};
use miette::{Context, IntoDiagnostic, miette};
use serde::Deserialize;
use serde_yaml::from_str;
use tracing::{debug, info, warn};

/// Path the extracted package tree is bind-mounted on inside the sandbox.
///
/// The host-side staging directory is a throwaway temporary path, so entrypoints
/// are always invoked through this stable in-container path instead.
const CONTAINER_PACKAGE_ROOT: &str = "/pkg";

/// Immutable store a Nix-provisioned toolchain resolves into.
///
/// Mirrors the constant of the same name in [`crate::sandbox`]: a package built
/// against a Nix toolchain names its loader and libraries here, and neither is
/// covered by `rootfs("/")`.
const NIX_STORE: &str = "/nix/store";

/// Path the archive is bind-mounted at inside the extraction jail, read-only.
///
/// See [`PackageRunner::extract_jailed`].
const EXTRACT_ARCHIVE_MOUNT: &str = "/archive.cpkg";

/// Path the extraction destination is bind-mounted at inside the extraction
/// jail, writable - the only writable path the jailed `tar` can reach.
///
/// See [`PackageRunner::extract_jailed`].
const EXTRACT_DEST_MOUNT: &str = "/dest";

/// Package-root file a profile may be recorded in, when it is not inside the
/// `metadata` member.
///
/// Read as a fallback so that a package built by a `pm` that records the profile
/// beside the metadata rather than inside it still runs enforced. Its content is
/// either a `permissions:`/`enforcement:` map or a bare serialised
/// [`Permissions`].
const PROFILE_SIDECAR: &str = "permissions";

/// Directories the glibc loader searches when a `DT_NEEDED` soname carries no
/// path of its own.
///
/// Only used to *locate* the libraries an entrypoint names, so that the
/// directory actually holding each one can be allowed; a directory in this list
/// that holds none of them is never added to the ruleset. The order mirrors the
/// loader's own: architecture-specific directories before the generic ones.
const DEFAULT_LIBRARY_DIRS: [&str; 6] = [
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
];

/// Wall-clock budget for an audited run before the traced process group is
/// killed.
///
/// An audit exists to produce a report, and a report that never arrives is worse
/// than a partial one. [`TraceReport::timed_out`] is surfaced in the summary, so
/// a truncated audit is never mistaken for a clean one.
///
/// [`TraceReport::timed_out`]: crate::perms::monitor::TraceReport::timed_out
const AUDIT_TIMEOUT: Duration = Duration::from_secs(300);

/// Exit code reported for an audited run whose entrypoint did not exit on its
/// own - it timed out or died on a signal.
///
/// 124 is `timeout(1)`'s, which is the convention a shell caller already knows.
const AUDIT_UNFINISHED: i32 = 124;

/// Flags for the read-only bind mount of the extracted package.
///
/// **Not** [`Container::bindmount_ro`], which asks for `BIND|REC|NOSUID|RDONLY`
/// and is a trap together with [`Runctl::MountFallback`]. `hakoniwa` applies
/// `RDONLY` through a second `MS_REMOUNT`, and inside a user namespace the
/// kernel refuses a remount that drops a flag the source filesystem has locked.
/// Every `pm` workspace lives under `TMPDIR`, and a `/tmp` mounted
/// `nosuid,nodev` - the norm - locks `nodev`, which `bindmount_ro` never asks
/// for. That remount fails, the fallback recomputes the flags from `statfs`,
/// and because it re-adds only what the source filesystem carries it *drops*
/// `MS_RDONLY`: the "read-only" package comes back writable. Asking for `nodev`
/// up front makes the first remount succeed, so the fallback is never reached.
///
/// `noexec` is deliberately absent: the whole point is to exec the entrypoint.
fn package_mount_flags() -> MountOptions {
    MountOptions::BIND
        | MountOptions::REC
        | MountOptions::NOSUID
        | MountOptions::NODEV
        | MountOptions::RDONLY
}

/// Flags for the writable bind mount [`PackageRunner::extract_jailed`] gives
/// `tar` for the extraction destination.
///
/// Same reasoning as [`package_mount_flags`] minus `RDONLY`: `nodev` is asked
/// for up front so the read-write remount matches what a `nosuid,nodev` `/tmp`
/// (where the staging workspace this mounts lives) has already locked, and
/// [`Runctl::MountFallback`] is never actually needed to recover.
fn extraction_dest_flags() -> MountOptions {
    MountOptions::BIND | MountOptions::REC | MountOptions::NOSUID | MountOptions::NODEV
}

/// Extracts a `.cpkg` archive and runs one of its binaries inside a sandbox.
///
/// Defaults are the secure ones: the signature is required, and the sandbox has
/// no network. [`PackageRunner::allow_unsigned`] and
/// [`PackageRunner::allow_network`] relax each, and both say so in the log.
pub struct PackageRunner {
    path: PathBuf,
    /// Share the host network namespace instead of unsharing it.
    network: bool,
    /// Skip signature verification entirely. Documented escape hatch for tests
    /// and for locally built packages that were never signed.
    unsigned: bool,
    /// Trust store directory; [`default_trust_dir`] when `None`.
    trust_dir: Option<PathBuf>,
    /// Trace the entrypoint and report what fell outside its profile, instead of
    /// running it in the jail.
    audit: bool,
    /// Apply the recorded profile even when it is only in audit mode.
    enforce: bool,
}

impl PackageRunner {
    /// Initialises the package runner for the archive at `path`.
    ///
    /// Signature verification is on and the network is off; see
    /// [`PackageRunner::allow_unsigned`] and [`PackageRunner::allow_network`].
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            network: false,
            unsigned: false,
            trust_dir: None,
            audit: false,
            enforce: false,
        }
    }

    /// Lets the sandboxed entrypoint reach the network.
    ///
    /// By default the sandbox unshares the network namespace, so the package
    /// sees nothing but a downed `lo` and cannot exfiltrate anything it read.
    /// Pass `true` for packages that legitimately need to talk to the outside
    /// world; the choice is logged either way.
    pub fn allow_network(&mut self, allow: bool) -> &mut Self {
        self.network = allow;
        self
    }

    /// Runs the package even when it carries no valid signature.
    ///
    /// **This disables the only check that says where the package came from.**
    /// It exists for tests and for packages built locally a moment ago that
    /// were never signed; `run` logs a warning on every use. With `false` - the
    /// default - `<package>.cpkg.sig` must exist, verify, and be signed by a
    /// key in the trust store, all *before* the archive is extracted.
    pub fn allow_unsigned(&mut self, allow: bool) -> &mut Self {
        self.unsigned = allow;
        self
    }

    /// Verifies signatures against the trust store in `dir` instead of the
    /// default `<config>/pm/trusted/`.
    pub fn trust_dir(&mut self, dir: PathBuf) -> &mut Self {
        self.trust_dir = Some(dir);
        self
    }

    /// Trace the entrypoint and report accesses outside its profile.
    ///
    /// This answers "what would enforcing this profile break?", which landlock
    /// itself cannot answer: it has no log-only mode and reports no violations,
    /// so the only honest audit is to watch a real execution. The entrypoint is
    /// run under the `ptrace` monitor, every access it makes is compared against
    /// the recorded profile plus the allowances the sandbox always adds, and each
    /// one that falls outside is logged with its syscall and path, followed by a
    /// summary of the grants a promotion to [`Enforcement::Enforce`] would need.
    ///
    /// **The audited run is not jailed.** `ptrace` observes, it does not deny,
    /// and the monitor execs the entrypoint directly rather than inside the
    /// container - so an audited package runs with the caller's own privileges.
    /// Audit a package you are already willing to run; `run` says so at warn
    /// level every time. The run is also killed after [`AUDIT_TIMEOUT`].
    ///
    /// Auditing never turns denial on: it is a report, not a promotion.
    pub fn audit(&mut self, audit: bool) -> &mut Self {
        self.audit = audit;
        self
    }

    /// Apply the profile even when it is only in audit mode.
    ///
    /// A freshly derived profile is [`Enforcement::Audit`], because it was
    /// derived by observation and is incomplete by construction; enforcing one
    /// breaks the package the first time it takes a path nobody watched. This is
    /// the human promotion, and the only thing in `pm` that turns denial on for a
    /// profile that did not already carry it.
    ///
    /// A package that records no profile at all cannot be enforced - `run`
    /// refuses rather than enforcing an empty set, which would deny everything
    /// outside the package root.
    pub fn enforce(&mut self, enforce: bool) -> &mut Self {
        self.enforce = enforce;
        self
    }

    /// Extracts the package, picks a binary and runs it inside a `hakoniwa`
    /// sandbox, waiting for it to terminate.
    ///
    /// The detached signature is verified first, before a single archive member
    /// is unpacked. `bin` then names the entrypoint to run, matched against the
    /// entrypoint paths recorded in the package metadata (either the full
    /// package-relative path or just the file name). When it is `None` and the
    /// package exposes more than one usable binary, the user is prompted to pick
    /// one interactively; a package with a single binary runs it without asking.
    ///
    /// Entrypoints that do not resolve to a regular file inside the package are
    /// never run and never offered in the prompt, whoever asked for them.
    ///
    /// Delegates to [`PackageRunner::run_with`], passing
    /// [`PackageRunner::choose_interactively`] as the entrypoint chooser and
    /// [`trace`] as the tracer - today's behaviour, unchanged. Every existing
    /// caller of `run`, including the ones that assert on its exact numeric
    /// exit codes, keeps working exactly as it does today; the two seams a
    /// daemon needs are additions on `run_with`, not changes here.
    ///
    /// # Errors
    ///
    /// See [`PackageRunner::run_with`].
    pub fn run(&self, bin: Option<String>) -> miette::Result<ExitStatus> {
        self.run_with(bin, Self::choose_interactively, trace)
    }

    /// As [`PackageRunner::run`], but the entrypoint chooser and the profile
    /// tracer are supplied by the caller instead of hard-coded.
    ///
    /// [`PackageRunner::run`] cannot change signature - `tests/landlock.rs`
    /// and every other existing caller depends on calling it exactly as it is
    /// today - so the two seams a daemon needs live here, on a sibling entry
    /// point, and `run` delegates to this method with today's defaults
    /// plugged in.
    ///
    /// - **`choose`** answers "which entrypoint, when `bin` is `None`?" It is
    ///   handed the *declared* names of every usable entrypoint, sorted, and
    ///   must return one of them BY NAME - never a positional index, which
    ///   would be meaningless once the list has been re-derived on the other
    ///   side of a process boundary. [`PackageRunner::run`] passes
    ///   [`PackageRunner::choose_interactively`], which still prompts and
    ///   picks by index internally before translating the answer back to a
    ///   name; a daemon instead passes a closure that already has the
    ///   caller's answer in hand, with nothing to prompt at all. Whichever
    ///   chooser is asked, a name that does not match a usable entrypoint is
    ///   refused with the same diagnostic a bad `--bin` gets - both go
    ///   through the same lookup.
    /// - **`tracer`** replaces the in-process [`trace`] call inside
    ///   [`PackageRunner::audit_run`]. `monitor::supervise` reaps with
    ///   `waitpid(-1, __WALL)`, which would eat a daemon's other children if
    ///   it ran in the daemon's own process; a daemon instead hands in a
    ///   closure that spawns `pm-trace` as a separate process and reports
    ///   back. [`PackageRunner::run`] passes [`trace`] itself, so an
    ///   unmodified `run` traces exactly as it always has.
    ///
    /// # Drop order is unchanged
    ///
    /// This is the same function body [`PackageRunner::run`] used to be
    /// before these two parameters existed: the `workspace`/`SandboxedChild`
    /// declaration order documented below is exactly as load-bearing as it
    /// always was. Injecting a closure changes what runs, not the frame it
    /// runs in - the spawn and the wait are still one call apart, in the same
    /// stack frame, with nothing able to return between the workspace being
    /// created and the child being torn down.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the signature is missing, malformed, does not
    /// verify or comes from an untrusted key; when the staging workspace cannot
    /// be created; when `tar` fails to extract the archive (its exit status and
    /// stderr are surfaced); when the `metadata` member is missing or is not
    /// valid YAML; when the package exposes no usable binary entrypoints; when
    /// `bin` (or `choose`'s answer) names something that is not one of them;
    /// when an entrypoint path is not valid UTF-8; when `choose` itself errors -
    /// including [`PackageRunner::choose_interactively`] finding no terminal to
    /// prompt on, or the user dismissing the prompt; when
    /// [`PackageRunner::enforce`] was asked for but the package records no
    /// profile; or when the sandbox cannot be configured, spawned or waited on.
    ///
    /// A profile that cannot be parsed is reported and treated as absent rather
    /// than failing the run - but then `--enforce` has nothing to apply and
    /// errors, so a broken profile can never quietly become a permissive one.
    pub fn run_with<C, T>(
        &self,
        bin: Option<String>,
        choose: C,
        tracer: T,
    ) -> miette::Result<ExitStatus>
    where
        C: FnOnce(&[&str]) -> miette::Result<String>,
        T: Fn(&Path, &[String], &TraceOptions) -> miette::Result<TraceReport>,
    {
        info!("Running {}", self.path.display());

        // Before `tar` touches it: an archive nobody trusts is not unpacked at
        // all, so a malicious member cannot reach the filesystem even
        // transiently.
        self.verify_signature()?;

        // Declaration order is load-bearing: locals drop in REVERSE declaration
        // order, so the workspace declared here is torn down LAST - after the
        // `SandboxedChild` declared at the bottom of this function has killed and
        // reaped the process. Extracting the package is unlinked out from under a
        // still-running child otherwise.
        let workspace = Workspace::new("run")?;
        // Canonical from the start: every entrypoint check below compares
        // against this prefix, and a `/tmp` that is itself a symlink would make
        // an honest path look like an escape.
        let package_root = workspace
            .path()
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "cannot resolve the staging workspace at {}",
                    workspace.path().display()
                )
            })?;

        // Jailed by default - see `extract` and `extract_jailed`.
        self.extract(&package_root, true)?;

        let metadata_path = package_root.join("metadata");
        let metadata_text = read_to_string(&metadata_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "{} has no `metadata` member; it is not a pm package",
                    self.path.display()
                )
            })?;
        let metadata: Metadata = from_str(&metadata_text)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot parse the metadata of {}", self.path.display()))?;

        let profile = Self::load_profile(&package_root, &metadata_text);
        let entrypoint = Self::pick_entrypoint(&metadata, bin, &package_root, choose)?;
        // The entrypoint as it exists on the host right now. The ELF reader and
        // the `ptrace` monitor both work on the host filesystem, so neither can
        // be handed the in-container path.
        let host_bin = package_root.join(&entrypoint);

        if self.audit {
            if self.enforce {
                warn!(
                    "--enforce is ignored for this run: an audit traces the entrypoint OUTSIDE \
                     the landlock ruleset, which is the only way to see what the ruleset would \
                     have denied"
                );
            }
            match self.audit_run(&host_bin, &package_root, &profile, &tracer) {
                Ok(status) => return Ok(status),
                Err(error) => warn!(
                    %error,
                    "cannot audit this entrypoint; running it normally instead. The profile is \
                     NOT enforced by this fallback"
                ),
            }
        }

        // Enforcement is either what the package recorded or what the caller
        // promoted it to. It is never inferred from the profile's contents.
        let enforcing = self.enforce || profile.enforcement.denies();
        if enforcing && !profile.recorded {
            return Err(miette!(
                help = "run without --enforce, or rebuild the package with a recorded profile",
                "{} records no permission profile, so there is nothing to enforce",
                self.path.display()
            ));
        }

        let container_bin = Path::new(CONTAINER_PACKAGE_ROOT).join(&entrypoint);
        let container_bin = container_bin.to_str().ok_or_else(|| {
            miette!(
                "Entrypoint {} is not valid UTF-8 and cannot be passed to the sandbox",
                entrypoint.display()
            )
        })?;
        let host_root = package_root.to_str().ok_or_else(|| {
            miette!(
                "Workspace path {} is not valid UTF-8 and cannot be bind-mounted",
                package_root.display()
            )
        })?;

        info!("Running entrypoint {container_bin} in a sandbox");

        let mut container = Container::new();
        // A fresh container has an empty mount namespace, so neither the dynamic
        // loader nor the package itself would be reachable. Mount the host's
        // system directories read-only, give the process a minimal /dev, and bind
        // the extracted package read-only on a stable path.
        //
        // `MountFallback` is not optional here: the workspace lives under
        // `TMPDIR`, whose mount flags are locked inside a user namespace. See
        // `package_mount_flags` for why the mount is spelled out by hand rather
        // than going through `bindmount_ro`.
        container
            .rootfs("/")
            .into_diagnostic()?
            .devfsmount("/dev")
            .mount(host_root, CONTAINER_PACKAGE_ROOT, "", package_mount_flags())
            .runctl(Runctl::MountFallback);

        // `rootfs("/")` mirrors only `/bin /etc /lib* /sbin /usr`. On a
        // Nix-provisioned host a package's dynamic loader and every library it
        // needs live under the store instead, and none of those paths are
        // inside that list - so `execve` fails with ENOENT before the program
        // runs at all, and any landlock rule naming a store path refuses
        // because the path does not exist in the container. The build jail in
        // `crate::sandbox` already exposes the store for exactly this reason;
        // the run jail needs it just as much. It is world-readable and
        // immutable by construction, so read-only exposure costs no
        // confinement, and landlock still decides what the package may open.
        if Path::new(NIX_STORE).is_dir() {
            container.mount(NIX_STORE, NIX_STORE, "", package_mount_flags());
            debug!("exposed {NIX_STORE} read-only for a store-linked entrypoint");
        }

        // `Container::new` unshares Mount, User and PID only - a sandboxed
        // package otherwise keeps the caller's full network access. Unsharing
        // the network namespace without configuring a `Network` leaves the
        // process with nothing but a down `lo`.
        if self.network {
            warn!(
                package = %self.path.display(),
                "network access ENABLED; the package SHARES the host network and can exfiltrate anything it reads"
            );
        } else {
            container.unshare(Namespace::Network);
            info!("package runs in its own empty network namespace");
        }

        if enforcing {
            let ruleset = self.ruleset(&profile.permissions, &package_root, &host_bin)?;
            container.landlock_ruleset(ruleset);
            info!(
                grants = profile.permissions.len(),
                "ENFORCING the recorded profile with landlock"
            );
        } else if profile.recorded {
            info!(
                grants = profile.permissions.len(),
                "profile recorded in audit mode; NOT enforced. Run with --audit to see what \
                 enforcing it would deny, then --enforce to apply it"
            );
        } else {
            debug!("package records no permission profile; running with the default sandbox only");
        }

        let mut command = container.command(container_bin);
        command.current_dir(CONTAINER_PACKAGE_ROOT);

        // Declared after `workspace`, therefore dropped before it.
        let child = SandboxedChild::new(command.spawn().into_diagnostic()?, container_bin);
        let status = child.wait()?;

        info!(
            "Entrypoint {container_bin} exited with code {} ({})",
            status.code, status.reason
        );
        Ok(status)
    }

    /// Reads the permission profile the package recorded, from the `metadata`
    /// member or from the [`PROFILE_SIDECAR`] file beside it.
    ///
    /// Never fails: a package with no profile, or with one that does not parse,
    /// gets [`Profile::none`] and a warning. Failing the run instead would make
    /// an unreadable profile *more* permissive than a readable one in every mode
    /// but `--enforce`, which refuses outright - see [`PackageRunner::run`].
    fn load_profile(package_root: &Path, metadata_text: &str) -> Profile {
        match from_str::<Recorded>(metadata_text) {
            Ok(recorded) => {
                if let Some(profile) = recorded.into_profile() {
                    debug!(
                        grants = profile.permissions.len(),
                        enforcement = %profile.enforcement,
                        "profile read from the package metadata"
                    );
                    return profile;
                }
            }
            Err(error) => warn!(
                %error,
                "the package metadata carries a permission profile that does not parse; \
                 treating the package as having none"
            ),
        }

        let sidecar = package_root.join(PROFILE_SIDECAR);
        let Ok(text) = read_to_string(&sidecar) else {
            return Profile::none();
        };

        // The sidecar is either the same `permissions:`/`enforcement:` map the
        // metadata uses, or a bare serialised `Permissions`. Try the richer shape
        // first: a bare set parsed as the map would silently come back empty.
        if let Ok(recorded) = from_str::<Recorded>(&text)
            && let Some(profile) = recorded.into_profile()
        {
            debug!(path = %sidecar.display(), "profile read from the package sidecar");
            return profile;
        }
        match from_str::<Permissions>(&text) {
            Ok(permissions) => {
                debug!(path = %sidecar.display(), "bare permission set read from the sidecar");
                Profile {
                    permissions,
                    // A bare set says nothing about enforcement, and the default
                    // for a set that never went past a human is audit.
                    enforcement: Enforcement::Audit,
                    recorded: true,
                }
            }
            Err(error) => {
                warn!(
                    path = %sidecar.display(),
                    %error,
                    "the recorded profile does not parse; treating the package as having none"
                );
                Profile::none()
            }
        }
    }

    /// Builds the landlock ruleset that enforces `profile` on this entrypoint.
    ///
    /// # Order is load-bearing
    ///
    /// [`Ruleset::restrict`] comes first and [`Ruleset::allow_path`] after.
    /// hakoniwa's loader returns early when `restrictions` is empty, so a ruleset
    /// full of allow rules with nothing restricted enforces **nothing at all**
    /// while looking perfectly configured.
    ///
    /// # Path translation
    ///
    /// Profile paths are host paths, recorded when the profile was derived, but
    /// landlock is applied inside the container *after* the mounts are in place,
    /// so every rule path is resolved there. The container's rootfs is the host's
    /// `/`, so a system path such as `/usr/lib` means the same thing on both
    /// sides and is passed through unchanged. Only the package moves: it is
    /// bind-mounted at [`CONTAINER_PACKAGE_ROOT`], so a path under the staging
    /// root - and a relative path, which can only be package-relative - is
    /// rewritten onto `/pkg`. See [`translate`].
    ///
    /// # Compatibility mode
    ///
    /// `Resource::FS` asks for [`CompatMode::Enforce`]: this is a security
    /// feature, and a kernel too old for landlock should fail the run rather than
    /// run the package unrestricted while reporting success. (hakoniwa ignores
    /// the mode for `FS` and hard-requires landlock ABI v1 regardless, which is
    /// the same fail-closed behaviour; the argument states the intent.) The TCP
    /// resources take [`CompatMode::Relax`] instead, because they need ABI v4 -
    /// kernel 6.7 - and the real guarantee there is the unshared network
    /// namespace, which is already in place. Failing the whole run on an older
    /// kernel would buy nothing.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the package root is not valid UTF-8, since a
    /// landlock rule path must be a `str`.
    fn ruleset(
        &self,
        profile: &Permissions,
        package_root: &Path,
        host_bin: &Path,
    ) -> miette::Result<Ruleset> {
        // Keyed by the in-container path, because hakoniwa stores fs rules in a
        // map keyed by path: adding "/usr" twice keeps only the LAST access mode,
        // so a write grant added after a read grant would drop the read. Merge
        // the modes here and add each path exactly once.
        let mut wanted: BTreeMap<String, FsAccess> = BTreeMap::new();

        for (path, access) in Self::always_allowed(host_bin, package_root) {
            admit(&mut wanted, &path, access, package_root);
        }

        // Read gets R, write gets RW - a write grant must not lose the read a
        // separate read grant would have given, and a write-only file descriptor
        // is not what "may write this path" means in the model. Exec gets R and X
        // because a binary is read as well as executed.
        for path in profile.read_paths() {
            admit(&mut wanted, path, FsAccess::R, package_root);
        }
        for path in profile.write_paths() {
            admit(&mut wanted, path, FsAccess::R | FsAccess::W, package_root);
        }
        for path in profile.exec_paths() {
            admit(&mut wanted, path, FsAccess::R | FsAccess::X, package_root);
        }

        let mut ruleset = Ruleset::default();
        // RESTRICT FIRST. See the section above; the reverse is a silent no-op.
        ruleset.restrict(Resource::FS, CompatMode::Enforce);
        for (path, access) in &wanted {
            debug!(path, access = %access, "landlock rule");
            ruleset.allow_path(path, *access);
        }

        // The namespace decision already made the network unreachable; this
        // closes the same door a second time from inside, so that a future
        // `--allow-network` caller with a profile that does not ask for the
        // network still cannot open a TCP socket. No `allow_tcp_*` rule follows:
        // restricting with an empty rule list is what denies every port.
        if !profile.wants_network() && !self.network {
            ruleset.restrict(Resource::NET_TCP_BIND, CompatMode::Relax);
            ruleset.restrict(Resource::NET_TCP_CONNECT, CompatMode::Relax);
        }

        let _ = package_root
            .to_str()
            .ok_or_else(|| miette!("package root {} is not valid UTF-8", package_root.display()))?;
        Ok(ruleset)
    }

    /// The allowances every enforced run gets, whatever the profile says, as
    /// host paths.
    ///
    /// Without these, `Enforce` means "nothing runs at all", and the failure
    /// looks like a broken package rather than a too-tight profile:
    ///
    /// - **The package root, `r-x`.** `execve` of the entrypoint needs execute on
    ///   the file, and a package that cannot read its own data files is useless.
    ///   The mount is already read-only, so no `w` is needed or wanted.
    /// - **The ELF interpreter, `r-x`.** The kernel maps `PT_INTERP` before the
    ///   program ever gets to run; deny it and every dynamically linked package
    ///   dies before `main`.
    /// - **The directory holding each `DT_NEEDED` library, `r-x`.** The loader
    ///   opens them by soname out of its search path, so the directory that
    ///   actually holds each one is allowed - not the whole search path, and not
    ///   `/usr` wholesale.
    ///
    /// A statically linked entrypoint needs neither of the last two and gets
    /// neither.
    fn always_allowed(host_bin: &Path, package_root: &Path) -> Vec<(PathBuf, FsAccess)> {
        let execute = FsAccess::R | FsAccess::X;
        let mut allowed = vec![(package_root.to_path_buf(), execute)];

        match interpreter(host_bin) {
            Ok(Some(interp)) => allowed.push((PathBuf::from(interp), execute)),
            Ok(None) => debug!("entrypoint names no ELF interpreter; nothing to allow for it"),
            Err(error) => warn!(
                %error,
                "cannot read the entrypoint's ELF interpreter; if it is dynamically linked, \
                 enforcing may stop it from starting"
            ),
        }

        let needed = match needed_libraries(host_bin) {
            Ok(needed) => needed,
            Err(error) => {
                warn!(%error, "cannot read the entrypoint's DT_NEEDED entries");
                Vec::new()
            }
        };
        for directory in library_directories(host_bin, &needed) {
            allowed.push((directory, execute));
        }
        allowed
    }

    /// Runs the entrypoint under the `ptrace` monitor and reports every access
    /// that falls outside the recorded profile.
    ///
    /// This is what "audit" means here, because landlock cannot mean it: see the
    /// module docs. The traced process is **not** in the container - it is
    /// `execve`d by the monitor with the caller's privileges - so this says so at
    /// warn level before starting.
    ///
    /// Each access outside the profile is logged with its syscall and path, and
    /// the summary lists the grants a promotion to [`Enforcement::Enforce`] would
    /// need, in the same shape [`Permissions::report`] prints everywhere else.
    ///
    /// `tracer` runs the traced execution and hands back the report -
    /// [`trace`] itself for [`PackageRunner::run`], or a caller-supplied
    /// closure that runs it out of process. See [`PackageRunner::run_with`]
    /// for why that indirection exists: `monitor::supervise`'s
    /// `waitpid(-1, __WALL)` must never run inside a process with children of
    /// its own that it does not own.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the monitor cannot run at all - it is
    /// x86_64-only, and needs `ptrace` to be permitted. `run` catches that,
    /// reports it and runs the package normally instead; it never upgrades the
    /// profile to `Enforce` to compensate.
    fn audit_run<T>(
        &self,
        host_bin: &Path,
        package_root: &Path,
        profile: &Profile,
        tracer: &T,
    ) -> miette::Result<ExitStatus>
    where
        T: Fn(&Path, &[String], &TraceOptions) -> miette::Result<TraceReport>,
    {
        warn!(
            entrypoint = %host_bin.display(),
            "AUDITING: the entrypoint is traced, NOT jailed. ptrace observes, it does not deny, \
             and this run happens outside the container with your own privileges"
        );
        if !profile.recorded {
            warn!(
                "the package records no profile, so every access below is outside it; the \
                 summary is a starting profile rather than a diff"
            );
        }

        let options = TraceOptions {
            timeout: AUDIT_TIMEOUT,
            // The jailed run starts the entrypoint in the package root, so the
            // audit has to as well: a relative path the program opens resolves
            // differently otherwise, and the audit would describe a run the real
            // sandbox never performs.
            working_dir: Some(package_root.to_path_buf()),
            // Deliberately minimal rather than inherited: an audit that carried
            // the developer's environment would record their machine. `PATH` is
            // kept because a package that spawns a helper by name finds nothing
            // without it, and "it spawned nothing" would be a wrong report.
            env: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
            follow_forks: true,
        };

        let report = tracer(host_bin, &[], &options)?;
        let always = Self::always_allowed(host_bin, package_root);

        let mut outside: Vec<Grant> = Vec::new();
        for observation in report.observations() {
            if !observation.grants()
                || covered(observation.permission(), &profile.permissions, &always)
            {
                continue;
            }
            warn!(
                syscall = observation.syscall(),
                permission = %observation.permission(),
                pid = observation.pid(),
                "access OUTSIDE the recorded profile"
            );
            outside.push(Grant::new(
                observation.permission().clone(),
                Provenance::RuntimeMonitor,
                [observation.evidence()],
            ));
        }

        if report.timed_out() {
            warn!(
                timeout = ?AUDIT_TIMEOUT,
                "the audited run was killed by the timeout, so this report covers only what it \
                 managed to do first"
            );
        }

        if outside.is_empty() {
            info!(
                "audit clean: every access this run made is already inside the recorded profile. \
                 That is evidence about THIS run only - another input can still take a path \
                 nobody watched"
            );
        } else {
            let missing = Permissions::from_grants(outside);
            warn!(
                "{} access(es) fell outside the profile. Promoting to enforce would need these \
                 grants:\n{}",
                missing.len(),
                missing.report()
            );
        }

        Ok(audited_status(&report))
    }

    /// Verifies `<package>.sig` against the trust store, or says loudly that it
    /// was told not to.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the trust store cannot be located or read, or
    /// when the signature is missing, malformed, wrong, or from a key this
    /// installation does not trust.
    fn verify_signature(&self) -> miette::Result<()> {
        if self.unsigned {
            warn!(
                package = %self.path.display(),
                "signature verification DISABLED; running a package of unverified origin"
            );
            return Ok(());
        }

        let trust_dir = match &self.trust_dir {
            Some(dir) => dir.clone(),
            None => default_trust_dir()?,
        };
        let trust = TrustStore::load(&trust_dir)?;
        verify_file(&self.path, &trust).wrap_err_with(|| {
            format!(
                "refusing to extract {}: its signature does not check out",
                self.path.display()
            )
        })?;

        info!(
            package = %self.path.display(),
            trust_dir = %trust_dir.display(),
            "signature verified"
        );
        Ok(())
    }

    /// Extracts the archive into `dest`, jailed by default.
    ///
    /// `jailed` is a parameter of this one call, not a setting on
    /// [`PackageRunner`]: [`PackageRunner::run_with`] always passes `true`, and
    /// there is deliberately no builder flag or environment variable that
    /// could flip it for every extraction in a process at once. The only case
    /// the unjailed path exists for is a host where the container itself
    /// cannot even start - no unprivileged user namespaces, no landlock, a
    /// kernel too old - and that is a decision a caller makes once, per call,
    /// never a standing opt-out a hostile archive could rely on finding
    /// already set.
    ///
    /// # Errors
    ///
    /// See [`PackageRunner::extract_jailed`] and
    /// [`PackageRunner::extract_unjailed`].
    fn extract(&self, dest: &Path, jailed: bool) -> miette::Result<()> {
        if jailed {
            self.extract_jailed(dest)
        } else {
            self.extract_unjailed(dest)
        }
    }

    /// Extracts the archive inside a fresh `hakoniwa` container, so a hostile
    /// member - a `../` traversal, an absolute path - lands nowhere but `dest`
    /// even if `tar` itself falls for it.
    ///
    /// [`PackageRunner::verify_signature`] runs before this and stops an
    /// *untrusted* archive from being unpacked at all, but `--unsigned`
    /// exists, and nothing stops a *trusted* archive from being hostile too -
    /// `tar` has had real path-traversal bugs, and the signature says nothing
    /// about which version is installed. `tar` gets exactly two mounts here -
    /// the archive read-only at [`EXTRACT_ARCHIVE_MOUNT`], `dest` writable at
    /// [`EXTRACT_DEST_MOUNT`] - plus the host's system directories so it can
    /// actually run, and the network namespace is unshared unconditionally:
    /// unlike [`PackageRunner::allow_network`], nothing about extracting an
    /// archive ever needs a network. A `tar` that resolves a traversal member
    /// can still only reach those two mounted paths.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when `tar` cannot be located on `PATH`, when the
    /// archive or `dest` is not valid UTF-8, when the container cannot be
    /// configured or spawned, or when `tar` exits unsuccessfully - in which
    /// case its exit status and captured stderr are reported.
    fn extract_jailed(&self, dest: &Path) -> miette::Result<()> {
        let archive = self
            .path
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot resolve {} to extract it", self.path.display()))?;
        let archive_str = archive.to_str().ok_or_else(|| {
            miette!(
                "archive path {} is not valid UTF-8 and cannot be mounted into the extraction jail",
                archive.display()
            )
        })?;
        let dest_str = dest.to_str().ok_or_else(|| {
            miette!(
                "destination path {} is not valid UTF-8 and cannot be mounted into the extraction jail",
                dest.display()
            )
        })?;
        let tar = locate_tar()?;
        let tar_str = tar.to_str().ok_or_else(|| {
            miette!(
                "`tar` resolved to {}, which is not valid UTF-8",
                tar.display()
            )
        })?;

        let mut container = Container::new();
        // Same shape as the run jail below: mirror the host's system
        // directories read-only so `tar` and its dynamic loader can actually
        // run, then bind the two paths this extraction is allowed to touch.
        // `MountFallback` matches `package_mount_flags`'s reasoning - both
        // mounts live under `TMPDIR`, whose flags are locked inside a user
        // namespace.
        container
            .rootfs("/")
            .into_diagnostic()
            .wrap_err("cannot mirror the host system directories into the extraction jail")?
            .devfsmount("/dev")
            .mount(
                archive_str,
                EXTRACT_ARCHIVE_MOUNT,
                "",
                package_mount_flags(),
            )
            .mount(dest_str, EXTRACT_DEST_MOUNT, "", extraction_dest_flags())
            .runctl(Runctl::MountFallback)
            .unshare(Namespace::Network);

        // Same reasoning as the run jail: a Nix-provisioned `tar` and its
        // dynamic loader live under the store, not under `/usr`.
        if Path::new(NIX_STORE).is_dir() {
            container.mount(NIX_STORE, NIX_STORE, "", package_mount_flags());
        }

        let output = container
            .command(tar_str)
            .arg("-xpf")
            .arg(EXTRACT_ARCHIVE_MOUNT)
            .arg("-C")
            .arg(EXTRACT_DEST_MOUNT)
            .stdin(Stdio::from(devnull()?))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "cannot run `tar` inside the extraction jail for {}",
                    self.path.display()
                )
            })?;

        if !output.status.success() {
            return Err(miette!(
                "tar failed to extract {} into {} ({}): {}",
                self.path.display(),
                dest.display(),
                output.status.reason,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    /// Extracts the archive with an unsandboxed `tar`, at this process's own
    /// privileges.
    ///
    /// **Not the default** - see [`PackageRunner::extract`] for when this is
    /// the right call instead of [`PackageRunner::extract_jailed`].
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when `tar` cannot be spawned, or when it exits
    /// unsuccessfully - in which case its exit status and stderr are reported.
    fn extract_unjailed(&self, dest: &Path) -> miette::Result<()> {
        let output = Command::new("tar")
            .arg("-xpf")
            .arg(&self.path)
            .arg("-C")
            .arg(dest)
            .output()
            .into_diagnostic()?;

        if !output.status.success() {
            return Err(miette!(
                "tar failed to extract {} into {} ({}): {}",
                self.path.display(),
                dest.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    /// Resolves `bin` against the binary entrypoints of `metadata`, calling
    /// `choose` for the answer when `bin` is `None`.
    ///
    /// Both `bin` and the entrypoint table are attacker-controlled - `bin`
    /// comes from the command line (or, through [`PackageRunner::run_with`],
    /// from whatever a caller passed) and the table ships inside the package -
    /// so the answer is always one of the entrypoints that
    /// [`PackageRunner::resolve_entrypoint`] accepted. Entrypoints it rejects
    /// are logged and dropped: they are never matched against `bin` and never
    /// passed to `choose`.
    ///
    /// `choose` is handed the *declared* names of the usable entrypoints,
    /// sorted, and must answer with one of them BY NAME. Whatever it returns
    /// goes through the exact same lookup `bin` does, so a chooser's wrong
    /// answer is refused with the exact same diagnostic a bad `--bin` is.
    ///
    /// The returned path is package-relative and symlink-resolved, ready to be
    /// joined onto [`CONTAINER_PACKAGE_ROOT`].
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the package declares no binary entrypoints,
    /// when none of the ones it declares resolve inside the package, when
    /// `bin` or `choose`'s answer matches none of the usable ones, or when
    /// `choose` itself errors.
    fn pick_entrypoint<C>(
        metadata: &Metadata,
        bin: Option<String>,
        package_root: &Path,
        choose: C,
    ) -> miette::Result<PathBuf>
    where
        C: FnOnce(&[&str]) -> miette::Result<String>,
    {
        // Entrypoints live in a HashMap, whose iteration order is not stable;
        // sort so the prompt and the error listing are reproducible. This is one
        // of the few collects that has to stay: the list is walked twice and the
        // prompt answers with a *position*, which an iterator cannot be indexed
        // by. It holds `&Path`, so it is one pointer-sized push per entrypoint.
        let mut declared: Vec<&Path> = metadata.binaries().collect();
        declared.sort_unstable();

        if declared.is_empty() {
            return Err(miette!(
                "Package {} exposes no binary entrypoints",
                metadata.name()
            ));
        }

        let usable: Vec<Entrypoint<'_>> = declared
            .iter()
            .copied()
            .filter_map(|path| match Self::resolve_entrypoint(package_root, path) {
                Ok(resolved) => Some(Entrypoint {
                    declared: path,
                    resolved,
                }),
                Err(error) => {
                    warn!(
                        entrypoint = %path.display(),
                        package = metadata.name(),
                        "ignoring an entrypoint that does not resolve inside the package: {error}"
                    );
                    None
                }
            })
            .collect();

        if usable.is_empty() {
            return Err(miette!(
                "Package {} declares {} binary entrypoint(s), but none of them resolve to a file inside the package",
                metadata.name(),
                declared.len()
            ));
        }

        let wanted = match bin {
            Some(wanted) => wanted,
            None => {
                // Owned labels first, because `choose` only borrows for the
                // length of this call and the closure may want to keep its
                // answer past it.
                let labels: Vec<String> = usable
                    .iter()
                    .map(|entry| entry.declared.display().to_string())
                    .collect();
                let names: Vec<&str> = labels.iter().map(String::as_str).collect();
                choose(&names)?
            }
        };

        usable
            .iter()
            .find(|entry| {
                entry.declared.as_os_str() == wanted.as_str()
                    || entry
                        .declared
                        .file_name()
                        .is_some_and(|name| name == wanted.as_str())
            })
            .map(|entry| entry.resolved.clone())
            .ok_or_else(|| {
                miette!(
                    "{wanted} is not a binary entrypoint of {}. Available: {}",
                    metadata.name(),
                    Self::describe(&usable)
                )
            })
    }

    /// Checks that `declared` names a regular file that really lives inside
    /// `package_root`, and returns its package-relative, symlink-resolved path.
    ///
    /// `package_root` must already be canonical. Two independent checks, because
    /// neither one alone is enough:
    ///
    /// - Every component must be [`Component::Normal`]. That rejects `..`, `.`,
    ///   a leading `/` and a Windows-style prefix in a single test, and it
    ///   rejects them *before* anything touches the filesystem.
    /// - The joined path is then canonicalised and must still start with
    ///   `package_root`. Canonicalising resolves symlinks, which the component
    ///   check cannot: a package is free to ship `bin/tool` as a symlink to
    ///   `/usr/bin/curl`, and that path has none but normal components.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the path is empty, when it has a component
    /// that is not a plain name, when it does not exist, when it resolves
    /// outside the package, or when it is not a regular file.
    fn resolve_entrypoint(package_root: &Path, declared: &Path) -> miette::Result<PathBuf> {
        if declared.as_os_str().is_empty() {
            return Err(miette!("an entrypoint path cannot be empty"));
        }

        for component in declared.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(miette!(
                    "entrypoint {} must be a plain package-relative path, but it contains `{}`",
                    declared.display(),
                    Path::new(component.as_os_str()).display()
                ));
            }
        }

        let host = package_root.join(declared);
        let resolved = host.canonicalize().into_diagnostic().wrap_err_with(|| {
            format!(
                "entrypoint {} does not exist in the extracted package at {}",
                declared.display(),
                package_root.display()
            )
        })?;

        let relative = resolved.strip_prefix(package_root).map_err(|_| {
            miette!(
                "entrypoint {} escapes the package: it resolves to {}, which is outside {}",
                declared.display(),
                resolved.display(),
                package_root.display()
            )
        })?;

        if !resolved.is_file() {
            return Err(miette!(
                "entrypoint {} is not a regular file",
                declared.display()
            ));
        }

        Ok(relative.to_path_buf())
    }

    /// Asks the user which of `binaries` to run, answering with its declared
    /// name - the shape [`PackageRunner::pick_entrypoint`] requires of every
    /// chooser, interactive or not.
    ///
    /// `binaries` is expected to be non-empty and already sorted, so the menu
    /// entries keep the same order from one invocation to the next. A package
    /// with a single binary is not worth a prompt, so that one is chosen
    /// outright. The prompt itself still answers with a position - `Select`
    /// has no other mode - but that index only ever lives inside this
    /// function; what it returns to its caller is the name at that position,
    /// never the index itself.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when stdin is not a terminal - in which case there
    /// is nobody to answer the prompt and the available binaries are listed
    /// instead - when the user dismisses the prompt, or when the prompt itself
    /// fails.
    fn choose_interactively(binaries: &[&str]) -> miette::Result<String> {
        if let [only] = binaries {
            info!("{only} is the only binary entrypoint; running it without prompting");
            return Ok((*only).to_owned());
        }

        // `Select` reads keys straight off the terminal, so with a pipe or
        // /dev/null on stdin it can only fail. Say what the user can do about
        // it rather than letting dialoguer report a bare "not a terminal".
        if !stdin().is_terminal() {
            return Err(miette!(
                "Cannot prompt for a binary because stdin is not a terminal; pass --bin <NAME> to pick one of: {}",
                binaries.join(", ")
            ));
        }

        // `interact_opt` turns Esc and 'q' into `Ok(None)` instead of an error.
        let selection = Select::new()
            .with_prompt("Select which binary to run")
            .items(binaries)
            .default(0)
            .interact_opt();

        // dialoguer hides the cursor for the duration of the prompt and only
        // shows it again on the paths it returns from itself; when the prompt
        // fails part-way through, the cursor stays hidden and corrupts the shell
        // the user drops back into. `show_cursor` is idempotent, so run it on
        // every outcome and ignore its own I/O error - there is nothing useful
        // to report if the terminal is already gone.
        //
        // Ctrl-C is deliberately NOT covered here, because it cannot be: console
        // (`console::unix_term`) turns a read of \x03 into `libc::raise(SIGINT)`
        // against this process, and the default disposition terminates it before
        // any code below runs. Restoring the cursor there needs a SIGINT handler,
        // which needs a dependency this crate does not have.
        let _ = Term::stdout().show_cursor();

        let index = selection
            .into_diagnostic()
            .wrap_err("The interactive binary prompt failed")?
            .ok_or_else(|| {
                miette!(
                    "No binary selected; pass --bin <NAME> to run one of: {}",
                    binaries.join(", ")
                )
            })?;

        binaries
            .get(index)
            .map(|name| (*name).to_owned())
            .ok_or_else(|| miette!("The prompt returned index {index}, which is out of range"))
    }

    /// Renders entrypoint paths as a comma-separated list for diagnostics.
    ///
    /// The *declared* paths are listed, because those are the names `--bin`
    /// matches against.
    fn describe(binaries: &[Entrypoint<'_>]) -> String {
        binaries
            .iter()
            .map(|entry| entry.declared.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A binary entrypoint that survived validation.
///
/// `declared` is what the package metadata said, and is what `--bin` and the
/// prompt show. `resolved` is the package-relative path it actually resolves to
/// with symlinks followed, and is the only path ever handed to the sandbox.
struct Entrypoint<'a> {
    declared: &'a Path,
    resolved: PathBuf,
}

/// The run-time profile a package recorded: what it may do, and whether that is
/// enforced.
///
/// `recorded` distinguishes "the package says it needs nothing" from "the package
/// says nothing". The first is enforceable; the second is not, and `--enforce`
/// refuses it rather than denying the package everything outside its own root.
#[derive(Debug, Clone)]
struct Profile {
    permissions: Permissions,
    enforcement: Enforcement,
    recorded: bool,
}

impl Profile {
    /// The profile of a package that records none: no grants, audit, and known
    /// to be absent.
    fn none() -> Self {
        Self {
            permissions: Permissions::default(),
            enforcement: Enforcement::Audit,
            recorded: false,
        }
    }
}

/// The profile as it is deserialised, wherever it was written.
///
/// Spelled as its own type rather than read through [`Metadata`] so that the
/// shape of the recording and the shape of the metadata can move independently:
/// unknown fields are ignored by serde, so this parses the `metadata` member
/// whether or not the profile is in it, and parses a sidecar file that holds
/// nothing else. The aliases accept the spellings a recorder is likely to use.
#[derive(Debug, Deserialize)]
struct Recorded {
    #[serde(default, alias = "profile", alias = "perms")]
    permissions: Option<Permissions>,
    #[serde(default, alias = "mode", alias = "enforcement_mode")]
    enforcement: Option<Enforcement>,
}

impl Recorded {
    /// The profile this recording describes, or `None` when it holds no
    /// permission set at all.
    fn into_profile(self) -> Option<Profile> {
        let permissions = self.permissions?;
        Some(Profile {
            permissions,
            // Absent means audit: the default a derived profile carries, and the
            // one that does not deny. A recording that forgot to say must not be
            // read as a promotion.
            enforcement: self.enforcement.unwrap_or_default(),
            recorded: true,
        })
    }
}

/// Finds `tar` on `PATH`, canonicalised to an absolute path.
///
/// `hakoniwa` execs the program path directly with no `PATH` search of its
/// own - the same constraint `crate::sandbox::BuildSandbox::resolve` works
/// around on the build side - so [`PackageRunner::extract_jailed`] cannot
/// rely on `execvp`'s own search the way the unjailed
/// [`PackageRunner::extract_unjailed`] does; this does the same search by
/// hand instead, over the same `PATH` a plain `Command::new("tar")` would
/// have consulted.
///
/// # Errors
///
/// Returns a diagnostic when `PATH` is unset, or names no executable `tar`.
fn locate_tar() -> miette::Result<PathBuf> {
    let path = env::var_os("PATH").ok_or_else(|| {
        miette!("cannot extract the package: PATH is not set, so `tar` cannot be located")
    })?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join("tar");
        if candidate.is_file() {
            return candidate
                .canonicalize()
                .into_diagnostic()
                .wrap_err_with(|| format!("cannot resolve `{}`", candidate.display()));
        }
    }
    Err(miette!(
        "cannot extract the package: `tar` was not found on PATH"
    ))
}

/// Open `/dev/null` for the jailed `tar`'s stdin.
///
/// `tar -xpf` never reads stdin, but leaving it inherited would hand a jailed
/// process the caller's own terminal for no reason.
fn devnull() -> miette::Result<File> {
    File::open("/dev/null")
        .into_diagnostic()
        .wrap_err("cannot open /dev/null for tar's stdin inside the extraction jail")
}

/// Adds one host path to the rule map under its in-container name, merging the
/// access mode with whatever is already there.
///
/// Paths that cannot be translated, and paths that do not exist at run time, are
/// dropped with a log line. Dropping the second kind is not optional: hakoniwa
/// canonicalises every rule path inside the container and fails the *whole*
/// container when one is missing, so a single stale grant - a build-machine path
/// that is not on this machine - would stop the package from running at all.
fn admit(
    wanted: &mut BTreeMap<String, FsAccess>,
    host: &Path,
    access: FsAccess,
    package_root: &Path,
) {
    let Some(rule) = translate(host, package_root) else {
        warn!(path = %host.display(), "ignoring a grant whose path cannot be mapped into the sandbox");
        return;
    };
    if !rule.host.exists() {
        debug!(
            path = %host.display(),
            "ignoring a grant for a path that does not exist on this machine"
        );
        return;
    }
    *wanted.entry(rule.container).or_insert(FsAccess::empty()) |= access;
}

/// One rule path in both the namespaces that matter.
struct Rule {
    /// The path landlock is given, resolved inside the container.
    container: String,
    /// The same file as this process can see it, used to check that it exists at
    /// all before the rule is added.
    host: PathBuf,
}

/// Maps a recorded path to the path it has inside the container.
///
/// Three cases, and the middle one is the one that matters:
///
/// - **Relative.** Can only be package-relative - nothing else would have been
///   recorded without a root - so it hangs off [`CONTAINER_PACKAGE_ROOT`].
/// - **Under the staging root.** The package is bind-mounted at
///   [`CONTAINER_PACKAGE_ROOT`], and the staging directory itself does not exist
///   inside the container. A rule left as the host path would fail to resolve
///   and take the whole run down with it.
/// - **Anything else.** The container's rootfs *is* the host's `/`, so `/usr`,
///   `/etc` and friends name the same files on both sides and are passed through
///   untouched. Rewriting those onto `/pkg` would allow a path that does not
///   exist instead of the one the profile asked for.
///
/// Returns `None` for a path that is not valid UTF-8 - landlock rule paths are
/// `str` - or that still contains a `..` component, which cannot be reasoned
/// about lexically and must not be guessed at in a security decision.
fn translate(host: &Path, package_root: &Path) -> Option<Rule> {
    if host
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }

    let (container, host) = match host.strip_prefix(package_root) {
        Ok(relative) => (
            Path::new(CONTAINER_PACKAGE_ROOT).join(relative),
            package_root.join(relative),
        ),
        Err(_) if host.is_relative() => (
            Path::new(CONTAINER_PACKAGE_ROOT).join(host),
            package_root.join(host),
        ),
        Err(_) => (host.to_path_buf(), host.to_path_buf()),
    };
    Some(Rule {
        container: container.to_str()?.to_owned(),
        host,
    })
}

/// Whether `parent` is `child` or an ancestor of it.
///
/// Component-wise through [`Path::starts_with`], never a string prefix:
/// `/usrlocal` starts with the text `/usr` without being under it, and a textual
/// test would call an access covered that the ruleset would deny. A `..`
/// component on either side makes the answer unknowable without the run-time
/// filesystem, so it is reported as not covered - the direction that over-reports
/// in an audit rather than under-reporting.
fn under(parent: &Path, child: &Path) -> bool {
    let plain = |path: &Path| {
        !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    };
    plain(parent) && plain(child) && child.starts_with(parent)
}

/// Whether an observed access is already inside what an enforced run would allow.
///
/// The comparison is against the ruleset that would actually be built, which is
/// the profile *plus* the unconditional allowances - otherwise an audit would
/// report the dynamic loader as a violation on every single run and bury the
/// findings that matter.
///
/// The access mapping mirrors [`PackageRunner::ruleset`] exactly: every path
/// grant carries read, so a read is covered by a read, write or exec grant; a
/// write needs a write grant; an exec needs an exec grant.
fn covered(permission: &Permission, profile: &Permissions, always: &[(PathBuf, FsAccess)]) -> bool {
    let always_covers = |path: &Path, access: FsAccess| {
        always
            .iter()
            .any(|(root, mode)| mode.contains(access) && under(root, path))
    };

    match permission {
        Permission::Network => profile.wants_network(),
        Permission::Spawn => profile.wants_spawn(),
        Permission::ReadPath(path) => {
            always_covers(path, FsAccess::R)
                || profile
                    .read_paths()
                    .chain(profile.write_paths())
                    .chain(profile.exec_paths())
                    .any(|granted| under(granted, path))
        }
        Permission::WritePath(path) => {
            always_covers(path, FsAccess::W)
                || profile.write_paths().any(|granted| under(granted, path))
        }
        Permission::ExecPath(path) => {
            always_covers(path, FsAccess::X)
                || profile.exec_paths().any(|granted| under(granted, path))
        }
    }
}

/// The directories that actually hold the libraries `needed` names.
///
/// A `DT_NEEDED` entry is a soname, not a path, so the file behind it is found
/// the way the loader would: `DT_RUNPATH` first - with `$ORIGIN` expanded to the
/// entrypoint's own directory, which is how a package refers to the libraries it
/// ships - then the default search directories.
///
/// A soname that is found nowhere makes every *existing* default directory
/// allowed instead. That is wider than wanted, and it is still the right trade:
/// the alternative is an enforced package that cannot start, with a failure that
/// looks nothing like "the profile was too tight".
fn library_directories(host_bin: &Path, needed: &[String]) -> Vec<PathBuf> {
    if needed.is_empty() {
        return Vec::new();
    }

    let origin = host_bin.parent().unwrap_or(Path::new("."));
    let mut search: Vec<PathBuf> = match runpath(host_bin) {
        Ok(entries) => entries
            .iter()
            .map(|entry| PathBuf::from(entry.replace("$ORIGIN", &origin.to_string_lossy())))
            .collect(),
        Err(error) => {
            warn!(%error, "cannot read the entrypoint's DT_RUNPATH");
            Vec::new()
        }
    };
    search.extend(DEFAULT_LIBRARY_DIRS.iter().map(PathBuf::from));

    let mut found: Vec<PathBuf> = Vec::new();
    let mut unresolved = 0usize;
    for soname in needed {
        match search
            .iter()
            .find(|directory| directory.join(soname).exists())
        {
            Some(directory) => {
                if !found.contains(directory) {
                    found.push(directory.clone());
                }
            }
            None => {
                unresolved += 1;
                warn!(
                    soname,
                    "cannot locate a needed library in any search directory"
                );
            }
        }
    }

    if unresolved > 0 {
        warn!(
            unresolved,
            "allowing every default library directory, because an entrypoint whose loader \
             cannot find a library does not start at all"
        );
        for directory in DEFAULT_LIBRARY_DIRS.map(PathBuf::from) {
            if directory.exists() && !found.contains(&directory) {
                found.push(directory);
            }
        }
    }
    found
}

/// Turns a trace report into the exit status `run` returns.
///
/// An audited run is still a run, so its exit code is the entrypoint's. A run
/// that never exited on its own - killed by the timeout or by a signal - reports
/// [`AUDIT_UNFINISHED`] rather than borrowing a code the program never produced.
fn audited_status(report: &crate::perms::monitor::TraceReport) -> ExitStatus {
    let (code, reason) = match report.exit_status() {
        Some(code) => (code, format!("audited entrypoint exited with code {code}")),
        None if report.timed_out() => (
            AUDIT_UNFINISHED,
            format!("audited entrypoint was killed after {AUDIT_TIMEOUT:?}"),
        ),
        None => (
            AUDIT_UNFINISHED,
            "audited entrypoint did not exit on its own".to_owned(),
        ),
    };
    ExitStatus {
        code,
        reason,
        exit_code: report.exit_status(),
        rusage: None,
        proc_pid_smaps_rollup: None,
        proc_pid_status: None,
    }
}
