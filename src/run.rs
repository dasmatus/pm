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

use std::{
    fs::read_to_string,
    io::{IsTerminal, stdin},
    path::{Component, Path, PathBuf},
    process::Command,
};

use crate::{
    metadata::Metadata,
    signing::{TrustStore, default_trust_dir, verify_file},
    workspace::{SandboxedChild, Workspace},
};
use dialoguer::{Select, console::Term};
use hakoniwa::{Container, ExitStatus, MountOptions, Namespace, Runctl};
use miette::{Context, IntoDiagnostic, miette};
use serde_yaml::from_str;
use tracing::{info, warn};

/// Path the extracted package tree is bind-mounted on inside the sandbox.
///
/// The host-side staging directory is a throwaway temporary path, so entrypoints
/// are always invoked through this stable in-container path instead.
const CONTAINER_PACKAGE_ROOT: &str = "/pkg";

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
    /// # Errors
    ///
    /// Returns a diagnostic when the signature is missing, malformed, does not
    /// verify or comes from an untrusted key; when the staging workspace cannot
    /// be created; when `tar` fails to extract the archive (its exit status and
    /// stderr are surfaced); when the `metadata` member is missing or is not
    /// valid YAML; when the package exposes no usable binary entrypoints; when
    /// `bin` names something that is not one of them; when an entrypoint path is
    /// not valid UTF-8; when a binary has to be picked but there is no terminal
    /// to prompt on; when the user dismisses the prompt; or when the sandbox
    /// cannot be configured, spawned or waited on.
    pub fn run(&self, bin: Option<String>) -> miette::Result<ExitStatus> {
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

        self.extract(&package_root)?;

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

        let entrypoint = Self::pick_entrypoint(&metadata, bin, &package_root)?;

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

    /// Extracts the archive into `dest` with `tar`.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when `tar` cannot be spawned, or when it exits
    /// unsuccessfully - in which case its exit status and stderr are reported.
    fn extract(&self, dest: &Path) -> miette::Result<()> {
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

    /// Resolves `bin` against the binary entrypoints of `metadata`, prompting
    /// the user when `bin` is `None`.
    ///
    /// Both inputs are attacker-controlled - `bin` comes from the command line
    /// and the entrypoint table ships inside the package - so the answer is
    /// always one of the entrypoints that [`PackageRunner::resolve_entrypoint`]
    /// accepted. Entrypoints it rejects are logged and dropped: they are never
    /// matched against `bin` and never offered in the prompt.
    ///
    /// The returned path is package-relative and symlink-resolved, ready to be
    /// joined onto [`CONTAINER_PACKAGE_ROOT`].
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the package declares no binary entrypoints,
    /// when none of the ones it declares resolve inside the package, when `bin`
    /// matches none of the usable ones, when there is no terminal to prompt on,
    /// or when the user cancels the prompt.
    fn pick_entrypoint(
        metadata: &Metadata,
        bin: Option<String>,
        package_root: &Path,
    ) -> miette::Result<PathBuf> {
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

        let chosen = match bin {
            Some(wanted) => usable
                .iter()
                .find(|entry| {
                    entry.declared.as_os_str() == wanted.as_str()
                        || entry
                            .declared
                            .file_name()
                            .is_some_and(|name| name == wanted.as_str())
                })
                .ok_or_else(|| {
                    miette!(
                        "{wanted} is not a binary entrypoint of {}. Available: {}",
                        metadata.name(),
                        Self::describe(&usable)
                    )
                })?,
            None => Self::choose_interactively(&usable)?,
        };

        Ok(chosen.resolved.clone())
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

    /// Asks the user which of `binaries` to run.
    ///
    /// `binaries` is expected to be non-empty and already sorted, so the menu
    /// entries keep the same order from one invocation to the next. A package
    /// with a single binary is not worth a prompt, so that one is chosen
    /// outright.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when stdin is not a terminal - in which case there
    /// is nobody to answer the prompt and the available binaries are listed
    /// instead - when the user dismisses the prompt, or when the prompt itself
    /// fails.
    fn choose_interactively<'a, 'b>(
        binaries: &'a [Entrypoint<'b>],
    ) -> miette::Result<&'a Entrypoint<'b>> {
        if let [only] = binaries {
            info!(
                "{} is the only binary entrypoint; running it without prompting",
                only.declared.display()
            );
            return Ok(only);
        }

        // `Select` reads keys straight off the terminal, so with a pipe or
        // /dev/null on stdin it can only fail. Say what the user can do about
        // it rather than letting dialoguer report a bare "not a terminal".
        if !stdin().is_terminal() {
            return Err(miette!(
                "Cannot prompt for a binary because stdin is not a terminal; pass --bin <NAME> to pick one of: {}",
                Self::describe(binaries)
            ));
        }

        let labels: Vec<String> = binaries
            .iter()
            .map(|entry| entry.declared.display().to_string())
            .collect();
        // `interact_opt` turns Esc and 'q' into `Ok(None)` instead of an error.
        let selection = Select::new()
            .with_prompt("Select which binary to run")
            .items(&labels)
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
                    Self::describe(binaries)
                )
            })?;

        binaries
            .get(index)
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
