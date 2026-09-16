//! Build-file parsing, building and packaging.
//!
//! A build file is read **before** anything it describes is run: its steps are
//! matched against the built-in fingerprint table of [`crate::policy`], and the
//! resulting [`BuildPolicy`] decides what the jail the steps run in is allowed
//! to reach. A build file that is not signed by a trusted key is not read at
//! all - see [`BuildFile::load`].
//!
//! Once the steps have run, a *second* and quite separate profile is derived:
//! [`BuildFile::derive_permissions`] infers what the **resulting package** needs
//! at run time and records it in the package metadata. [`BuildPolicy`] governs
//! the build; [`crate::perms::Permissions`] governs the thing the build
//! produced. The two are never interchangeable.

use std::{
    collections::HashMap,
    env::current_dir,
    fs::{copy, create_dir_all, read_to_string, write},
    iter::once,
    path::{Path, PathBuf},
    process::Command,
};

use miette::{IntoDiagnostic, WrapErr, miette};
use serde::{Deserialize, Serialize};
use serde_yaml::{Value, from_str, to_string, to_value};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::{
    metadata::{Metadata, Type},
    perms::{Enforcement, Permissions, elf, source},
    policy::BuildPolicy,
    sandbox::BuildSandbox,
    signing::{TrustStore, default_trust_dir, verify_file},
    step::{Stage, Step},
    workspace::Workspace,
};

/// The key the policy fingerprint is written under in the package `metadata`
/// file.
const POLICY_FINGERPRINT_KEY: &str = "policy_fingerprint";

/// How a [`BuildFile`] came to be trusted.
///
/// Carried on the value rather than passed around, because it has to survive
/// into the recursive dependency build: a build file loaded through the
/// unverified escape hatch must not silently start demanding signatures of its
/// dependencies, and one loaded properly must never stop.
#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy, PartialEq, Eq)]
enum Verification {
    /// No signature was checked. Only reachable through
    /// [`BuildFile::load_unverified`] or by deserialising a value directly.
    #[default]
    Unverified,
    /// A detached `.sig` was verified against the local trust store.
    Signed,
}

/// Knobs [`BuildFile::run_with`] takes, all of which default to the safe answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuildOptions {
    /// Allow step commands that match no built-in fingerprint.
    ///
    /// The default, `false`, aborts the build before a single step runs when a
    /// command cannot be classified, because an unclassified command is one
    /// whose sandbox requirements nobody knows.
    pub permissive: bool,
    /// Run the steps straight on the host instead of inside the jail.
    ///
    /// A debugging escape hatch for a build the sandbox breaks. It hands the
    /// build file the calling user's full access to `$HOME`, the network and
    /// every file they can reach, and says so loudly in the log.
    pub unsandboxed: bool,
}

/// A parsed build file: everything needed to build and package one package.
#[derive(Serialize, Deserialize, Default)]
pub struct BuildFile {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
    steps: Vec<Step>,

    /// Canonical path this build file was loaded from, used to seed cycle
    /// detection. Never serialised: it is a property of the file on disk, not
    /// of its contents.
    #[serde(skip)]
    source: Option<PathBuf>,

    /// Whether the file this was parsed from carried a trusted signature.
    /// Never serialised, for the same reason as `source`.
    #[serde(skip)]
    verification: Verification,
}

impl BuildFile {
    /// Build a skeleton build file, meant to be serialised as a starting point
    /// for a new package.
    ///
    /// The skeleton is deliberately buildable as it stands: `pm build` on a
    /// freshly generated file succeeds and produces an empty package. That
    /// rules out a placeholder dependency path, which `pm build` would reject
    /// as "not a build file" before running anything - the first thing a new
    /// user would see. Fill in `dependencies` and `run` to make it do work.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            name: "example".into(),
            version: vec!["0".into(), "1".into(), "0".into()],
            dependencies: Vec::new(),
            steps: vec![Step {
                stage: Stage::Prepare,
                dl_urls: Some(HashMap::new()),
                name: "fetch".into(),
                run: Vec::new(),
            }],
            source: None,
            verification: Verification::Unverified,
        }
    }

    /// Parse a signed build file from YAML on disk.
    ///
    /// The detached signature at `<path>.sig` is verified against the local
    /// trust store **before** the file is parsed, and every dependency loaded
    /// out of this one is held to the same standard. A build file is a program:
    /// it names the commands that will run, so reading an unsigned one is
    /// already the interesting half of running it.
    ///
    /// # Errors
    ///
    /// Fails if the trust store cannot be located or read, if `<path>.sig` is
    /// missing, malformed, signed by a key this installation does not trust or
    /// does not verify against the file, if `path` cannot be read, or if it
    /// does not contain a valid build file.
    pub fn load(path: &Path) -> miette::Result<Self> {
        verify_signature(path)?;
        Self::parse(path, Verification::Signed)
    }

    /// Parse a build file **without checking its signature**.
    ///
    /// For tests and for debugging a build file that has not been signed yet.
    /// It is not a smaller version of [`BuildFile::load`]: nothing here
    /// establishes who wrote the commands that are about to run, and the
    /// dependencies this build file pulls in are loaded the same way. Prefer
    /// signing the file with `pm sign` and using [`BuildFile::load`].
    ///
    /// # Errors
    ///
    /// Fails if `path` cannot be read or does not contain a valid build file.
    pub fn load_unverified(path: &Path) -> miette::Result<Self> {
        warn!(
            file = %path.display(),
            "loading a build file WITHOUT verifying its signature; the commands in it, and in \
             every dependency it names, will run without anyone having vouched for them"
        );
        Self::parse(path, Verification::Unverified)
    }

    /// Build every dependency, build this package, and package the result.
    ///
    /// Steps run confined, and a command that matches no built-in fingerprint
    /// aborts the build. [`BuildFile::run_with`] relaxes either of those.
    ///
    /// Returns the path to the produced `.cpkg` archive in the current working
    /// directory.
    ///
    /// # Errors
    ///
    /// Fails if a step command cannot be classified, if a dependency is missing
    /// or forms a cycle, if the sandbox cannot be built, if a build step fails,
    /// or if staging, packing or moving the archive fails. On failure the build
    /// workspace is retained and its path logged for inspection.
    pub fn run(&self) -> miette::Result<PathBuf> {
        self.run_with(BuildOptions::default())
    }

    /// As [`BuildFile::run`], with the confinement and classification defaults
    /// overridden.
    ///
    /// `options` applies to this build file and to every dependency built out
    /// of it: a permissive top-level build does not get to impose strict
    /// classification on the packages it pulls in, and an unsandboxed one has
    /// already given up the jail.
    ///
    /// # Errors
    ///
    /// As [`BuildFile::run`].
    pub fn run_with(&self, options: BuildOptions) -> miette::Result<PathBuf> {
        let mut visiting = Vec::new();
        let mut built = HashMap::new();
        if let Some(source) = &self.source {
            visiting.push(source.clone());
        }
        self.run_tracked(options, &mut visiting, &mut built)
    }

    /// The package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version, one component per element.
    #[must_use]
    pub fn version(&self) -> &[String] {
        &self.version
    }

    /// Version components joined with `.`, e.g. `0.1.0`.
    #[must_use]
    pub fn version_string(&self) -> String {
        self.version.join(".")
    }

    /// Paths of the build files this package depends on.
    #[must_use]
    pub fn dependencies(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.dependencies.iter().map(PathBuf::as_path)
    }

    /// The build steps, in the order the file declares them.
    ///
    /// Sorting into execution order is [`BuildFile::execute_steps`]'s job; this
    /// hands back what the file said, which is what a policy derivation and a
    /// `pm explain` table want to show.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Parse the YAML at `path`, recording where it came from and how far it
    /// was trusted.
    fn parse(path: &Path, verification: Verification) -> miette::Result<Self> {
        let text = read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot read build file {}", path.display()))?;
        let mut build_file: Self = from_str(&text)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot parse build file {}", path.display()))?;
        // Fall back to the path as given when it cannot be canonicalised; cycle
        // detection degrades but the build still runs.
        build_file.source = Some(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
        build_file.verification = verification;
        Ok(build_file)
    }

    /// Recursive worker behind [`BuildFile::run`].
    ///
    /// `visiting` is the stack of canonical build-file paths currently being
    /// built; a dependency that is already on it closes a cycle. `built` caches
    /// archives already produced in this invocation so a diamond dependency is
    /// built once rather than once per path to it.
    fn run_tracked(
        &self,
        options: BuildOptions,
        visiting: &mut Vec<PathBuf>,
        built: &mut HashMap<PathBuf, PathBuf>,
    ) -> miette::Result<PathBuf> {
        // Read the build file first. Deriving the policy before the dependency
        // walk means a build file whose commands cannot be classified is
        // rejected before anything at all is built for it.
        let policy = self.derive_policy(options.permissive)?;

        let dependency_archives = self.build_dependencies(options, visiting, built)?;

        info!("building {} version {}", self.name, self.version_string());
        let mut workspace = Workspace::new(format!("{}-{}", self.name, self.version_string()))?;
        let archive_name = format!("{}-{}.cpkg", self.name, self.version_string());
        let staged_archive = workspace.path().join(&archive_name);

        if let Err(report) = self.stage(
            &policy,
            options,
            workspace.path(),
            &dependency_archives,
            &staged_archive,
        ) {
            // Leak the workspace so the half-finished tree can be inspected.
            workspace.keep();
            return Err(report);
        }

        let destination = current_dir()
            .into_diagnostic()
            .wrap_err("cannot determine the current working directory")?
            .join(&archive_name);
        let archive = workspace.persist(&staged_archive, &destination)?;
        info!("packaged {} at {}", self.name, archive.display());
        Ok(archive)
    }

    /// Match every step command against the built-in fingerprint table and log
    /// what came out.
    fn derive_policy(&self, permissive: bool) -> miette::Result<BuildPolicy> {
        let policy = BuildPolicy::derive(self, permissive).wrap_err_with(|| {
            format!(
                "cannot derive a sandbox policy for {}; run `pm explain` on it to see the \
                 whole build file, or build with --permissive to allow the commands anyway",
                self.name
            )
        })?;

        for (command, fingerprint) in policy.matches() {
            info!(
                package = %self.name,
                command = %command,
                fingerprint = %fingerprint,
                "step command classified"
            );
        }
        info!(
            package = %self.name,
            fingerprint = policy.fingerprint(),
            capabilities = ?policy.capabilities(),
            "derived the sandbox policy from the build file"
        );

        Ok(policy)
    }

    /// Build every dependency in turn, returning the archive produced for each.
    ///
    /// Deliberately sequential: this recurses, and recursing inside a Rayon
    /// `par_iter` runs the nested build on a worker of the same global pool
    /// while the outer task blocks on it, which starves the pool on deep or
    /// wide dependency graphs. Dependency builds are I/O- and subprocess-bound
    /// anyway, so there is little to win here.
    fn build_dependencies(
        &self,
        options: BuildOptions,
        visiting: &mut Vec<PathBuf>,
        built: &mut HashMap<PathBuf, PathBuf>,
    ) -> miette::Result<Vec<PathBuf>> {
        if self.dependencies.is_empty() {
            return Ok(Vec::new());
        }
        info!("resolving {} dependencies", self.dependencies.len());

        self.dependencies
            .iter()
            .map(|dependency| self.build_dependency(dependency, options, visiting, built))
            .collect()
    }

    /// Build one dependency, reusing an archive already built in this run.
    fn build_dependency(
        &self,
        dependency: &Path,
        options: BuildOptions,
        visiting: &mut Vec<PathBuf>,
        built: &mut HashMap<PathBuf, PathBuf>,
    ) -> miette::Result<PathBuf> {
        if !dependency.is_file() {
            return Err(miette!(
                "dependency of {} is not a build file: {}",
                self.name,
                dependency.display()
            ));
        }
        let key = dependency
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot resolve dependency {}", dependency.display()))?;

        if visiting.contains(&key) {
            return Err(miette!("dependency cycle: {}", cycle_chain(visiting, &key)));
        }
        if let Some(archive) = built.get(&key) {
            debug!("reusing already built dependency {}", key.display());
            return Ok(archive.clone());
        }

        visiting.push(key.clone());
        // A dependency is loaded exactly as strictly as the build file naming
        // it was: signatures are checked all the way down, or not at all.
        let load = match self.verification {
            Verification::Signed => Self::load,
            Verification::Unverified => Self::load_unverified,
        };
        let result = load(&key).and_then(|loaded| loaded.run_tracked(options, visiting, built));
        visiting.pop();

        let archive = result.wrap_err_with(|| format!("dependency {} failed", key.display()))?;
        built.insert(key, archive.clone());
        Ok(archive)
    }

    /// Lay out the staging tree under `root`, run the build steps into it,
    /// write its metadata and pack it into `archive`.
    ///
    /// `root` holds two siblings: `work`, the working directory the steps run
    /// in, and `pkg`, the tree that ends up inside the archive. `archive` is a
    /// third sibling, so packing `pkg` never picks up the archive itself.
    fn stage(
        &self,
        policy: &BuildPolicy,
        options: BuildOptions,
        root: &Path,
        dependency_archives: &[PathBuf],
        archive: &Path,
    ) -> miette::Result<()> {
        let workdir = root.join("work");
        let staging = root.join("pkg");
        let deps = staging.join("deps");
        create_dir_all(&workdir).into_diagnostic()?;
        create_dir_all(&deps).into_diagnostic()?;

        let dependency_entries = dependency_archives
            .iter()
            .map(|source| {
                let name = source.file_name().ok_or_else(|| {
                    miette!("dependency archive has no file name: {}", source.display())
                })?;
                copy(source, deps.join(name))
                    .into_diagnostic()
                    .wrap_err_with(|| format!("cannot stage dependency {}", source.display()))?;
                Ok(Path::new("deps").join(name))
            })
            .collect::<miette::Result<Vec<PathBuf>>>()?;

        let sandbox = self.sandbox(policy, options, &workdir, &staging, dependency_archives)?;
        self.execute_steps(&sandbox, &workdir)?;

        // Collect entrypoints BEFORE writing `metadata`, so the metadata file
        // does not end up listing itself as a runnable entrypoint.
        let entrypoints = collect_entrypoints(&staging)?;
        // A package with no entrypoints is legitimate - metadata-only and
        // data-only packages exist - but it is far more often a build whose
        // steps ran yet installed nothing into DESTDIR. Say so rather than
        // reporting an empty archive as an unqualified success.
        if entrypoints.is_empty() {
            warn!(
                "{} is empty: no entrypoints were staged into {}",
                self.name,
                staging.display()
            );
        }
        let permissions = self.derive_permissions(&workdir, &staging, &entrypoints)?;
        let metadata = Metadata::create(
            self.name.clone(),
            self.version.clone(),
            dependency_entries,
            entrypoints,
            permissions,
            // A profile derived by observation is incomplete by construction, so it is
            // recorded in audit mode and denies nothing. Promotion to
            // `Enforcement::Enforce` is a human decision made after reading the report;
            // nothing on the build path may make it.
            Enforcement::Audit,
        );
        write(
            staging.join("metadata"),
            metadata_yaml(&metadata, policy.fingerprint())?,
        )
        .into_diagnostic()
        .wrap_err("cannot write package metadata")?;

        // TODO: rewrite RUNPATH/DT_NEEDED of the staged binaries to point at
        // `deps/` inside the archive, so a package resolves its libraries from
        // its own tree instead of the host's. Blocked on an ELF editing
        // dependency (goblin/object + a patchelf-equivalent writer); the crate
        // has none and the contract forbids adding one.
        package(&staging, archive)
    }

    /// Derive the run-time permission profile of the package that was just staged.
    ///
    /// Two signals, merged into one set:
    ///
    /// * **[`source::scan`] over `workdir`.** The steps unpacked and patched the
    ///   package's sources there, so that tree is what the shipped program was compiled
    ///   from. It sees intent a binary no longer records - a `getenv("HOME")`, a config
    ///   path built up from string literals.
    /// * **[`elf::analyse`] over each staged entrypoint.** The entrypoints were already
    ///   classified by [`collect_entrypoints`], so this re-uses that list instead of
    ///   walking the staging tree a second time. `analyse` answers `Ok(None)` for
    ///   anything that is not an ELF, which is how a shell or Python entrypoint passes
    ///   through without being an error.
    ///
    /// # The build is deliberately NOT traced
    ///
    /// It is tempting to point [`crate::perms::monitor::trace`] at the build steps here,
    /// and it would be wrong. Tracing a build traces the **compiler**: the profile would
    /// come back holding every header under `/usr/include`, every object in the
    /// workspace, `cc1`, `as`, `ld`, the linker's temp files and the network fetch of
    /// the tarball - none of which the shipped program touches, and all of which the
    /// package would then be entitled to. A profile that wide means nothing, and the one
    /// program that was never traced is the one being packaged. The monitor belongs to
    /// `pm run --audit`, where it traces the actual entrypoint.
    ///
    /// # Errors
    ///
    /// Fails only if the source scan cannot walk `workdir`. An entrypoint that
    /// [`elf::analyse`] rejects - a truncated object, or a big-endian or 32-bit one this
    /// crate's ELF64 reader does not read - is logged at `warn` and skipped rather than
    /// failing the build: a file the reader cannot parse narrows the profile, and the
    /// profile is recorded in audit mode where a narrow set denies nothing. Failing a
    /// whole package over an unreadable staged file would trade a build for no security
    /// at all.
    fn derive_permissions(
        &self,
        workdir: &Path,
        staging: &Path,
        entrypoints: &HashMap<PathBuf, Type>,
    ) -> miette::Result<Permissions> {
        let sources = source::scan(workdir).wrap_err_with(|| {
            format!(
                "cannot scan the sources of {} in {} for the run-time permission profile",
                self.name,
                workdir.display()
            )
        })?;
        debug!(
            package = %self.name,
            grants = sources.len(),
            "source analysis contributed grants"
        );

        let from_elf = entrypoints.keys().filter_map(|relative| {
            let staged = staging.join(relative);
            match elf::analyse(&staged) {
                Ok(Some(permissions)) => {
                    debug!(
                        package = %self.name,
                        entrypoint = %relative.display(),
                        grants = permissions.len(),
                        "ELF analysis contributed grants"
                    );
                    Some(permissions)
                }
                // Not an ELF at all: a script entrypoint, a data file, a `.a` archive.
                Ok(None) => None,
                Err(report) => {
                    warn!(
                        package = %self.name,
                        entrypoint = %relative.display(),
                        error = %report,
                        "cannot analyse this entrypoint; its libraries are missing from the \
                         recorded profile"
                    );
                    None
                }
            }
        });

        let permissions = Permissions::merge(once(sources).chain(from_elf));
        info!(
            package = %self.name,
            grants = permissions.len(),
            summary = %summarise(&permissions),
            enforcement = ?Enforcement::Audit,
            "derived the run-time permission profile"
        );
        debug!(
            "permission profile of {}:\n{}",
            self.name,
            permissions.report()
        );
        Ok(permissions)
    }

    /// Build the jail the steps of this package run in.
    ///
    /// `workdir` and `staging` are the only writable mounts. Everything else
    /// the build legitimately reads has to be named here, because the jail
    /// mounts neither `$HOME` nor the host `/tmp` the workspace lives under.
    fn sandbox(
        &self,
        policy: &BuildPolicy,
        options: BuildOptions,
        workdir: &Path,
        staging: &Path,
        dependency_archives: &[PathBuf],
    ) -> miette::Result<BuildSandbox> {
        if options.unsandboxed {
            return Ok(BuildSandbox::unsandboxed(workdir, staging));
        }

        let read_only = self.read_only_mounts(dependency_archives);
        let borrowed: Vec<&Path> = read_only.iter().map(PathBuf::as_path).collect();
        BuildSandbox::new(policy, workdir, staging, &borrowed)
            .wrap_err_with(|| format!("cannot build the sandbox for {}", self.name))
    }

    /// Host directories the steps may read, mounted read-only at their own
    /// paths so a command can name them exactly as the build file does.
    ///
    /// Two things go in:
    ///
    /// * **the directory holding this build file.** Sources, patches, helper
    ///   scripts and hand-written Makefiles live next to a build file and are
    ///   referred to by the path the build file was written with. Read-only,
    ///   because a build writes into its working directory and into `DESTDIR`,
    ///   not back into the tree it was described by.
    /// * **the directory each dependency archive sits in.** The archives are
    ///   already copied into `deps/` under `DESTDIR`, but a build file is
    ///   entitled to reach for the one it named, at the path it named it at.
    ///
    /// Nothing else: not the current directory, not `$HOME`, not the host
    /// `/tmp`. A path that cannot be canonicalised is kept as written and left
    /// for [`BuildSandbox::new`] to reject by name.
    fn read_only_mounts(&self, dependency_archives: &[PathBuf]) -> Vec<PathBuf> {
        let candidates = self
            .source
            .iter()
            .map(PathBuf::as_path)
            .chain(dependency_archives.iter().map(PathBuf::as_path))
            .filter_map(Path::parent);

        let mut mounts: Vec<PathBuf> = Vec::new();
        for candidate in candidates {
            let resolved = candidate
                .canonicalize()
                .unwrap_or_else(|_| candidate.to_path_buf());
            // A dependency built in this run left its archive in the current
            // directory, which is very often the build file's own directory;
            // mounting the same path twice is a hakoniwa error, not a no-op.
            if !mounts.contains(&resolved) {
                debug!(path = %resolved.display(), "exposing to the build sandbox read-only");
                mounts.push(resolved);
            }
        }
        mounts
    }

    /// Run every step in stage order, then in authored order within a stage.
    ///
    /// Each command goes through `sandbox`, which places the working directory
    /// and `DESTDIR` at fixed paths inside the jail. `workdir` is still the
    /// host-side path, because a step's downloads are fetched before the jail
    /// is entered - the policy may well deny it the network.
    fn execute_steps(&self, sandbox: &BuildSandbox, workdir: &Path) -> miette::Result<()> {
        // The steps run untraced on purpose. The run-time permission profile is
        // derived afterwards by `BuildFile::derive_permissions`, from the sources
        // and the staged ELF objects; see the "the build is deliberately NOT
        // traced" section there for why pointing the ptrace monitor at this loop
        // would profile the toolchain rather than the package.
        let mut ordered: Vec<&Step> = self.steps.iter().collect();
        // Stable sort: steps keep their authored order within one stage.
        ordered.sort_by_key(|step| step.stage);

        ordered.iter().try_for_each(|step| -> miette::Result<()> {
            debug!("step {} (stage {:?})", step.name, step.stage);
            step.execute(sandbox, workdir)
                .wrap_err_with(|| format!("step {} failed", step.name))
        })
    }
}

/// Verify the detached signature sitting next to `path` against the trust store
/// of this installation.
fn verify_signature(path: &Path) -> miette::Result<()> {
    let trust_dir = default_trust_dir()?;
    let trust = TrustStore::load(&trust_dir)?;
    verify_file(path, &trust).wrap_err_with(|| {
        format!(
            "refusing to read the build file {}: its signature did not check out",
            path.display()
        )
    })
}

/// Serialise `metadata` with the policy fingerprint spliced in, so a package
/// records the policy its build ran under.
///
/// The fingerprint is not a `Metadata` field yet and `metadata.rs` is not this
/// module's to change, so it is inserted into the serialised mapping instead of
/// being set on the struct. `Metadata` does not deny unknown fields, so the
/// file still deserialises into one; when `Metadata::create` grows the
/// parameter, `to_value` already emits the key and this insert overwrites it
/// with the identical value.
fn metadata_yaml(metadata: &Metadata, fingerprint: &str) -> miette::Result<String> {
    let mut value = to_value(metadata)
        .into_diagnostic()
        .wrap_err("cannot serialise the package metadata")?;
    let Some(mapping) = value.as_mapping_mut() else {
        return Err(miette!("package metadata did not serialise to a mapping"));
    };
    mapping.insert(
        Value::String(POLICY_FINGERPRINT_KEY.to_owned()),
        Value::String(fingerprint.to_owned()),
    );
    to_string(&value)
        .into_diagnostic()
        .wrap_err("cannot render the package metadata")
}

/// One line naming what a derived profile came to, for the build log.
///
/// Path kinds are always counted, zero included, so "0 write" is visible rather than
/// merely absent; `network` and `spawn` appear only when granted, because those two are
/// the ones a reader scans for.
fn summarise(permissions: &Permissions) -> String {
    let counted = [
        ("read", permissions.read_paths().count()),
        ("write", permissions.write_paths().count()),
        ("exec", permissions.exec_paths().count()),
    ]
    .into_iter()
    .map(|(label, count)| format!("{count} {label}"));

    let flagged = [
        ("network", permissions.wants_network()),
        ("spawn", permissions.wants_spawn()),
    ]
    .into_iter()
    .filter(|&(_, wanted)| wanted)
    .map(|(label, _)| label.to_owned());

    counted.chain(flagged).collect::<Vec<_>>().join(", ")
}

/// Render the cycle `visiting` closes when `key` is entered again.
fn cycle_chain(visiting: &[PathBuf], key: &Path) -> String {
    let start = visiting.iter().position(|seen| seen == key).unwrap_or(0);
    visiting[start..]
        .iter()
        .map(|path| path.display().to_string())
        .chain(std::iter::once(key.display().to_string()))
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// Classify every regular file under `staging`, keyed by its path RELATIVE to
/// the staging root.
///
/// Relative keys are the only useful ones: the package is extracted somewhere
/// else entirely at run time, so a build-time absolute path names nothing
/// there. Directories are skipped ([`Metadata::classify`] returns `None` for
/// them) and so is `deps/`, whose contents belong to other packages.
fn collect_entrypoints(staging: &Path) -> miette::Result<HashMap<PathBuf, Type>> {
    WalkDir::new(staging)
        .into_iter()
        .map(|entry| -> miette::Result<Option<(PathBuf, Type)>> {
            let entry = entry
                .into_diagnostic()
                .wrap_err_with(|| format!("cannot walk {}", staging.display()))?;
            let path = entry.into_path();
            let Some(kind) = Metadata::classify(&path) else {
                return Ok(None);
            };
            let relative = path
                .strip_prefix(staging)
                .into_diagnostic()
                .wrap_err_with(|| format!("{} escaped the staging tree", path.display()))?;
            if relative.starts_with("deps") {
                return Ok(None);
            }
            Ok(Some((relative.to_path_buf(), kind)))
        })
        .filter_map(Result::transpose)
        .collect()
}

/// Pack `staging` into `archive` as an xz-compressed tar.
///
/// Packed as `tar -cJf <archive> -C <staging> .` so that extracting with
/// `tar -xpf <archive> -C <dest>` puts the package tree, `metadata` included,
/// directly at `<dest>`.
fn package(staging: &Path, archive: &Path) -> miette::Result<()> {
    info!("packing {}", archive.display());
    let output = Command::new("tar")
        .arg("-cJf")
        .arg(archive)
        .arg("-C")
        .arg(staging)
        .arg(".")
        .output()
        .into_diagnostic()
        .wrap_err("cannot run tar")?;
    if !output.status.success() {
        return Err(miette!(
            "tar exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
