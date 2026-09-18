//! Extending pm's built-in tables with sandboxed WebAssembly components.
//!
//! pm decides two things from tables that are compiled into it: what a build-step
//! command needs from the build jail ([`crate::policy`]), and what a package's sources
//! imply it will need at run time ([`crate::perms::source`]). Both tables are finite,
//! and both are wrong the moment somebody builds a package in a language or with a
//! build system pm has never heard of. Today the first case aborts the build and the
//! second silently contributes nothing.
//!
//! A plugin is how that gets fixed without rebuilding pm. It is a WebAssembly
//! **component**, compiled against `wit/plugin.wit`, that answers one or both of those
//! questions. pm loads every `*.wasm` in `<config>/pm/plugins/`, asks each one to
//! [`describe`](Plugin::manifest) itself, and calls the hooks it declared.
//!
//! # Why a component, and why sandboxed
//!
//! A plugin runs **in pm's own process**. There is no jail around it, because pm is the
//! thing doing the jailing; the WebAssembly sandbox is the entire boundary, and
//! [`engine`] is where that boundary is built: one import (a one-way `log`), no WASI, a
//! per-call fuel budget, a memory cap, a stack cap, and a fresh instance for every call
//! so nothing carries between them.
//!
//! The component model, rather than a bare core module, is what makes the interface
//! worth having: the world in `wit/plugin.wit` is a typed contract with strings, lists,
//! records and variants in it, so a plugin author writes `Option<Verdict>` and pm reads
//! `Option<Verdict>`, with no hand-rolled pointer-and-length protocol in between for
//! either side to get wrong.
//!
//! # What a plugin can and cannot do to a build
//!
//! This is the part worth being precise about, because a plugin system that can only
//! *widen* a security decision is a plugin system that deletes it.
//!
//! * **It cannot reclassify a command pm already knows.** [`Registry::classify`] is only
//!   reached for a command that matched no built-in fingerprint. No plugin can say that
//!   `cargo` needs no network or that `git` is not version control, because no plugin is
//!   ever asked.
//! * **It can name a command pm would have refused.** That widens the jail for that
//!   command, from "the build does not run at all" to "the build runs with these
//!   capabilities". This is the plugin system's whole point and it is also its entire
//!   risk, which is why a plugin must be signed by a key in the same trust store that
//!   governs build files (see [`Loader::allow_unsigned`]), and why every plugin
//!   publishes a ceiling it is held to - see [`Manifest::grants_at_most`].
//! * **It cannot hide.** A plugin's fingerprints are recorded as `<plugin>:<name>`, so
//!   `pm explain` shows which command was classified by whom; its grants carry
//!   [`Provenance::Plugin`] and an evidence line naming it; and the whole plugin set
//!   folds into [`Registry::digest`], which folds into the build policy's own digest.
//!   Two builds of one build file under different plugin sets do not compare equal.
//! * **It cannot turn enforcement on.** Grants from `scan-source` land in a profile
//!   recorded at [`Enforcement::Audit`], exactly like the built-in signals, and nothing
//!   on the build path promotes anything. A human reading `pm profile` sees the
//!   `plugin` provenance before deciding.
//! * **It cannot fail a build by misbehaving.** A plugin that traps, runs out of fuel or
//!   returns something unusable is logged and treated as having had no answer. A plugin
//!   that could abort a build at will could hold one hostage.
//!
//! The ceiling deserves one more sentence, because it is easy to overrate. It is the
//! plugin's *own claim* about itself, which pm then enforces; its value is that
//! reviewing `pm plugins` is a cheap substitute for reading the plugin. It is not a
//! defence against a plugin signed by a key you should not have trusted - nothing here
//! is. Trust the key, then read the ceiling.
//!
//! [`Enforcement::Audit`]: crate::perms::Enforcement::Audit
//! [`Provenance::Plugin`]: crate::perms::Provenance::Plugin

/// Conversions from what a plugin said into what pm will act on.
mod convert;
/// The WebAssembly runtime a plugin is confined to.
mod engine;
/// The bindings generated from `wit/plugin.wit`.
mod wit;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{read, read_dir},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use miette::{IntoDiagnostic, Result, WrapErr, miette};
use ring::digest::{Context, SHA256};
use tracing::{debug, info, warn};
use wasmtime::component::Component;

use self::{
    engine::Runtime,
    wit::{WitSourceFile, WitVerdict},
};
use crate::{
    perms::Grant,
    policy::Capability,
    signing::{TrustStore, config_dir, verify_file},
};

/// The extension a plugin file must have to be loaded.
const PLUGIN_EXTENSION: &str = "wasm";

/// What introduces a symbol reference in a build file.
///
/// `%{` rather than `${`: a build file's commands are run with **no shell**, so `$HOME`
/// and `$DESTDIR` are already literal text there, and a `${...}` that did expand beside
/// a `$DESTDIR` that did not would be the worst of both. `%{` is also what rpm spells
/// its macros with, which is the right neighbourhood for a package manager.
const OPEN: &str = "%{";

/// The registry handed to anything that was not given a real one.
///
/// Empty, so every hook is a no-op and [`Registry::digest`] is the empty string, which
/// is what keeps a plugin-free build's policy digest identical to what pm produced
/// before plugins existed.
static NONE: LazyLock<Registry> = LazyLock::new(Registry::empty);

/// Directory plugins are loaded from, `<config>/pm/plugins/`.
///
/// Beside `<config>/pm/trusted/` on purpose: a plugin is code that runs with pm's
/// privileges, so the two things a user installs out-of-band live in one place.
///
/// # Errors
///
/// Fails if neither `$XDG_CONFIG_HOME` nor `$HOME` names a directory.
pub fn default_plugin_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("pm").join("plugins"))
}

/// A hook a plugin implements.
///
/// pm calls a hook only when the plugin's manifest lists it. The world's exports are
/// all mandatory - the component model has no optional export - so a plugin that does
/// one job still exports the other entry point and returns the empty answer from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hook {
    /// Classify a build-step command that matched no built-in fingerprint.
    ClassifyCommand,
    /// Infer run-time permissions from a source file.
    ScanSource,
}

impl Hook {
    /// A short, stable label: `classify-command` or `scan-source`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ClassifyCommand => "classify-command",
            Self::ScanSource => "scan-source",
        }
    }
}

impl fmt::Display for Hook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A named constant a build file may substitute into a step command.
///
/// Published by a plugin in its manifest, printed by `pm plugins`, and referred to from
/// a build file as `%{<plugin>:<name>}`. See [`Registry::expand`] for the substitution
/// itself and for why the value is always a single word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The part after the plugin's name in a reference.
    pub name: String,
    /// What it expands to: one word, no whitespace.
    pub value: String,
    /// One line saying what it is.
    pub summary: String,
}

/// What a plugin says it is, after pm has checked that it can use the answer.
///
/// Built by [`convert::manifest`] from the plugin's own `describe` export, once, at
/// load time. Printed by `pm plugins`, which is the review surface: everything here is
/// something the plugin claims and pm then holds it to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Identifies the plugin everywhere pm mentions it: 1-32 characters of `a-z`, `0-9`
    /// and `-`. It prefixes the plugin's fingerprints and tags its log and evidence
    /// lines, which is why a plugin without a usable one is refused outright.
    pub name: String,
    /// Free-form, shown but never interpreted.
    pub version: String,
    /// One line saying what the plugin is for.
    pub summary: String,
    /// Which hooks pm calls.
    pub hooks: BTreeSet<Hook>,
    /// The most `classify-command` will ever ask for.
    ///
    /// A verdict reaching past this has the extra capabilities dropped and logged. It
    /// is the plugin's own published claim, enforced - see the module documentation for
    /// what that is and is not worth. Empty when [`Hook::ClassifyCommand`] is not among
    /// the hooks.
    pub grants_at_most: Vec<Capability>,
    /// File extensions, without the dot, that `scan-source` is called for. Empty when
    /// [`Hook::ScanSource`] is not among the hooks.
    pub source_extensions: BTreeSet<String>,
    /// Named constants build files may substitute into step commands, keyed by name.
    ///
    /// Not gated on a hook: nothing calls back into the plugin to read these, they are
    /// data pm took once at load and keeps. Most plugins publish none.
    pub symbols: BTreeMap<String, Symbol>,
}

/// How a plugin came to be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// A detached `.sig` verified against the trust store.
    Signed,
    /// Loaded through [`Loader::allow_unsigned`] with no signature checked.
    Unverified,
}

impl Trust {
    /// A short, stable label: `signed` or `unverified`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Unverified => "unverified",
        }
    }
}

impl fmt::Display for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One loaded plugin: its manifest, its identity on disk, and its compiled component.
pub struct Plugin {
    manifest: Manifest,
    path: PathBuf,
    /// SHA-256 of the file as loaded. Part of [`Registry::digest`], so a plugin that is
    /// swapped under a build changes the build's policy digest.
    sha256: String,
    trust: Trust,
    component: Component,
}

impl Plugin {
    /// What the plugin says it is.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Where it was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// SHA-256 of the file, lower-case hex.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Whether its signature was checked.
    #[must_use]
    pub fn trust(&self) -> Trust {
        self.trust
    }
}

impl fmt::Debug for Plugin {
    /// Everything but the compiled component, which has no useful rendering and would
    /// bury the fields that do.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plugin")
            .field("manifest", &self.manifest)
            .field("path", &self.path)
            .field("sha256", &self.sha256)
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

/// Where plugins are loaded from and how strictly.
///
/// ```no_run
/// # use std::path::PathBuf;
/// let registry = pm::plugin::Loader::new(pm::plugin::default_plugin_dir()?).load()?;
/// # Ok::<(), miette::Report>(())
/// ```
#[derive(Debug, Clone)]
pub struct Loader {
    dir: PathBuf,
    trust_dir: Option<PathBuf>,
    allow_unsigned: bool,
}

impl Loader {
    /// Load plugins from `dir`, signatures required.
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            trust_dir: None,
            allow_unsigned: false,
        }
    }

    /// Check signatures against `dir` instead of [`crate::signing::default_trust_dir`].
    #[must_use]
    pub fn trust_dir(mut self, dir: PathBuf) -> Self {
        self.trust_dir = Some(dir);
        self
    }

    /// Load plugins **without checking their signatures**.
    ///
    /// The counterpart of [`crate::bf::BuildFile::load_unverified`], and it gives up
    /// rather more: a build file names commands that run inside a jail, while a plugin
    /// is code that runs inside pm and helps decide what that jail allows. For
    /// developing a plugin you have not signed yet, and nothing else.
    #[must_use]
    pub fn allow_unsigned(mut self, allow: bool) -> Self {
        self.allow_unsigned = allow;
        self
    }

    /// Load every `*.wasm` in the directory, in file-name order.
    ///
    /// A directory that does not exist is an empty registry rather than an error: not
    /// having installed any plugins is the normal state.
    ///
    /// Loading is **strict about everything it finds**. A file that is not a component,
    /// whose signature is missing or untrusted, whose `describe` export traps, or that
    /// calls itself by a name another plugin already took, fails the whole load. The
    /// alternative - skipping it - would silently change what pm decides about a build
    /// while the user believes the plugin they installed is in play.
    ///
    /// # Errors
    ///
    /// Fails if the directory cannot be read, if the trust store cannot be loaded, or
    /// for any of the per-plugin reasons above, each naming the file it came from.
    pub fn load(self) -> Result<Registry> {
        let files = self.discover()?;
        if files.is_empty() {
            debug!(dir = %self.dir.display(), "no plugins installed");
            return Ok(Registry::empty());
        }

        let trust = if self.allow_unsigned {
            warn!(
                dir = %self.dir.display(),
                count = files.len(),
                "loading plugins WITHOUT verifying their signatures; they run inside pm, \
                 with your privileges, and help decide what the build jail allows"
            );
            None
        } else {
            let dir = match self.trust_dir.clone() {
                Some(dir) => dir,
                None => crate::signing::default_trust_dir()?,
            };
            Some(TrustStore::load(&dir)?)
        };

        let runtime = Runtime::new()?;
        let mut plugins: Vec<Plugin> = Vec::with_capacity(files.len());
        for path in files {
            let plugin = load_one(&runtime, &path, trust.as_ref())?;
            if let Some(clash) = plugins
                .iter()
                .find(|other| other.manifest.name == plugin.manifest.name)
            {
                return Err(miette!(
                    help = "Plugin names prefix the fingerprints and evidence lines they \
                            produce, so two plugins cannot share one. Remove or rename one \
                            of the two files.",
                    "{} and {} both call themselves `{}`",
                    clash.path.display(),
                    plugin.path.display(),
                    plugin.manifest.name
                ));
            }
            info!(
                plugin = %plugin.manifest.name,
                version = %plugin.manifest.version,
                trust = %plugin.trust,
                hooks = plugin.manifest.hooks.len(),
                "loaded plugin"
            );
            plugins.push(plugin);
        }

        let digest = digest(&plugins);
        debug!(plugins = plugins.len(), %digest, "plugin registry ready");
        Ok(Registry {
            runtime: Some(runtime),
            plugins,
            digest,
        })
    }

    /// Every `*.wasm` directly in the directory, sorted by path.
    ///
    /// Sorted because the order plugins are consulted in decides which one's verdict
    /// wins a tie, and that has to be the same on every machine - a build policy is
    /// digested, and a digest that depends on directory iteration order is not one.
    ///
    /// Subdirectories are not descended into and other extensions are skipped, so the
    /// directory can hold a `README`, a `.sig` beside each plugin and the sources a
    /// plugin was built from without any of it being mistaken for a plugin.
    fn discover(&self) -> Result<Vec<PathBuf>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut files: Vec<PathBuf> = read_dir(&self.dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot read the plugin directory {}", self.dir.display()))?
            .map(|entry| {
                entry
                    .into_diagnostic()
                    .wrap_err_with(|| format!("cannot read an entry of {}", self.dir.display()))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .is_some_and(|extension| extension == PLUGIN_EXTENSION)
            })
            .collect();
        files.sort();
        Ok(files)
    }
}

/// Every plugin this run of pm will consult.
///
/// Build one with [`Loader`], or take the shared empty one from [`Registry::none`].
/// It is `Sync`, and every hook takes `&self`, so one registry serves the whole
/// concurrent build: the compiled components are shared and the mutable per-call state
/// lives in a store that exists only for the duration of one call.
pub struct Registry {
    /// `None` exactly when there are no plugins, so a pm with none installed never
    /// builds a WebAssembly engine at all.
    runtime: Option<Runtime>,
    plugins: Vec<Plugin>,
    digest: String,
}

impl Registry {
    /// The shared empty registry: no plugins, every hook a no-op.
    ///
    /// This is what the library entry points and the tests use, and it is why adding
    /// plugins changed no existing behaviour: with an empty registry every code path
    /// through [`Registry::classify`] and [`Registry::scan_source`] answers exactly what
    /// pm answered before they existed.
    #[must_use]
    pub fn none() -> &'static Self {
        &NONE
    }

    /// An owned empty registry, for a caller that needs a value rather than a borrow.
    ///
    /// Builds no WebAssembly engine, because there is nothing to run in one.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            runtime: None,
            plugins: Vec::new(),
            digest: String::new(),
        }
    }

    /// The loaded plugins, in the order they are consulted.
    #[must_use]
    pub fn plugins(&self) -> &[Plugin] {
        &self.plugins
    }

    /// How many plugins are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether no plugins are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// A stable digest over the whole plugin set: name, version and file hash of each.
    ///
    /// The empty string when no plugins are loaded, which is what keeps the build
    /// policy digest of a plugin-free build byte-identical to a pm without plugins.
    ///
    /// [`crate::policy::BuildPolicy`] folds this into its own digest. It has to: the
    /// same build file under a different plugin set can derive a different capability
    /// set, and two policies that are not the same policy must not print the same
    /// digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Whether any plugin asked to see files with this extension.
    ///
    /// `extension` is without the dot and is compared lower-case.
    #[must_use]
    pub fn wants_extension(&self, extension: &str) -> bool {
        let extension = extension.to_ascii_lowercase();
        self.plugins.iter().any(|plugin| {
            plugin.manifest.hooks.contains(&Hook::ScanSource)
                && plugin.manifest.source_extensions.contains(&extension)
        })
    }

    /// The symbol `plugin` publishes under `name`, if it publishes one.
    #[must_use]
    pub fn symbol(&self, plugin: &str, name: &str) -> Option<&Symbol> {
        self.plugins
            .iter()
            .find(|candidate| candidate.manifest.name == plugin)?
            .manifest
            .symbols
            .get(name)
    }

    /// Every symbol every plugin publishes, as `(<plugin>:<name>, symbol)`, sorted.
    pub fn symbols(&self) -> impl Iterator<Item = (String, &Symbol)> {
        self.plugins.iter().flat_map(|plugin| {
            plugin
                .manifest
                .symbols
                .values()
                .map(move |symbol| (format!("{}:{}", plugin.manifest.name, symbol.name), symbol))
        })
    }

    /// Substitute `%{<plugin>:<name>}` references in `text`.
    ///
    /// The point is the things a build file would otherwise hardcode and get wrong:
    /// `install -Dm644 foo.service %{systemd:unitdir}/foo.service` names where unit
    /// files go without the build file having to know, or be rewritten when the answer
    /// changes.
    ///
    /// # What is and is not a reference
    ///
    /// `%{...}` is a reference **only** when what is inside it is a well-formed
    /// `<plugin>:<name>` - a plugin name, one colon, a symbol name, both in their own
    /// narrow charsets. A well-formed reference that names nothing is an **error**: a
    /// mistyped `%{systemd:unitdirr}` must not end up in a command as itself, quietly
    /// installing a file into a directory named after the typo.
    ///
    /// Anything else keeps its shape and passes through untouched - `%{NAME}`,
    /// `--queryformat=%{VERSION}`, a bare `%`, `%%`. There is no escape character,
    /// because there is nothing to escape: a string that is not shaped like a reference
    /// is already literal. That also means a command cannot contain a literal `%{` that
    /// *is* shaped like one, which is the whole cost of having no escape and is worth
    /// it against making every `%` in every command mean something.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic naming the reference when no loaded plugin offers it, and
    /// listing what is on offer. A registry with no plugins in it is the common way to
    /// reach that, so the diagnostic says so rather than listing nothing.
    pub fn expand(&self, text: &str) -> Result<String> {
        self.expand_into(text, &mut BTreeSet::new())
    }

    /// As [`Registry::expand`], recording every reference it resolved into `used`.
    ///
    /// `pm explain` prints what it collected, so a reader of a build file can see which
    /// symbols shaped the commands that actually ran without going and reading the
    /// plugins.
    ///
    /// # Errors
    ///
    /// As [`Registry::expand`].
    pub fn expand_into(&self, text: &str, used: &mut BTreeSet<String>) -> Result<String> {
        // The overwhelmingly common case, and the one that has to cost nothing: no
        // build file anybody has today holds a reference.
        if !text.contains(OPEN) {
            return Ok(text.to_owned());
        }

        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.find(OPEN) {
            out.push_str(&rest[..at]);
            let after = &rest[at + OPEN.len()..];
            // An unterminated `%{` is not a reference; it is a `%` followed by a brace.
            let Some(end) = after.find('}') else {
                out.push_str(OPEN);
                rest = after;
                continue;
            };
            let reference = &after[..end];
            let Some((plugin, name)) = well_formed(reference) else {
                out.push_str(OPEN);
                rest = after;
                continue;
            };
            let Some(symbol) = self.symbol(plugin, name) else {
                return Err(self.unknown_symbol(reference));
            };
            debug!(
                reference,
                value = %symbol.value,
                "substituted a plugin symbol into a build file"
            );
            out.push_str(&symbol.value);
            used.insert(reference.to_owned());
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    /// The diagnostic for a well-formed reference nothing offers.
    fn unknown_symbol(&self, reference: &str) -> miette::Report {
        let offered: Vec<String> = self.symbols().map(|(qualified, _)| qualified).collect();
        if offered.is_empty() {
            return miette!(
                help = "Install the plugin that offers it, or run with --no-plugins to \
                        see what the build file does without one.",
                "the build file uses `{OPEN}{reference}}}`, but no loaded plugin offers \
                 any symbols"
            );
        }
        miette!(
            "the build file uses `{OPEN}{reference}}}`, which no loaded plugin \
             offers\navailable symbols: {}",
            offered.join(", ")
        )
    }

    /// Ask the plugins to classify a command the built-in table did not recognise.
    ///
    /// **Only ever called for an unmatched command** - see [`crate::policy::BuildPolicy::derive`].
    /// Plugins are consulted in load order and the first verdict wins, which is why that
    /// order is sorted rather than whatever the directory happened to hand back.
    ///
    /// Returns the fingerprint name, already prefixed with the plugin's own, and the
    /// capabilities that survived the plugin's declared ceiling. A plugin that traps or
    /// answers with something unusable is logged and treated as having had no answer.
    #[must_use]
    pub fn classify(&self, command: &str) -> Option<(String, Vec<Capability>)> {
        let runtime = self.runtime.as_ref()?;
        self.plugins
            .iter()
            .filter(|plugin| plugin.manifest.hooks.contains(&Hook::ClassifyCommand))
            .find_map(|plugin| {
                let answer: WitVerdict = runtime
                    .enter(
                        &plugin.manifest.name,
                        &plugin.component,
                        |bindings, store| bindings.call_classify_command(store, command),
                    )
                    .map_err(|report| {
                        warn!(
                            plugin = %plugin.manifest.name,
                            command,
                            "cannot classify this command: {report}"
                        );
                    })
                    .ok()
                    .flatten()?;
                let verdict = convert::verdict(answer, &plugin.manifest)?;
                debug!(
                    plugin = %plugin.manifest.name,
                    command,
                    fingerprint = %verdict.0,
                    capabilities = ?verdict.1,
                    "a plugin classified a command the built-in table did not"
                );
                Some(verdict)
            })
    }

    /// Ask every plugin that wants this file what the built program will need.
    ///
    /// `relative` is the file's path inside the scanned tree and `contents` its text;
    /// [`crate::perms::source`] has already applied the size, binary and UTF-8 filters,
    /// so a plugin never sees a file the built-in scanners would not see either.
    ///
    /// Unlike [`Registry::classify`], *every* interested plugin is asked and the grants
    /// are concatenated: permissions merge, so two plugins agreeing about a path is
    /// information worth keeping rather than a tie to break.
    #[must_use]
    pub fn scan_source(&self, relative: &str, contents: &str) -> Vec<Grant> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Vec::new();
        };
        let Some(extension) = extension_of(relative) else {
            return Vec::new();
        };

        self.plugins
            .iter()
            .filter(|plugin| {
                plugin.manifest.hooks.contains(&Hook::ScanSource)
                    && plugin.manifest.source_extensions.contains(&extension)
            })
            .flat_map(|plugin| {
                let file = WitSourceFile {
                    path: relative.to_owned(),
                    contents: contents.to_owned(),
                };
                match runtime.enter(
                    &plugin.manifest.name,
                    &plugin.component,
                    |bindings, store| bindings.call_scan_source(store, &file),
                ) {
                    Ok(raw) => convert::grants(raw, &plugin.manifest, relative),
                    Err(report) => {
                        warn!(
                            plugin = %plugin.manifest.name,
                            file = %relative,
                            "cannot scan this file; its grants are missing from the profile: \
                             {report}"
                        );
                        Vec::new()
                    }
                }
            })
            .collect()
    }
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("plugins", &self.plugins)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Registry {
    /// Two registries are equal when they hold the same plugins at the same versions
    /// and file hashes, which is exactly what [`Registry::digest`] covers.
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl Eq for Registry {}

/// Read, verify, compile and interrogate one plugin file.
fn load_one(runtime: &Runtime, path: &Path, trust: Option<&TrustStore>) -> Result<Plugin> {
    let bytes = read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot read the plugin {}", path.display()))?;

    let trust_state = match trust {
        Some(store) => {
            verify_file(path, store).wrap_err_with(|| {
                format!(
                    "refusing to load the plugin {}: its signature did not check out. A \
                     plugin runs inside pm and helps decide what a build jail allows, so \
                     it is held to the same standard as a build file.",
                    path.display()
                )
            })?;
            Trust::Signed
        }
        None => Trust::Unverified,
    };

    let component = runtime
        .compile(&bytes)
        .wrap_err_with(|| format!("cannot load the plugin {}", path.display()))?;

    let file = path.display().to_string();
    // `describe` is called once, here, and the answer is cached for the process. A
    // plugin that reported one thing at load and another later would make `pm plugins`
    // a lie; asking once makes that impossible rather than merely unlikely.
    let described = runtime
        .enter("<loading>", &component, |bindings, store| {
            bindings.call_describe(store)
        })
        .wrap_err_with(|| format!("the plugin {file} could not describe itself"))?;

    let manifest = convert::manifest(described, &file).map_err(|reason| miette!("{reason}"))?;

    Ok(Plugin {
        manifest,
        path: path.to_path_buf(),
        sha256: sha256(&bytes),
        trust: trust_state,
        component,
    })
}

/// SHA-256 of `bytes` as lower-case hex.
fn sha256(bytes: &[u8]) -> String {
    let mut context = Context::new(&SHA256);
    context.update(bytes);
    context
        .finish()
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            use fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// A stable digest over a whole plugin set.
///
/// Taken over each plugin's name, version and file hash, in load order, with a
/// separator that cannot occur in any of the three so no two different sets can hash
/// the same. The empty set digests to the empty string rather than to the hash of
/// nothing, because "no plugins" has to be distinguishable from "some plugins" without
/// anyone having to know this function's output for zero inputs.
fn digest(plugins: &[Plugin]) -> String {
    if plugins.is_empty() {
        return String::new();
    }
    let mut context = Context::new(&SHA256);
    for plugin in plugins {
        context.update(plugin.manifest.name.as_bytes());
        context.update(b"\0");
        context.update(plugin.manifest.version.as_bytes());
        context.update(b"\0");
        context.update(plugin.sha256.as_bytes());
        context.update(b"\n");
    }
    let finished = context.finish();
    sha256_hex(finished.as_ref())
}

/// Render digest bytes as lower-case hex.
fn sha256_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            use fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Split a reference's contents into a plugin name and a symbol name, if it is shaped
/// like one at all.
///
/// Exactly one colon, and both halves in the charsets [`convert`] validates a plugin
/// name and a symbol name against. Anything else is not a reference and is left alone -
/// see [`Registry::expand`].
fn well_formed(reference: &str) -> Option<(&str, &str)> {
    let (plugin, name) = reference.split_once(':')?;
    let plugin_ok = !plugin.is_empty()
        && plugin
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    let name_ok = !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    (plugin_ok && name_ok).then_some((plugin, name))
}

/// The lower-case extension of a `/`-separated relative path, without the dot.
fn extension_of(relative: &str) -> Option<String> {
    let name = relative.rsplit('/').next()?;
    let (stem, extension) = name.rsplit_once('.')?;
    // A dotfile with no extension - `.gitignore` - has an empty stem, and its whole
    // name is not an extension.
    (!stem.is_empty() && !extension.is_empty()).then(|| extension.to_ascii_lowercase())
}
