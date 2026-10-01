//! pm's own plugins: WebAssembly components embedded in the pm binary.
//!
//! What pm knows about build tools and source languages lives in fourteen components
//! that pm's `build.rs` compiles from `plugins/bundled/` on every build, one per
//! ecosystem: eight that classify build-step
//! commands (`buildsys`, `rust`, `go`, `node`, `python`, `c`, `posix`, `git`) and six
//! that read sources (`c-source`, `cpp-source`, `rust-source`, `python-source`,
//! `go-source`, `bash-source`). They export the `bundled` world of `wit/plugin.wit` and
//! run in the same WebAssembly runtime as an installed plugin, with the same single
//! `log` import and nothing else.
//!
//! # What makes them different from an installed plugin
//!
//! They are part of pm, so they are treated as pm's own tables always were:
//!
//! * **Consulted first.** A command is offered to the bundled classifiers, in the
//!   order of [`COMMANDS`], before any installed plugin hears of it - so an installed
//!   plugin still cannot reclassify `cargo` or `git`.
//! * **Recorded unprefixed.** A bundled verdict is recorded as `cargo`, not
//!   `rust:cargo`, and a bundled grant as source analysis, with the evidence line the
//!   scanner wrote. Policies and profiles come out exactly as they did when these were
//!   compiled-in tables, digest included.
//! * **Always there.** They need no signature, are not listed by `pm plugins`, and
//!   `--no-plugins` does not turn them off: without them pm can classify nothing.
//! * **Compiled lazily, by tier.** The classifiers are compiled the first time a
//!   command is classified and the scanners the first time a source tree is scanned, each
//!   tier in parallel, once per process. A build that never scans never compiles a
//!   grammar.
//! * **Kept alive per thread.** See [`super::engine::Live`]: a scanner compiles its
//!   tree-sitter queries once per instance, not once per file.

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap},
    sync::LazyLock,
};

use miette::{Result, miette};
use rayon::prelude::*;
use tracing::{debug, warn};
use wasmtime::component::Component;

use super::{
    Hook, Manifest, convert,
    engine::{Live, Runtime},
    wit::{WitPermission, WitSourceFile},
};
use crate::{
    perms::{Grant, Permission, Provenance},
    policy::Capability,
};

/// One embedded component.
type Embedded = (&'static str, &'static [u8]);

/// Embed the component `build.rs` built from `plugins/bundled/<name>` under its name.
macro_rules! embed {
    ($name:literal) => {
        (
            $name,
            include_bytes!(concat!(env!("OUT_DIR"), "/bundled/", $name, ".wasm")),
        )
    };
}

/// The command classifiers, in precedence order: the first verdict wins.
///
/// The order, and each plugin's own order, concatenate to the order the compiled-in
/// fingerprint table had; a test holds it there.
static COMMANDS: [Embedded; 8] = [
    embed!("buildsys"),
    embed!("rust"),
    embed!("go"),
    embed!("node"),
    embed!("python"),
    embed!("c"),
    embed!("posix"),
    embed!("git"),
];

/// The source scanners. No two claim the same extension, so their order decides nothing.
static SOURCES: [Embedded; 6] = [
    embed!("c-source"),
    embed!("cpp-source"),
    embed!("rust-source"),
    embed!("python-source"),
    embed!("go-source"),
    embed!("bash-source"),
];

/// One bundled plugin, compiled and described.
pub struct Loaded {
    manifest: Manifest,
    /// Its `fingerprints` export, leaked once so verdicts can hand out `&'static str`.
    fingerprints: Vec<&'static str>,
    component: Component,
}

impl Loaded {
    /// What the plugin says it is.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Every fingerprint name its `classify-command` can return, in the order it tries
    /// them. Empty for a source scanner.
    #[must_use]
    pub fn fingerprints(&self) -> &[&'static str] {
        &self.fingerprints
    }
}

/// The engine every bundled plugin runs in, built on first use.
static RUNTIME: LazyLock<std::result::Result<Runtime, String>> =
    LazyLock::new(|| Runtime::new().map_err(|report| format!("{report:?}")));

static COMMAND_TIER: LazyLock<std::result::Result<Vec<Loaded>, String>> =
    LazyLock::new(|| load(&COMMANDS));

static SOURCE_TIER: LazyLock<std::result::Result<Vec<Loaded>, String>> =
    LazyLock::new(|| load(&SOURCES));

thread_local! {
    /// This thread's live instance of each bundled plugin it has called, by name.
    static LIVE: RefCell<HashMap<&'static str, Live>> = RefCell::new(HashMap::new());
}

fn runtime() -> Result<&'static Runtime> {
    RUNTIME
        .as_ref()
        .map_err(|error| miette!("cannot start the runtime pm's bundled plugins run in: {error}"))
}

/// Compile and describe a tier, in parallel. Any failure is a bug in pm.
fn load(tier: &[Embedded]) -> std::result::Result<Vec<Loaded>, String> {
    let runtime = runtime().map_err(|report| format!("{report:?}"))?;
    tier.par_iter()
        .map(|(name, bytes)| {
            let component = runtime
                .compile(bytes)
                .map_err(|report| format!("{name}: {report:?}"))?;
            let mut live = runtime
                .instantiate_bundled(name, &component)
                .map_err(|report| format!("{name}: {report:?}"))?;
            let described = live
                .call(name, |bindings, store| bindings.call_describe(store))
                .map_err(|report| format!("{name}: {report:?}"))?;
            let manifest = convert::manifest(described, name)?;
            if manifest.name != *name {
                return Err(format!("{name} calls itself `{}`", manifest.name));
            }
            let fingerprints = live
                .call(name, |bindings, store| bindings.call_fingerprints(store))
                .map_err(|report| format!("{name}: {report:?}"))?
                .into_iter()
                .map(|fingerprint| &*Box::leak(fingerprint.into_boxed_str()))
                .collect();
            debug!(plugin = name, "loaded bundled plugin");
            Ok(Loaded {
                manifest,
                fingerprints,
                component,
            })
        })
        .collect()
}

/// The command classifiers, compiled.
///
/// # Errors
///
/// Fails if one does not compile or describe itself, which is a bug in pm.
pub fn commands() -> Result<&'static [Loaded]> {
    COMMAND_TIER.as_deref().map_err(|error| {
        miette!("pm's bundled command classifiers failed to load: {error}; this is a bug in pm")
    })
}

/// The source scanners, compiled.
///
/// # Errors
///
/// Fails if one does not compile or describe itself, which is a bug in pm.
pub fn sources() -> Result<&'static [Loaded]> {
    SOURCE_TIER.as_deref().map_err(|error| {
        miette!("pm's bundled source scanners failed to load: {error}; this is a bug in pm")
    })
}

/// Every bundled fingerprint name, in precedence order.
///
/// # Errors
///
/// As [`commands`].
pub fn fingerprint_names() -> Result<Vec<&'static str>> {
    Ok(commands()?
        .iter()
        .flat_map(|plugin| plugin.fingerprints.iter().copied())
        .collect())
}

/// Run `call` against this thread's live instance of `plugin`, making one if needed.
///
/// An instance whose call failed is dropped, so the next call gets a fresh one.
fn with_live<T>(plugin: &'static Loaded, call: impl FnOnce(&mut Live) -> Result<T>) -> Result<T> {
    let name: &'static str = plugin.manifest.name.as_str();
    LIVE.with(|live| {
        let mut live = live.borrow_mut();
        if !live.contains_key(name) {
            let instance = runtime()?.instantiate_bundled(name, &plugin.component)?;
            live.insert(name, instance);
        }
        let instance = live.get_mut(name).expect("inserted above");
        let outcome = call(instance);
        if outcome.is_err() {
            live.remove(name);
        }
        outcome
    })
}

/// Ask the bundled classifiers about `command`, in precedence order.
///
/// Returns the fingerprint name, unprefixed, and what it grants. A classifier that
/// traps, or answers with a name it did not declare, is logged and passed over - the
/// same treatment an installed plugin gets.
///
/// # Errors
///
/// As [`commands`].
pub fn classify(command: &str) -> Result<Option<(&'static str, Vec<Capability>)>> {
    for plugin in commands()? {
        let name = plugin.manifest.name.as_str();
        let answer = with_live(plugin, |live| {
            live.call(name, |bindings, store| {
                bindings.call_classify_command(store, command)
            })
        });
        let verdict = match answer {
            Ok(Some(verdict)) => verdict,
            Ok(None) => continue,
            Err(report) => {
                warn!(
                    plugin = name,
                    command, "cannot classify this command: {report}"
                );
                continue;
            }
        };
        let Some(fingerprint) = plugin
            .fingerprints
            .iter()
            .find(|declared| **declared == verdict.fingerprint)
        else {
            warn!(
                plugin = name,
                fingerprint = %verdict.fingerprint,
                "answered with a fingerprint it does not declare; ignoring the verdict"
            );
            continue;
        };
        let capabilities: BTreeSet<Capability> = verdict
            .capabilities
            .into_iter()
            .map(convert::capability)
            .filter(|wanted| plugin.manifest.grants_at_most.contains(wanted))
            .collect();
        return Ok(Some((fingerprint, capabilities.into_iter().collect())));
    }
    Ok(None)
}

/// The bundled scanner that reads files with this extension, if any.
///
/// `extension` is compared exactly, case included, as the compiled-in language table
/// compared it: `.C` is not read as C.
///
/// # Errors
///
/// As [`sources`].
pub fn scanner_for(extension: &str) -> Result<Option<&'static Loaded>> {
    Ok(sources()?.iter().find(|plugin| {
        plugin.manifest.hooks.contains(&Hook::ScanSource)
            && plugin.manifest.source_extensions.contains(extension)
    }))
}

/// Ask `scanner` what the file at `relative` implies the built program needs.
///
/// Its grants are recorded as [`Provenance::SourceAnalysis`] with the scanner's own
/// evidence line, exactly as the compiled-in scanner recorded them. A scanner that traps
/// costs this file's grants and a `warn` line, never the scan.
#[must_use]
pub fn scan_source(scanner: &'static Loaded, relative: &str, contents: &str) -> Vec<Grant> {
    let name = scanner.manifest.name.as_str();
    let file = WitSourceFile {
        path: relative.to_owned(),
        contents: contents.to_owned(),
    };
    let answer = with_live(scanner, |live| {
        live.call(name, |bindings, store| {
            bindings.call_scan_source(store, &file)
        })
    });
    match answer {
        Ok(grants) => grants
            .into_iter()
            .map(|grant| {
                let permission = match grant.permission {
                    WitPermission::ReadPath(path) => Permission::ReadPath(path.into()),
                    WitPermission::WritePath(path) => Permission::WritePath(path.into()),
                    WitPermission::ExecPath(path) => Permission::ExecPath(path.into()),
                    WitPermission::Network => Permission::Network,
                    WitPermission::Spawn => Permission::Spawn,
                };
                Grant::new(permission, Provenance::SourceAnalysis, [grant.evidence])
            })
            .collect(),
        Err(report) => {
            warn!(
                plugin = name,
                file = %relative,
                "cannot scan this file; its grants are missing from the profile: {report}"
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The concatenated fingerprint list is the precedence order the compiled-in table
    /// had. Moving a plugin or a fingerprint changes which one wins a tie and what the
    /// "no fingerprint matched" diagnostic lists, so it has to be a decision.
    #[test]
    fn fingerprint_precedence_is_unchanged() {
        assert_eq!(
            fingerprint_names().expect("bundled classifiers load"),
            [
                "make",
                "configure",
                "cmake",
                "ninja",
                "meson",
                "cargo",
                "go",
                "node",
                "pip",
                "python",
                "pkg-config",
                "compiler",
                "ld",
                "coreutils",
                "shell",
                "archive",
                "git",
            ]
        );
    }

    #[test]
    fn every_classifier_classifies_and_every_scanner_scans() {
        for plugin in commands().expect("bundled classifiers load") {
            assert!(plugin.manifest.hooks.contains(&Hook::ClassifyCommand));
            assert!(!plugin.fingerprints.is_empty(), "{}", plugin.manifest.name);
        }
        for plugin in sources().expect("bundled scanners load") {
            assert!(plugin.manifest.hooks.contains(&Hook::ScanSource));
            assert!(plugin.fingerprints.is_empty(), "{}", plugin.manifest.name);
        }
    }

    /// Two scanners claiming one extension would make which grammar reads a file depend
    /// on order, which nothing else about scanning does.
    #[test]
    fn no_extension_is_claimed_twice() {
        let mut seen = BTreeSet::new();
        for plugin in sources().expect("bundled scanners load") {
            for extension in &plugin.manifest.source_extensions {
                assert!(
                    seen.insert(extension.clone()),
                    "`.{extension}` is claimed twice, the second time by `{}`",
                    plugin.manifest.name
                );
            }
        }
        assert_eq!(
            seen.into_iter().collect::<Vec<_>>(),
            [
                "bash", "c", "c++", "cc", "cpp", "cxx", "go", "h", "hh", "hpp", "hxx", "py", "pyi",
                "rs", "sh"
            ]
        );
    }
}
