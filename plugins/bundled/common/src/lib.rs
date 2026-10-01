//! What pm's bundled plugins share: the fingerprint matcher behind `classify-command`,
//! the tree-sitter query engine behind `scan-source`, and the macro that turns a table
//! of either into a component exporting the `bundled` world of `wit/plugin.wit`.
//!
//! These used to be compiled into pm itself, in `src/policy.rs` and
//! `src/perms/source.rs`. They behave exactly as they did there; only where they run
//! has changed. pm embeds the components built from this crate's users, consults them
//! before any plugin loaded from disk, and records their answers unprefixed, so a build
//! policy and a permission profile come out byte-for-byte what they were.

use std::{path::PathBuf, sync::OnceLock};

pub use regex::Regex;

/// One capability a build step may need from the jail. Mirrors the WIT enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// Compilers, linkers, headers and build systems.
    Toolchain,
    /// The basic file-manipulation utilities.
    Coreutils,
    /// A POSIX shell.
    Shell,
    /// Archive and compression tools.
    Archive,
    /// The host's network namespace.
    Network,
    /// Version-control clients.
    VersionControl,
}

/// One thing the built package may do at run time. Mirrors the WIT variant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    /// Read this path, and everything under it if it is a directory.
    ReadPath(PathBuf),
    /// Write this path, and everything under it if it is a directory.
    WritePath(PathBuf),
    /// Execute this path, or anything under it if it is a directory.
    ExecPath(PathBuf),
    /// Reach the network.
    Network,
    /// Fork or exec child processes at all.
    Spawn,
}

/// What a plugin's `scan-source` does. Implemented by `bundled-source`'s scanner; a
/// plugin that only classifies commands passes [`NoSources`].
pub trait Sources: Sync {
    /// File extensions, without the dot, the plugin wants to see.
    fn extensions(&self) -> Vec<String>;
    /// What `contents`, the file at `path`, implies the built program needs, one
    /// `(permission, evidence line)` pair per line of evidence.
    fn scan(&self, path: &str, contents: &str) -> Vec<(Permission, String)>;
}

/// The [`Sources`] of a plugin that reads none.
pub struct NoSources;

impl Sources for NoSources {
    fn extensions(&self) -> Vec<String> {
        Vec::new()
    }

    fn scan(&self, _: &str, _: &str) -> Vec<(Permission, String)> {
        Vec::new()
    }
}

/// A fingerprint: a regex matched against a step command, and what a matching command
/// needs.
#[derive(Debug)]
pub struct Fingerprint {
    /// Stable identifier, recorded unprefixed in the build policy.
    pub name: &'static str,
    /// The regex, compiled once per instance.
    pub pattern: &'static str,
    /// What a command matching `pattern` is granted.
    pub capabilities: &'static [Capability],
}

/// A plugin's fingerprints, in precedence order, with their regexes compiled lazily.
pub struct Table {
    fingerprints: &'static [Fingerprint],
    compiled: OnceLock<Vec<Regex>>,
}

impl Table {
    /// A table over `fingerprints`. Order is precedence: the first match wins.
    #[must_use]
    pub const fn new(fingerprints: &'static [Fingerprint]) -> Self {
        Self {
            fingerprints,
            compiled: OnceLock::new(),
        }
    }

    /// The fingerprints, in precedence order.
    #[must_use]
    pub fn fingerprints(&self) -> &'static [Fingerprint] {
        self.fingerprints
    }

    /// The first fingerprint whose pattern matches `command`, if any.
    ///
    /// `command` is expected to be already trimmed. An empty command matches nothing,
    /// which is the right answer: pm rejects it when it runs, too.
    ///
    /// # Panics
    ///
    /// If a pattern does not compile. That is a bug in the plugin, the trap it causes is
    /// reported by pm, and the test suite compiles every pattern so it never ships.
    #[must_use]
    pub fn classify(&self, command: &str) -> Option<&'static Fingerprint> {
        if command.is_empty() {
            return None;
        }
        let compiled = self.compiled.get_or_init(|| {
            self.fingerprints
                .iter()
                .map(|fingerprint| {
                    Regex::new(fingerprint.pattern).unwrap_or_else(|error| {
                        panic!(
                            "fingerprint `{}` does not compile: {error}",
                            fingerprint.name
                        )
                    })
                })
                .collect()
        });
        self.fingerprints
            .iter()
            .zip(compiled)
            .find(|(_, regex)| regex.is_match(command))
            .map(|(fingerprint, _)| fingerprint)
    }

    /// Every capability any fingerprint grants: the plugin's published ceiling.
    #[must_use]
    pub fn ceiling(&self) -> Vec<Capability> {
        let mut all: Vec<Capability> = self
            .fingerprints
            .iter()
            .flat_map(|fingerprint| fingerprint.capabilities.iter().copied())
            .collect();
        all.sort();
        all.dedup();
        all
    }
}

/// Anchor a program name as a whole command word.
///
/// Expands to `^`, an optional leading path, the alternation, and a word
/// terminator. `concat!` needs literals, so the pieces are spelled out rather
/// than pulled from constants.
///
/// The leading path group is `(?:[\w.+/-]*/)?` and it has to end in `/`, which
/// is what keeps `evilmake` from matching `make`: there the group can only
/// match the empty string, and `make` then has to match at the very start of
/// `evilmake`, which it does not. `.` is a literal inside the character class,
/// so `./configure` is matched literally and not as "any character followed by
/// `/configure`". The trailing `(?:\s|$)` demands that the program name end
/// where the pattern says it does, so `makefile-generator` and `cmake` do not
/// match `make` either.
#[macro_export]
macro_rules! program {
    ($alternation:literal) => {
        concat!(r"^(?:[\w.+/-]*/)?(?:", $alternation, r")(?:\s|$)")
    };
}

/// As [`program!`], but also allowing up to four leading `word-` groups, so
/// `aarch64-unknown-linux-gnu-gcc` matches wherever `gcc` does. Used only for
/// the toolchain programs that are conventionally named after a target triple.
#[macro_export]
macro_rules! prefixed_program {
    ($alternation:literal) => {
        concat!(
            r"^(?:[\w.+/-]*/)?(?:[A-Za-z0-9_]+-){0,4}(?:",
            $alternation,
            r")(?:\s|$)"
        )
    };
}

/// The capabilities most build systems need: a toolchain to drive, the files to
/// shuffle, and the shell every recipe line runs through.
pub static BUILD_SYSTEM: [Capability; 3] = [
    Capability::Toolchain,
    Capability::Coreutils,
    Capability::Shell,
];

/// What a language package manager needs: it compiles, and it downloads its own
/// dependency graph.
pub static FETCHING_TOOLCHAIN: [Capability; 3] = [
    Capability::Toolchain,
    Capability::Coreutils,
    Capability::Network,
];

/// A table with nothing in it, for a plugin that only scans sources.
pub static NO_COMMANDS: Table = Table::new(&[]);

/// Export the `bundled` world from the crate this is invoked in.
///
/// ```ignore
/// bundled::plugin! {
///     name: "go",
///     summary: "the go command",
///     commands: &FINGERPRINTS,
///     sources: &bundled::NoSources,
/// }
/// ```
///
/// `commands` is a `&'static` [`Table`] and `sources` a `&'static` [`Sources`]. The
/// hooks the manifest declares follow from which of the two has anything in it.
#[macro_export]
macro_rules! plugin {
    (
        name: $name:literal,
        summary: $summary:literal,
        commands: $table:expr,
        sources: $sources:expr $(,)?
    ) => {
        ::wit_bindgen::generate!({ path: "../../../wit", world: "bundled" });

        /// The plugin.
        struct Bundled;

        fn __commands() -> &'static $crate::Table {
            $table
        }

        fn __sources() -> &'static dyn $crate::Sources {
            $sources
        }

        fn __capability(from: $crate::Capability) -> pm::plugin::types::Capability {
            use pm::plugin::types::Capability as Wit;
            match from {
                $crate::Capability::Toolchain => Wit::Toolchain,
                $crate::Capability::Coreutils => Wit::Coreutils,
                $crate::Capability::Shell => Wit::Shell,
                $crate::Capability::Archive => Wit::Archive,
                $crate::Capability::Network => Wit::Network,
                $crate::Capability::VersionControl => Wit::VersionControl,
            }
        }

        fn __permission(from: $crate::Permission) -> pm::plugin::types::Permission {
            use pm::plugin::types::Permission as Wit;
            match from {
                $crate::Permission::ReadPath(path) => Wit::ReadPath(path.display().to_string()),
                $crate::Permission::WritePath(path) => {
                    Wit::WritePath(path.display().to_string())
                }
                $crate::Permission::ExecPath(path) => Wit::ExecPath(path.display().to_string()),
                $crate::Permission::Network => Wit::Network,
                $crate::Permission::Spawn => Wit::Spawn,
            }
        }

        impl Guest for Bundled {
            fn describe() -> Manifest {
                let mut hooks = Vec::new();
                if !__commands().fingerprints().is_empty() {
                    hooks.push(pm::plugin::types::Hook::ClassifyCommand);
                }
                let extensions = __sources().extensions();
                if !extensions.is_empty() {
                    hooks.push(pm::plugin::types::Hook::ScanSource);
                }
                Manifest {
                    name: $name.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    summary: $summary.into(),
                    hooks,
                    grants_at_most: __commands()
                        .ceiling()
                        .into_iter()
                        .map(__capability)
                        .collect(),
                    source_extensions: extensions,
                    symbols: Vec::new(),
                }
            }

            fn classify_command(command: String) -> Option<Verdict> {
                let fingerprint = __commands().classify(&command)?;
                Some(Verdict {
                    fingerprint: fingerprint.name.into(),
                    capabilities: fingerprint
                        .capabilities
                        .iter()
                        .copied()
                        .map(__capability)
                        .collect(),
                })
            }

            fn scan_source(file: SourceFile) -> Vec<Grant> {
                __sources()
                    .scan(&file.path, &file.contents)
                    .into_iter()
                    .map(|(permission, evidence)| Grant {
                        permission: __permission(permission),
                        evidence,
                    })
                    .collect()
            }

            fn fingerprints() -> Vec<String> {
                __commands()
                    .fingerprints()
                    .iter()
                    .map(|fingerprint| fingerprint.name.into())
                    .collect()
            }
        }

        export!(Bundled);
    };
}
