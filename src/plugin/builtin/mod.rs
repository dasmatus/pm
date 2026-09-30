//! pm's own tables, organised as plugins that are compiled in.
//!
//! pm answers the same two questions a WebAssembly plugin does - what a build-step
//! command needs from the jail, and what a source file implies the built program needs
//! at run time - from tables of its own. Those tables used to be two monoliths, one in
//! [`crate::policy`] and one in [`crate::perms::source`], each covering every ecosystem
//! pm knows at once. Here they are split by ecosystem instead: everything pm knows
//! about Go, say, is in [`go`], fingerprint and grammar together, the way a
//! [`crate::plugin::Plugin`] for Zig carries both of Zig's answers.
//!
//! # What a built-in plugin is, and what it is not
//!
//! A [`Builtin`] is **data**: fingerprints for `classify-command` and tree-sitter
//! languages for `scan-source`. [`crate::policy`] and [`crate::perms::source`] read it
//! and run the same engines they always ran. None of the WebAssembly machinery applies,
//! because none of it is needed: a built-in is part of the pm that was signed and
//! installed, so there is no key to check, no ceiling to hold it to and no fuel to
//! meter.
//!
//! What it keeps is the one thing about the old tables that mattered for security:
//! **built-ins are consulted first**. A loaded plugin is still only asked about a
//! command no built-in fingerprint matched, so no loaded plugin can reclassify `cargo`
//! or `git`. Built-in fingerprint names are recorded unprefixed (`cargo`, not
//! `rust:cargo`), exactly as they always were, so a policy serialised by an earlier pm
//! still deserialises and a digest does not move.
//!
//! # Order
//!
//! Fingerprints are matched first-wins, in the order [`all`] lists the plugins and then
//! the order each plugin lists its fingerprints. That concatenation is the precedence
//! order the monolithic table had, and a test below holds it there, because it is also
//! the order `pm` prints the known fingerprints in when a command matches none.

use crate::{
    perms::{Permission, source::LanguageRules},
    policy::{Capability, Fingerprint},
};

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
macro_rules! program {
    ($alternation:literal) => {
        concat!(r"^(?:[\w.+/-]*/)?(?:", $alternation, r")(?:\s|$)")
    };
}

/// As [`program!`], but also allowing up to four leading `word-` groups, so
/// `aarch64-unknown-linux-gnu-gcc` matches wherever `gcc` does. Used only for
/// the toolchain programs that are conventionally named after a target triple.
macro_rules! prefixed_program {
    ($alternation:literal) => {
        concat!(
            r"^(?:[\w.+/-]*/)?(?:[A-Za-z0-9_]+-){0,4}(?:",
            $alternation,
            r")(?:\s|$)"
        )
    };
}

/// Autotools, CMake, Meson, Ninja and make.
mod buildsys;
/// The C and C++ toolchain, and the C and C++ grammars.
mod c;
/// Version control.
mod git;
/// The Go toolchain and the Go grammar.
mod go;
/// npm and friends.
mod node;
/// Coreutils, the shells, archivers, and the Bash grammar.
mod posix;
/// pip, the Python interpreter, and the Python grammar.
mod python;
/// Cargo and the Rust grammar.
mod rust;

/// One ecosystem's worth of what pm knows, compiled in.
#[derive(Debug)]
pub struct Builtin {
    /// Identifies the plugin in documentation and tests: 1-32 characters of `a-z`,
    /// `0-9` and `-`, the same charset a loaded plugin's name is held to.
    pub name: &'static str,
    /// One line saying what it covers.
    pub summary: &'static str,
    /// Its `classify-command` table, in precedence order.
    pub fingerprints: &'static [Fingerprint],
    /// Its `scan-source` languages.
    pub languages: &'static [LanguageRules],
}

/// Every built-in plugin, in precedence order. See the module documentation.
static BUILTINS: [&Builtin; 8] = [
    &buildsys::PLUGIN,
    &rust::PLUGIN,
    &go::PLUGIN,
    &node::PLUGIN,
    &python::PLUGIN,
    &c::PLUGIN,
    &posix::PLUGIN,
    &git::PLUGIN,
];

/// Every built-in plugin, in the order their fingerprints are matched.
#[must_use]
pub fn all() -> &'static [&'static Builtin] {
    &BUILTINS
}

/// Permissions a match implies, as `'static` arrays so the query tables stay plain
/// constants. [`Permission`] owns a `PathBuf` and so cannot be promoted out of a
/// temporary, but a named `static` is never dropped and holds one fine.
static WANTS_NETWORK: [Permission; 1] = [Permission::Network];
static WANTS_SPAWN: [Permission; 1] = [Permission::Spawn];
static WANTS_NOTHING: [Permission; 0] = [];

/// The capabilities most build systems need: a toolchain to drive, the files to
/// shuffle, and the shell every recipe line runs through.
static BUILD_SYSTEM: [Capability; 3] = [
    Capability::Toolchain,
    Capability::Coreutils,
    Capability::Shell,
];

/// What a language package manager needs: it compiles, and it downloads its own
/// dependency graph.
static FETCHING_TOOLCHAIN: [Capability; 3] = [
    Capability::Toolchain,
    Capability::Coreutils,
    Capability::Network,
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use tree_sitter::{Language, Query};

    use super::*;

    /// The concatenated table is the precedence order the monolithic one had. Moving a
    /// plugin or a fingerprint changes which one wins a tie and what the "no fingerprint
    /// matched" diagnostic lists, so it has to be a decision rather than an accident.
    #[test]
    fn fingerprint_precedence_is_unchanged() {
        let names: Vec<&str> = all()
            .iter()
            .flat_map(|plugin| plugin.fingerprints)
            .map(|fingerprint| fingerprint.name)
            .collect();
        assert_eq!(
            names,
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
    fn names_are_unique_and_well_formed() {
        let mut seen = BTreeSet::new();
        for plugin in all() {
            assert!(
                (1..=32).contains(&plugin.name.len())
                    && plugin
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "`{}` is not a usable plugin name",
                plugin.name
            );
            assert!(seen.insert(plugin.name), "`{}` is taken twice", plugin.name);
            assert!(
                !plugin.fingerprints.is_empty() || !plugin.languages.is_empty(),
                "`{}` contributes nothing",
                plugin.name
            );
        }
    }

    /// Two languages claiming one extension would make which grammar reads a file depend
    /// on plugin order, which nothing else about scanning does.
    #[test]
    fn no_extension_is_claimed_twice() {
        let mut seen = BTreeSet::new();
        for rules in all().iter().flat_map(|plugin| plugin.languages) {
            for extension in rules.extensions {
                assert!(
                    seen.insert(*extension),
                    "`.{extension}` is claimed twice, the second time by `{}`",
                    rules.name
                );
            }
        }
    }

    /// Every query compiles against the grammar it ships with.
    #[test]
    fn every_query_compiles() {
        for rules in all().iter().flat_map(|plugin| plugin.languages) {
            let language: Language = (rules.grammar)();
            for query in rules.queries {
                Query::new(&language, query.query)
                    .unwrap_or_else(|error| panic!("`{}` does not compile: {error}", query.name));
            }
        }
    }

    /// Every query name is prefixed with its language, so an evidence line says which
    /// grammar produced it.
    #[test]
    fn query_names_carry_their_language() {
        for rules in all().iter().flat_map(|plugin| plugin.languages) {
            for query in rules.queries {
                assert!(
                    query.name.starts_with(&format!("{}:", rules.name)),
                    "`{}` does not name `{}`",
                    query.name,
                    rules.name
                );
            }
        }
    }
}
