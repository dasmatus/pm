//! A pm plugin that teaches pm about Zig.
//!
//! The reference plugin, and a worked example of both hooks:
//!
//! * [`classify_command`] recognises `zig` invocations, which pm's built-in fingerprint
//!   table does not, so a build file that compiles Zig stops being one pm refuses to
//!   run;
//! * [`scan_source`] reads `.zig` files for the handful of `std` entry points that imply
//!   the built program will open a file, reach the network or start a child process.
//!
//! # What this can and cannot reach
//!
//! Nothing. The component imports one function, `log`, and it returns nothing. There is
//! no filesystem here, no clock, no network and no environment: pm hands over a command
//! string or a file's text and takes an answer back. Everything below is a pure function
//! over its argument, because there is nothing else available for it to be.

wit_bindgen::generate!({ path: "../../wit", world: "plugin" });

use pm::plugin::{
    host::{Level, log},
    types::{Capability, Hook, Permission},
};

/// The plugin.
struct Zig;

/// Capabilities a `zig` command is granted when it only compiles.
const COMPILING: &[Capability] = &[Capability::Toolchain, Capability::Coreutils];

/// Capabilities a `zig` command is granted when it also resolves dependencies.
const FETCHING: &[Capability] = &[
    Capability::Toolchain,
    Capability::Coreutils,
    Capability::Network,
];

/// The `zig` subcommands that resolve `build.zig.zon` dependencies, and therefore need
/// the network.
///
/// `zig build` is here because a package with a `build.zig.zon` fetches its dependencies
/// as part of the build, exactly as `cargo build` does - and pm's built-in `cargo`
/// fingerprint grants [`Capability::Network`] for that same reason.
const FETCHES: &[&str] = &["build", "fetch"];

/// The `zig` subcommands this plugin recognises at all.
///
/// An unknown subcommand gets no verdict rather than a guess: pm's answer to "no
/// fingerprint matched" is a diagnostic naming the command, which is a better outcome
/// than a jail sized by a plugin that was not sure either.
const SUBCOMMANDS: &[&str] = &[
    "build",
    "build-exe",
    "build-lib",
    "build-obj",
    "cc",
    "c++",
    "fetch",
    "fmt",
    "run",
    "test",
    "translate-c",
];

impl Guest for Zig {
    /// Name the plugin and publish the ceiling pm holds it to.
    ///
    /// The ceiling is the union of [`COMPILING`] and [`FETCHING`], and nothing else:
    /// this plugin has no reason to ask for a shell, an archiver or a version-control
    /// client, so it publishes that it never will and pm drops any verdict that does.
    fn describe() -> Manifest {
        Manifest {
            name: "zig".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            summary: "Classifies `zig` build commands and reads `.zig` sources".into(),
            hooks: vec![Hook::ClassifyCommand, Hook::ScanSource],
            grants_at_most: FETCHING.to_vec(),
            source_extensions: vec!["zig".into()],
        }
    }

    /// Classify a `zig` invocation.
    ///
    /// pm only asks about commands its own table did not match, so this never sees
    /// `make` or `cargo` and cannot reclassify them.
    ///
    /// The word matching mirrors what pm's built-in table does with a regex, and for the
    /// same reason: an optional leading directory, then the program name, then a word
    /// boundary. Without the boundary `zigzag` and `myzig` would both read as `zig`.
    fn classify_command(command: String) -> Option<Verdict> {
        let mut words = command.split_whitespace();
        let program = program_name(words.next()?)?;
        if program != "zig" {
            return None;
        }

        // `zig` on its own prints usage and exits; there is nothing to size a jail for.
        let subcommand = words.next()?;
        if !SUBCOMMANDS.contains(&subcommand) {
            log(
                Level::Debug,
                &format!("unrecognised zig subcommand `{subcommand}`; no verdict"),
            );
            return None;
        }

        let capabilities = if FETCHES.contains(&subcommand) {
            FETCHING
        } else {
            COMPILING
        };
        Some(Verdict {
            fingerprint: "zig".into(),
            capabilities: capabilities.to_vec(),
        })
    }

    /// Read a `.zig` file for the `std` entry points that imply a run-time permission.
    ///
    /// Matching is over a token stream with comments and string literals removed, not
    /// over the raw text, so a `std.net` inside a `//` comment or a doc string does not
    /// count. That is the least this can do to be honest; it is still a long way short
    /// of pm's own tree-sitter queries, which match against a *syntax tree* and can
    /// therefore bind a path literal to the call it was an argument of.
    ///
    /// A plugin is free to do better. A component can carry a whole parser - tree-sitter
    /// grammars compile to WebAssembly - and nothing here is a limit of the plugin
    /// interface, only of this example.
    fn scan_source(file: SourceFile) -> Vec<Grant> {
        let stripped = strip(&file.contents);
        let mut grants = Vec::new();
        // Two views of the same line: markers are looked for in the stripped one, so a
        // `std.net` inside a comment or a string does not count, and the path literal is
        // read out of the original, because stripping is exactly what removed it.
        for (number, (code, raw)) in stripped.lines().zip(file.contents.lines()).enumerate() {
            let line_number = number + 1;
            for (needle, marker) in MARKERS {
                if !mentions(code, needle) {
                    continue;
                }
                let permission = match marker {
                    // A path-taking call: worth recording only when the path really is a
                    // literal here. One assembled at run time names nothing.
                    Marker::Path(write) => match literal(raw) {
                        Some(path) if *write => Permission::WritePath(path),
                        Some(path) => Permission::ReadPath(path),
                        None => continue,
                    },
                    Marker::Network => Permission::Network,
                    Marker::Spawn => Permission::Spawn,
                };
                grants.push(Grant {
                    permission,
                    evidence: format!("{line_number}: {needle}"),
                });
            }
        }
        grants
    }
}

/// What a marker in [`MARKERS`] implies.
enum Marker {
    /// A call taking a path; `true` when it writes it.
    Path(bool),
    /// The program reaches the network.
    Network,
    /// The program starts a child process.
    Spawn,
}

/// The `std` entry points this plugin knows, and what each implies.
///
/// Deliberately short. Every entry is a name a reviewer can check against Zig's standard
/// library, and a list nobody can check is worse than a list that misses things - a
/// derived profile is incomplete by construction anyway, which is why pm records one in
/// audit mode.
const MARKERS: &[(&str, Marker)] = &[
    ("openFileAbsolute", Marker::Path(false)),
    ("openFile", Marker::Path(false)),
    ("readFileAlloc", Marker::Path(false)),
    ("createFileAbsolute", Marker::Path(true)),
    ("createFile", Marker::Path(true)),
    ("writeFile", Marker::Path(true)),
    ("std.net", Marker::Network),
    ("std.http", Marker::Network),
    ("std.process.Child", Marker::Spawn),
    ("execv", Marker::Spawn),
];

/// The program name of a command's first word: the last path component, or `None` when
/// the word is empty or ends in a separator.
fn program_name(word: &str) -> Option<&str> {
    let name = word.rsplit('/').next()?;
    (!name.is_empty()).then_some(name)
}

/// Whether `line` mentions `needle` at identifier boundaries on both sides.
///
/// Zig identifiers are ASCII alphanumerics and `_`, so that is the whole test - `.` is
/// a boundary like any other punctuation. It has to be: half these needles are dotted
/// paths that must not match a longer one (`std.net` is not `std.network`, and
/// `mystd.net` is not `std.net`), and the other half are method names that are *always*
/// preceded by a dot (`.openFile`). The same rule settles both, and incidentally stops
/// `openFile` from matching inside `openFileAbsolute`, so a call is never counted twice.
fn mentions(line: &str, needle: &str) -> bool {
    let boundary =
        |byte: Option<u8>| byte.is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_');
    let bytes = line.as_bytes();
    line.match_indices(needle).any(|(at, _)| {
        boundary(at.checked_sub(1).map(|before| bytes[before]))
            && boundary(bytes.get(at + needle.len()).copied())
    })
}

/// The first double-quoted literal on `line`, if it looks like a path rather than a
/// format string.
///
/// A literal holding `{` is a Zig format string and names no file, the same judgement
/// pm's own source analysis makes about `%` and `{` in a C or Rust literal.
fn literal(line: &str) -> Option<String> {
    let (_, rest) = line.split_once('"')?;
    let (text, _) = rest.split_once('"')?;
    (!text.is_empty() && !text.contains('{')).then(|| text.to_owned())
}

/// Blank out `//` comments and the contents of string literals, keeping the line
/// structure.
///
/// Newlines survive untouched, so the nth line of the result is the nth line of the
/// input and an evidence line points where the reader expects. Everything a comment or
/// a string literal held becomes a space, which is what keeps a `std.net` in a comment
/// or a `"std.http"` in a message from being read as a call.
fn strip(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut in_string = false;
    let mut in_comment = false;
    let mut escaped = false;
    let mut characters = source.chars().peekable();

    while let Some(character) = characters.next() {
        // A `//` comment ends at the newline, and Zig has no multi-line string that
        // survives one either, so a newline resets everything.
        if character == '\n' {
            in_comment = false;
            in_string = false;
            escaped = false;
            out.push('\n');
            continue;
        }
        if in_comment {
            out.push(' ');
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
                // The closing quote is kept, so the stripped line still shows that a
                // literal was there.
                out.push('"');
                continue;
            }
            out.push(' ');
            continue;
        }
        if character == '/' && characters.peek() == Some(&'/') {
            in_comment = true;
            out.push(' ');
            continue;
        }
        if character == '"' {
            in_string = true;
        }
        out.push(character);
    }
    out
}

export!(Zig);
