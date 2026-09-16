//! Permissions inferred by parsing the package's own source code.
//!
//! Every supported source file under a directory is parsed with tree-sitter and matched
//! against a table of tree-sitter *queries* - patterns written against the syntax tree,
//! not against the text. That distinction is the whole point of this module: a query for
//! a call to `socket` matches a [`call_expression`] whose function identifier *is*
//! `socket`, so `my_socket_wrapper()`, the word `connection`, `disconnect()`, a
//! commented-out `socket()` and the word `"system"` inside a string all fail to match
//! for free, structurally, with no exclusion list to maintain. Textual matching gets
//! every one of those wrong.
//!
//! The same structure is what makes the read/write split honest. A string literal
//! `"/var/log/app.log"` says nothing on its own; the query binds it *together with* the
//! mode argument of the enclosing call, so `fopen(path, "a")` and
//! `open(path, O_WRONLY | O_CREAT)` become [`Permission::WritePath`] while
//! `fopen(path, "r")` becomes [`Permission::ReadPath`] - decided from the same call node,
//! never from proximity in the file.
//!
//! # What this does NOT see
//!
//! Source analysis is a *starting point for a profile, not an authority*. It is blind to:
//!
//! - **dynamically constructed paths** - `sprintf(buf, "%s/%s", dir, name)`, `PathBuf::push`,
//!   anything assembled at run time. Literals holding `%` or `{` are skipped outright
//!   rather than recorded as a path that never existed;
//! - **`dlopen` and friends** - the library named there is a run-time decision;
//! - **macros and code generation** - the C preprocessor runs *after* this, `build.rs`
//!   output is not in the tree, and a Rust macro body that expands to a `socket` call
//!   parses as a macro invocation;
//! - **indirect calls** - a `socket` reached through a function pointer, a vtable, a
//!   `dyn Trait` or a Python attribute lookup has no `socket` identifier to match;
//! - **dependencies** - only the package's own tree is walked, so a crate or module that
//!   opens the network on the package's behalf leaves no trace here;
//! - **name collisions** - matching is by name, so a local function called `bind` reads
//!   exactly like libc's.
//!
//! The first four make this signal **under**-approximate and the last **over**-approximate,
//! which is why the module produces [`Provenance::SourceAnalysis`] grants to be merged with
//! the other two signals rather than a profile on its own, and why a derived profile stays
//! at [`Enforcement::Audit`] until a human promotes it.
//!
//! [`call_expression`]: https://tree-sitter.github.io/tree-sitter/using-parsers/queries/
//! [`Enforcement::Audit`]: crate::perms::Enforcement::Audit

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, hash_map::Entry},
    fs,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use miette::{IntoDiagnostic, Result, WrapErr, miette};
use rayon::prelude::*;
use tracing::debug;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor, StreamingIterator as _, Tree};
use walkdir::WalkDir;

use crate::perms::{Grant, Permission, Permissions, Provenance};

/// One tree-sitter query and the permissions a match implies.
///
/// `query` is matched against the whole file. Capture names carry the meaning:
///
/// | capture        | meaning                                                          |
/// |----------------|------------------------------------------------------------------|
/// | `@call`        | the node to blame in the evidence line; optional                 |
/// | `@path`        | a literal that may name a path - read, unless `@mode` says write |
/// | `@write.path`  | a literal that is written unconditionally                        |
/// | `@exec.path`   | a literal naming a program to execute                            |
/// | `@mode`        | the text deciding whether `@path` is written (see below)         |
/// | anything else  | structural only, conventionally named `@_thing`                  |
///
/// A `@mode` capture that is a string literal is read as a `fopen` mode (write when it
/// holds `w`, `a` or `+`); any other `@mode` node is read as open flags (write when its
/// text mentions `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_CREATE`, `O_APPEND` or `O_TRUNC`).
/// Because the query binds `@path` and `@mode` from the same call node, this is a
/// structural decision rather than a guess from what happens to be nearby.
#[derive(Debug)]
pub struct SourceQuery {
    /// Stable identifier, printed in the evidence line, e.g. `c:fopen-mode`.
    pub name: &'static str,
    /// The tree-sitter query source, compiled once per process.
    pub query: &'static str,
    /// Permissions every match implies regardless of its captures.
    ///
    /// Only the pathless variants ([`Permission::Network`], [`Permission::Spawn`]) can
    /// appear here; path permissions come from the captures, which is the only place the
    /// path is known.
    pub implies: &'static [Permission],
}

/// One language: how its files are recognised and what is asked of them.
#[derive(Debug)]
pub struct LanguageRules {
    /// The grammar's name: `c`, `cpp`, `rust`, `python`, `go` or `bash`.
    pub name: &'static str,
    /// File extensions, without the dot, that select this language.
    pub extensions: &'static [&'static str],
    /// The queries run against every file of this language.
    pub queries: &'static [SourceQuery],
}

/// Parse every supported source file under `dir` and infer what the built program needs.
///
/// Files are walked once, then parsed and queried in parallel. Anything that is not a
/// recognised extension, is larger than [`MAX_FILE_BYTES`], lives under `.git`, `target`,
/// `node_modules` or `vendor`, is not valid UTF-8, or looks binary is skipped silently -
/// a real source tree is full of all five. A file that fails to parse is skipped with a
/// `debug` log rather than failing the scan, and a file that parses *with* `ERROR` nodes
/// is still queried: tree-sitter recovers locally, so the rest of the tree is as good as
/// ever.
///
/// The result is always [`Provenance::SourceAnalysis`] and always incomplete - see the
/// module documentation for the six things it cannot see. It is meant to be merged with
/// the runtime and ELF signals, and it never justifies enforcing anything on its own.
///
/// # Errors
///
/// Diagnostic if `dir` cannot be walked, or if a grammar fails to load or one of the
/// built-in queries fails to compile - both of which are bugs in this module rather than
/// anything about `dir`.
pub fn scan(dir: &Path) -> Result<Permissions> {
    let languages = compiled()?;
    let files = collect(dir, languages)?;
    debug!(dir = %dir.display(), files = files.len(), "scanning sources");

    let grants: Vec<Grant> = files
        .par_iter()
        .flat_map_iter(|(path, language)| scan_file(dir, path, language))
        .collect();

    let permissions: Permissions = grants.into_iter().collect();
    debug!(
        dir = %dir.display(),
        grants = permissions.len(),
        "source analysis finished"
    );
    Ok(permissions)
}

/// The languages understood and the queries applied to each.
///
/// Exposed so `pm` can print what it looks for - a user asking why a package got no
/// network permission deserves to see the list that came up empty.
pub fn languages() -> &'static [LanguageRules] {
    &RULES
}

/// Largest file that is parsed. Past this it is generated, minified or vendored data,
/// and parsing it costs far more than the matches are worth.
pub const MAX_FILE_BYTES: u64 = 1 << 20;

/// Directory names never descended into.
const SKIPPED_DIRS: [&str; 6] = [
    ".git",
    "target",
    "node_modules",
    "vendor",
    ".venv",
    "__pycache__",
];

/// Path prefixes that make a string literal interesting. Anything else is a relative
/// path, a URL, a format string or prose, and recording it would bury the real grants.
const SYSTEM_PREFIXES: [&str; 7] = [
    "/etc/",
    "/var/",
    "/usr/share/",
    "/dev/",
    "/run/",
    "/proc/",
    "/sys/",
];

/// How many evidence lines one permission keeps per file before they are merely counted.
/// A shell script with two hundred commands should not put two hundred lines in the
/// report; three locators and a tally are enough to go and look.
const EVIDENCE_PER_FILE: usize = 3;

/// Bytes sniffed for a NUL before deciding a file is binary.
const BINARY_SNIFF: usize = 8192;

/// What a captured literal turns into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// `@path` with no write-ish mode: a read.
    Read,
    /// `@write.path`, or `@path` whose `@mode` says write.
    Write,
    /// `@exec.path`: a program name.
    Exec,
}

/// A language with its grammar loaded and its queries compiled.
struct Compiled {
    rules: &'static LanguageRules,
    language: Language,
    queries: Vec<Query>,
}

/// Grammars and queries, built once per process.
///
/// Compiling a tree-sitter query is orders of magnitude more expensive than running one,
/// so doing it per file would dominate the scan. The error is kept as a `String` because
/// [`LazyLock`] hands out `&T` and `tree_sitter::QueryError` is not `Clone`; every caller
/// turns it back into a diagnostic in [`compiled`].
static COMPILED: LazyLock<std::result::Result<Vec<Compiled>, String>> = LazyLock::new(compile);

thread_local! {
    /// One [`Parser`] per language per thread.
    ///
    /// `Parser::parse` takes `&mut self`, so a single shared parser would have to sit
    /// behind a mutex and serialise the whole scan no matter how many threads rayon
    /// runs. Giving each worker its own parser keeps the parse parallel and makes a data
    /// race impossible without any locking; the compiled [`Query`] values, which *are*
    /// `Sync` and read-only, stay shared in [`COMPILED`].
    static PARSERS: RefCell<HashMap<&'static str, Parser>> = RefCell::new(HashMap::new());
}

/// The grammars and queries, or a diagnostic if the built-in table is broken.
fn compiled() -> Result<&'static [Compiled]> {
    match &*COMPILED {
        Ok(languages) => Ok(languages),
        Err(error) => Err(miette!("{error}")).wrap_err("built-in source queries are broken"),
    }
}

/// Load every grammar and compile every query in [`RULES`].
fn compile() -> std::result::Result<Vec<Compiled>, String> {
    RULES
        .iter()
        .map(|rules| {
            let language = grammar(rules.name)
                .ok_or_else(|| format!("no grammar is wired up for language `{}`", rules.name))?;
            let queries = rules
                .queries
                .iter()
                .map(|rule| {
                    Query::new(&language, rule.query)
                        .map_err(|error| format!("query `{}` does not compile: {error}", rule.name))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(Compiled {
                rules,
                language,
                queries,
            })
        })
        .collect()
}

/// The grammar behind a [`LanguageRules::name`].
fn grammar(name: &str) -> Option<Language> {
    Some(match name {
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "bash" => tree_sitter_bash::LANGUAGE.into(),
        _ => return None,
    })
}

/// Every parseable file under `dir`, paired with the language that claims it.
///
/// Walking is serial and deliberately so: it is one `readdir` storm that parallelises
/// badly, and it produces the work list the parallel phase then chews through.
///
/// # Errors
///
/// Diagnostic if a directory cannot be read.
fn collect<'a>(dir: &Path, languages: &'a [Compiled]) -> Result<Vec<(PathBuf, &'a Compiled)>> {
    let mut files = Vec::new();
    let walk = WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            !entry
                .file_name()
                .to_str()
                .is_some_and(|name| SKIPPED_DIRS.contains(&name))
        });

    for entry in walk {
        let entry = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("walking {} for source files", dir.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(extension) = entry.path().extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let Some(language) = languages
            .iter()
            .find(|language| language.rules.extensions.contains(&extension))
        else {
            continue;
        };
        match entry.metadata() {
            Ok(metadata) if metadata.len() > MAX_FILE_BYTES => {
                let bytes = metadata.len();
                debug!(path = %entry.path().display(), bytes, "skipping oversized file");
                continue;
            }
            Ok(_) => files.push((entry.path().to_path_buf(), language)),
            Err(error) => {
                debug!(path = %entry.path().display(), %error, "skipping unstattable file")
            }
        }
    }
    Ok(files)
}

/// Run every query of `language` over one file and turn the matches into grants.
///
/// Never fails: an unreadable, binary, non-UTF-8 or unparseable file yields no grants and
/// a `debug` line. Source trees are full of such files and none of them is a reason to
/// abandon the scan.
fn scan_file(root: &Path, path: &Path, language: &Compiled) -> Vec<Grant> {
    let Ok(bytes) = fs::read(path) else {
        debug!(path = %path.display(), "skipping unreadable file");
        return Vec::new();
    };
    if bytes.iter().take(BINARY_SNIFF).any(|byte| *byte == 0) {
        debug!(path = %path.display(), "skipping binary file");
        return Vec::new();
    }
    let Ok(source) = String::from_utf8(bytes) else {
        debug!(path = %path.display(), "skipping non-UTF-8 file");
        return Vec::new();
    };
    let Some(tree) = parse(language, &source) else {
        debug!(path = %path.display(), language = language.rules.name, "skipping unparseable file");
        return Vec::new();
    };

    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    let mut findings = Findings::default();
    for (query, rule) in language.queries.iter().zip(language.rules.queries) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
        while let Some(matched) = matches.next() {
            let captures: Vec<(&str, Node<'_>)> = matched
                .captures()
                .iter()
                .filter_map(|capture| {
                    let name = query.capture_names().get(capture.index as usize)?;
                    Some((*name, capture.node))
                })
                .collect();
            record(&mut findings, &captures, rule, &source, &relative);
        }
    }
    findings.into_grants(&relative)
}

/// Parse `source` with this thread's parser for `language`.
fn parse(language: &Compiled, source: &str) -> Option<Tree> {
    PARSERS.with(|parsers| {
        let mut parsers = parsers.borrow_mut();
        let parser = match parsers.entry(language.rules.name) {
            Entry::Occupied(occupied) => occupied.into_mut(),
            Entry::Vacant(vacant) => {
                let mut parser = Parser::new();
                parser.set_language(&language.language).ok()?;
                vacant.insert(parser)
            }
        };
        parser.parse(source, None)
    })
}

/// Turn one query match into findings.
fn record(
    findings: &mut Findings,
    captures: &[(&str, Node<'_>)],
    rule: &SourceQuery,
    source: &str,
    relative: &str,
) {
    let mode = captures
        .iter()
        .find(|(name, _)| *name == "mode")
        .and_then(|(_, node)| text(source, *node));
    let writes = mode.is_some_and(is_write_mode);

    let anchor = captures
        .iter()
        .find(|(name, _)| *name == "call")
        .or_else(|| captures.first())
        .map(|(_, node)| *node);
    if let Some(anchor) = anchor {
        for permission in rule.implies {
            findings.add(permission.clone(), evidence(relative, anchor, rule));
        }
    }

    for (name, node) in captures {
        let role = match *name {
            "path" if writes => Role::Write,
            "path" => Role::Read,
            "write.path" => Role::Write,
            "exec.path" => Role::Exec,
            _ => continue,
        };
        let Some(literal) = text(source, *node).map(literal_text) else {
            continue;
        };
        let Some(permission) = permission_for(role, literal) else {
            continue;
        };
        findings.add(permission, evidence(relative, *node, rule));
    }
}

/// The permission a captured literal earns, if any.
///
/// Read and write literals must name one of [`SYSTEM_PREFIXES`]; an executable may be any
/// absolute path, since `/usr/bin/git` is exactly the sort of thing worth recording and
/// is under none of them. A literal holding `%` or `{` is a format string whose real path
/// is only known at run time, so it is dropped rather than recorded as a lie.
///
/// The literal is cut at its first backslash. Escapes are still in their source spelling
/// here - nothing has interpreted them - and `"/dev/urandom\0"` is the path `/dev/urandom`
/// with a NUL terminator glued on, not a directory whose name ends in a backslash and a
/// zero. Cutting there keeps the prefix that is certainly real and drops the part that is
/// only a guess.
fn permission_for(role: Role, literal: &str) -> Option<Permission> {
    let literal = match literal.find('\\') {
        Some(escape) => &literal[..escape],
        None => literal,
    };
    if literal.contains(['%', '{']) {
        debug!(literal, "ignoring dynamically constructed path");
        return None;
    }
    match role {
        Role::Exec if literal.starts_with('/') => {
            Some(Permission::ExecPath(PathBuf::from(literal)))
        }
        Role::Read if is_system_path(literal) => Some(Permission::ReadPath(PathBuf::from(literal))),
        Role::Write if is_system_path(literal) => {
            Some(Permission::WritePath(PathBuf::from(literal)))
        }
        _ => None,
    }
}

/// `<relative path>:<line>: <query name>`, with the 0-based tree-sitter row shown 1-based
/// the way every editor and compiler shows it.
fn evidence(relative: &str, node: Node<'_>, rule: &SourceQuery) -> String {
    format!(
        "{relative}:{}: {}",
        node.start_position().row + 1,
        rule.name
    )
}

/// The source text a node covers, or `None` if the range is not on a character boundary.
fn text<'a>(source: &'a str, node: Node<'_>) -> Option<&'a str> {
    source.get(node.byte_range())
}

/// Strip a literal down to its contents: any prefix (`L`, `u8`, `b`, `r`, `f`), then the
/// surrounding quotes. A bare shell word has neither and survives unchanged.
fn literal_text(raw: &str) -> &str {
    raw.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_')
        .trim_matches(['"', '\'', '`'])
}

/// Whether a literal names a path worth recording.
fn is_system_path(literal: &str) -> bool {
    SYSTEM_PREFIXES
        .iter()
        .any(|prefix| literal.starts_with(prefix))
}

/// Whether a `@mode` capture means the path is written.
///
/// A quoted capture is a `fopen`-style mode string: `w`, `a` and `+` all write, `r` and
/// `b` alone do not. Anything else is an open-flags expression, judged by the flag names
/// it mentions. Both readings look only at the node the query bound from the enclosing
/// call, so neither can drift onto an unrelated argument.
fn is_write_mode(mode: &str) -> bool {
    if mode.starts_with('"') || mode.starts_with('\'') {
        return literal_text(mode).contains(['w', 'a', '+']);
    }
    [
        "O_WRONLY", "O_RDWR", "O_CREAT", "O_CREATE", "O_APPEND", "O_TRUNC",
    ]
    .iter()
    .any(|flag| mode.contains(flag))
}

/// Evidence gathered for one permission in one file.
#[derive(Default)]
struct Evidence {
    lines: Vec<String>,
    extra: usize,
}

/// Everything one file yielded, keyed by permission so repeated matches collapse.
#[derive(Default)]
struct Findings {
    hits: BTreeMap<Permission, Evidence>,
}

impl Findings {
    /// Record one match, keeping at most [`EVIDENCE_PER_FILE`] distinct locators.
    fn add(&mut self, permission: Permission, line: String) {
        let slot = self.hits.entry(permission).or_default();
        if slot.lines.contains(&line) {
            return;
        }
        if slot.lines.len() < EVIDENCE_PER_FILE {
            slot.lines.push(line);
        } else {
            slot.extra += 1;
        }
    }

    /// Finish the file: drop reads that a write of the same path already covers, then
    /// turn what is left into grants.
    ///
    /// A path opened for writing in this file is not *also* evidence of a read - the
    /// generic string-literal query saw the same literal the `fopen`-with-mode query saw,
    /// and only the second one knew what it meant.
    fn into_grants(self, relative: &str) -> Vec<Grant> {
        // Decided as a `bool` per entry, and the borrow of `hits` ends with the
        // statement, so the map can then be consumed without cloning a single path.
        let keep: Vec<bool> = {
            let written: Vec<&Path> = self
                .hits
                .keys()
                .filter_map(|permission| match permission {
                    Permission::WritePath(path) => Some(path.as_path()),
                    _ => None,
                })
                .collect();
            self.hits
                .keys()
                .map(|permission| match permission {
                    Permission::ReadPath(path) => !written.contains(&path.as_path()),
                    _ => true,
                })
                .collect()
        };

        self.hits
            .into_iter()
            .zip(keep)
            .filter(|(_, keep)| *keep)
            .map(|((permission, mut evidence), _)| {
                if evidence.extra > 0 {
                    evidence
                        .lines
                        .push(format!("{relative}: {} more match(es)", evidence.extra));
                }
                Grant::new(permission, Provenance::SourceAnalysis, evidence.lines)
            })
            .collect()
    }
}

/// Permissions a match implies, as `'static` arrays so [`RULES`] stays a plain constant.
/// [`Permission`] owns a `PathBuf` and so cannot be promoted out of a temporary, but a
/// named `static` is never dropped and holds one fine.
static WANTS_NETWORK: [Permission; 1] = [Permission::Network];
static WANTS_SPAWN: [Permission; 1] = [Permission::Spawn];
static WANTS_NOTHING: [Permission; 0] = [];

/// Every language and every query, in the order they run.
static RULES: [LanguageRules; 6] = [
    LanguageRules {
        name: "c",
        extensions: &["c", "h"],
        queries: C_QUERIES,
    },
    LanguageRules {
        name: "cpp",
        extensions: &["cc", "cpp", "cxx", "c++", "hpp", "hh", "hxx"],
        queries: CPP_QUERIES,
    },
    LanguageRules {
        name: "rust",
        extensions: &["rs"],
        queries: RUST_QUERIES,
    },
    LanguageRules {
        name: "python",
        extensions: &["py", "pyi"],
        queries: PYTHON_QUERIES,
    },
    LanguageRules {
        name: "go",
        extensions: &["go"],
        queries: GO_QUERIES,
    },
    LanguageRules {
        name: "bash",
        extensions: &["sh", "bash"],
        queries: BASH_QUERIES,
    },
];

/// C, and the base for C++: plain identifier calls plus string literals.
static C_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "c:network-call",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#any-of? @_fn
                "socket" "socketpair" "connect" "bind" "listen" "accept" "accept4"
                "getaddrinfo" "gethostbyname" "getnameinfo" "sendto" "recvfrom")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "c:spawn-call",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#any-of? @_fn
                "fork" "vfork" "system" "popen" "posix_spawn" "posix_spawnp"
                "execl" "execlp" "execle" "execv" "execvp" "execvpe" "execve")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "c:exec-path",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list . (string_literal) @exec.path)
              (#any-of? @_fn
                "execl" "execlp" "execle" "execv" "execvp" "execvpe" "execve"
                "posix_spawn" "posix_spawnp")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "c:fopen-mode",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path . (string_literal) @mode)
              (#any-of? @_fn "fopen" "fopen64" "freopen")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "c:open-flags",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path) @mode
              (#any-of? @_fn "open" "open64" "openat")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "c:create-path",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list . (string_literal) @write.path)
              (#any-of? @_fn "creat" "mkdir" "unlink" "rename" "truncate")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "c:path-literal",
        query: r"(string_literal) @path",
        implies: &WANTS_NOTHING,
    },
];

/// C++: everything C does, plus the qualified-call and `ofstream` forms C has no node for.
static CPP_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "cpp:network-call",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#any-of? @_fn
                "socket" "socketpair" "connect" "bind" "listen" "accept"
                "getaddrinfo" "gethostbyname" "sendto" "recvfrom")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "cpp:network-call-qualified",
        query: r#"
            (call_expression
              function: (qualified_identifier name: (identifier) @_fn)
              (#any-of? @_fn
                "socket" "socketpair" "connect" "bind" "listen" "accept"
                "getaddrinfo" "gethostbyname" "sendto" "recvfrom")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "cpp:spawn-call",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#any-of? @_fn
                "fork" "vfork" "system" "popen" "posix_spawn"
                "execl" "execlp" "execv" "execvp" "execve")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "cpp:spawn-call-qualified",
        query: r#"
            (call_expression
              function: (qualified_identifier name: (identifier) @_fn)
              (#any-of? @_fn
                "fork" "vfork" "system" "popen" "posix_spawn"
                "execl" "execlp" "execv" "execvp" "execve")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "cpp:fopen-mode",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path . (string_literal) @mode)
              (#any-of? @_fn "fopen" "fopen64" "freopen")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "cpp:open-flags",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path) @mode
              (#any-of? @_fn "open" "open64" "openat")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "cpp:ofstream",
        query: r#"
            (declaration
              type: (qualified_identifier name: (type_identifier) @_ty)
              declarator: (init_declarator
                (argument_list . (string_literal) @write.path))
              (#any-of? @_ty "ofstream" "fstream" "ofstream_t")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "cpp:path-literal",
        query: r"(string_literal) @path",
        implies: &WANTS_NOTHING,
    },
];

/// Rust: `use` trees name the crate, and the standard library's constructors name the mode.
static RUST_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "rust:net-import",
        query: r#"
            (use_declaration
              [(scoped_identifier path: (scoped_identifier name: (identifier) @_m))
               (scoped_use_list path: (scoped_identifier name: (identifier) @_m))
               (scoped_identifier path: (identifier) @_m)
               (scoped_use_list path: (identifier) @_m)
               (identifier) @_m]
              (#any-of? @_m
                "net" "reqwest" "hyper" "ureq" "curl" "tonic" "socket2" "isahc")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "rust:net-call",
        query: r#"
            (call_expression
              function: (scoped_identifier
                path: (identifier) @_ty
                name: (identifier) @_fn)
              (#any-of? @_ty "TcpStream" "TcpListener" "UdpSocket" "reqwest" "hyper" "ureq")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "rust:process-import",
        query: r#"
            (use_declaration
              [(scoped_identifier path: (scoped_identifier name: (identifier) @_m))
               (scoped_use_list path: (scoped_identifier name: (identifier) @_m))]
              (#any-of? @_m "process")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "rust:command-new",
        query: r#"
            (call_expression
              function: (scoped_identifier
                path: (identifier) @_ty
                name: (identifier) @_fn)
              (#eq? @_ty "Command")
              (#eq? @_fn "new")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "rust:command-program",
        query: r#"
            (call_expression
              function: (scoped_identifier
                path: (identifier) @_ty
                name: (identifier) @_fn)
              arguments: (arguments . (string_literal) @exec.path)
              (#eq? @_ty "Command")
              (#eq? @_fn "new")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "rust:file-create",
        query: r#"
            (call_expression
              function: (scoped_identifier name: (identifier) @_fn)
              arguments: (arguments . (string_literal) @write.path)
              (#any-of? @_fn
                "create" "create_new" "create_dir" "create_dir_all"
                "write" "remove_file" "remove_dir_all" "rename")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "rust:path-literal",
        query: r"(string_literal) @path",
        implies: &WANTS_NOTHING,
    },
];

/// Python: imports are nodes, and `open`'s mode is its second argument.
static PYTHON_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "python:net-import",
        query: r#"
            (import_statement
              name: [(dotted_name (identifier) @_m)
                     (aliased_import name: (dotted_name (identifier) @_m))]
              (#any-of? @_m
                "socket" "requests" "urllib" "urllib2" "urllib3" "http" "httplib"
                "httpx" "aiohttp" "ftplib" "smtplib" "telnetlib")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "python:net-import-from",
        query: r#"
            (import_from_statement
              module_name: (dotted_name (identifier) @_m)
              (#any-of? @_m
                "socket" "requests" "urllib" "urllib2" "urllib3" "http" "httplib"
                "httpx" "aiohttp" "ftplib" "smtplib" "telnetlib")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "python:net-call",
        query: r#"
            (call
              function: (attribute object: (identifier) @_obj)
              (#any-of? @_obj "socket" "requests" "urllib" "httpx" "aiohttp")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "python:spawn-import",
        query: r#"
            (import_statement
              name: [(dotted_name (identifier) @_m)
                     (aliased_import name: (dotted_name (identifier) @_m))]
              (#any-of? @_m "subprocess" "multiprocessing" "pty")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "python:spawn-import-from",
        query: r#"
            (import_from_statement
              module_name: (dotted_name (identifier) @_m)
              (#any-of? @_m "subprocess" "multiprocessing" "pty")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "python:spawn-call",
        query: r#"
            (call
              function: (attribute
                object: (identifier) @_obj
                attribute: (identifier) @_fn)
              (#any-of? @_obj "subprocess" "os")
              (#any-of? @_fn
                "run" "call" "check_call" "check_output" "Popen" "system" "popen"
                "fork" "execv" "execvp" "execl" "execlp" "spawnv" "spawnl" "posix_spawn")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "python:open-mode",
        query: r#"
            (call
              function: (identifier) @_fn
              arguments: (argument_list (string) @path . (string) @mode)
              (#any-of? @_fn "open" "fdopen")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "python:write-call",
        query: r#"
            (call
              function: (attribute object: (identifier) @_obj attribute: (identifier) @_fn)
              arguments: (argument_list . (string) @write.path)
              (#any-of? @_obj "os" "shutil" "pathlib")
              (#any-of? @_fn
                "remove" "unlink" "rename" "mkdir" "makedirs" "rmtree" "copy" "chmod")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "python:path-literal",
        query: r"(string) @path",
        implies: &WANTS_NOTHING,
    },
];

/// Go: the import path is a string literal, so the import itself is queryable.
static GO_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "go:net-import",
        query: r#"
            (import_spec
              path: (interpreted_string_literal (interpreted_string_literal_content) @_p)
              (#any-of? @_p
                "net" "net/http" "net/url" "net/rpc" "net/smtp" "crypto/tls"
                "golang.org/x/net/http2")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "go:net-call",
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              (#any-of? @_pkg "net" "http" "tls" "smtp")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "go:spawn-import",
        query: r#"
            (import_spec
              path: (interpreted_string_literal (interpreted_string_literal_content) @_p)
              (#any-of? @_p "os/exec" "syscall")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "go:spawn-call",
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              (#any-of? @_pkg "exec" "os" "syscall")
              (#any-of? @_fn "Command" "CommandContext" "StartProcess" "Exec" "ForkExec")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "go:openfile-flags",
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              arguments: (argument_list (interpreted_string_literal) @path) @mode
              (#eq? @_pkg "os")
              (#any-of? @_fn "OpenFile")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "go:write-call",
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              arguments: (argument_list . (interpreted_string_literal) @write.path)
              (#any-of? @_pkg "os" "ioutil")
              (#any-of? @_fn
                "Create" "WriteFile" "Remove" "RemoveAll" "Mkdir" "MkdirAll" "Rename")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "go:path-literal",
        query: r"[(interpreted_string_literal) (raw_string_literal)] @path",
        implies: &WANTS_NOTHING,
    },
];

/// Bash: a command name is its own node, and a redirection target is a node too - so
/// `> /var/log/x` is a write with no heuristics at all.
static BASH_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "bash:network-command",
        query: r#"
            (command
              name: (command_name (word) @_cmd)
              (#any-of? @_cmd
                "curl" "wget" "nc" "netcat" "ftp" "sftp" "scp" "rsync" "ssh"
                "telnet" "git" "pip" "pip3" "npm" "cargo" "apt" "apt-get" "dnf")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "bash:spawn-command",
        query: r"(command name: (command_name) @call)",
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "bash:exec-command",
        query: r#"
            (command
              name: (command_name (word) @_cmd)
              argument: (word) @exec.path
              (#any-of? @_cmd "exec" "nohup" "setsid" "sudo" "env" "timeout")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "bash:redirect-write",
        query: r"(file_redirect destination: [(word) (string)] @write.path) @call",
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "bash:path-literal",
        query: r"[(word) (string) (raw_string)] @path",
        implies: &WANTS_NOTHING,
    },
];
