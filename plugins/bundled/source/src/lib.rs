//! The tree-sitter query engine behind the bundled `*-source` plugins.
//!
//! Every file pm hands over is parsed with tree-sitter and matched against a table of
//! tree-sitter *queries* - patterns written against the syntax tree, not against the
//! text. That distinction is the whole point: a query for a call to `socket` matches a
//! `call_expression` whose function identifier *is* `socket`, so `my_socket_wrapper()`,
//! the word `connection`, `disconnect()`, a commented-out `socket()` and the word
//! `"system"` inside a string all fail to match for free, structurally, with no
//! exclusion list to maintain. Textual matching gets every one of those wrong.
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
//! which is why pm records these grants as source analysis, merges them with its other
//! signals, and keeps a derived profile in audit mode until a human promotes it.
//!
//! # One instance, many files
//!
//! pm keeps a bundled plugin's instance alive across calls on the same thread, so the
//! queries below are compiled once per instance rather than once per file. Compiling a
//! tree-sitter query is orders of magnitude more expensive than running one.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, hash_map::Entry},
    path::{Path, PathBuf},
    rc::Rc,
};

pub use bundled::Permission;
pub use tree_sitter;
use tree_sitter::{Language as Grammar, Node, Parser, Query, QueryCursor, StreamingIterator as _};

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
    /// The tree-sitter query source, compiled once per instance.
    pub query: &'static str,
    /// What every match implies regardless of its captures.
    pub implies: Implies,
}

/// The pathless permission a query implies on every match. Path permissions come from
/// the captures, which is the only place the path is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implies {
    /// Nothing beyond what the captures say.
    Nothing,
    /// [`Permission::Network`].
    Network,
    /// [`Permission::Spawn`].
    Spawn,
}

/// One language: how its files are recognised and what is asked of them.
#[derive(Debug)]
pub struct Language {
    /// The grammar's name: `c`, `cpp`, `rust`, `python`, `go` or `bash`.
    pub name: &'static str,
    /// File extensions, without the dot, that select this language. Compared exactly,
    /// case included.
    pub extensions: &'static [&'static str],
    /// Loads the tree-sitter grammar the queries are written against.
    pub grammar: fn() -> Grammar,
    /// The queries run against every file of this language.
    pub queries: &'static [SourceQuery],
}

/// A language with its grammar loaded and its queries compiled.
struct Compiled {
    rules: &'static Language,
    grammar: Grammar,
    queries: Vec<Query>,
}

thread_local! {
    /// One [`Parser`] per language. `Parser` is neither `Send` nor `Sync`, and an
    /// instance only ever runs on one thread anyway.
    static PARSERS: RefCell<HashMap<&'static str, Parser>> = RefCell::new(HashMap::new());

    /// Every [`Scanner`]'s compiled languages, keyed by the address of its table.
    static COMPILED: RefCell<HashMap<usize, Rc<Vec<Compiled>>>> = RefCell::new(HashMap::new());
}

/// A plugin's languages, compiled on first use.
pub struct Scanner {
    languages: &'static [Language],
}

impl Scanner {
    /// A scanner over `languages`.
    #[must_use]
    pub const fn new(languages: &'static [Language]) -> Self {
        Self { languages }
    }

    /// The languages, for tests.
    #[must_use]
    pub fn languages(&self) -> &'static [Language] {
        self.languages
    }

    /// The grammars and compiled queries, built the first time this thread needs them.
    ///
    /// Thread-local rather than in `self` because tree-sitter's grammar and query types
    /// are neither `Send` nor `Sync` on this target; a WebAssembly instance has only the
    /// one thread anyway.
    fn compiled(&self) -> Rc<Vec<Compiled>> {
        let key = self.languages.as_ptr() as usize;
        COMPILED.with(|compiled| {
            Rc::clone(
                compiled
                    .borrow_mut()
                    .entry(key)
                    .or_insert_with(|| Rc::new(self.compile())),
            )
        })
    }

    fn compile(&self) -> Vec<Compiled> {
        self.languages
            .iter()
            .map(|rules| {
                let grammar = (rules.grammar)();
                let queries = rules
                    .queries
                    .iter()
                    .map(|rule| {
                        Query::new(&grammar, rule.query).unwrap_or_else(|error| {
                            panic!("query `{}` does not compile: {error}", rule.name)
                        })
                    })
                    .collect();
                Compiled {
                    rules,
                    grammar,
                    queries,
                }
            })
            .collect()
    }
}

impl bundled::Sources for Scanner {
    fn extensions(&self) -> Vec<String> {
        self.languages
            .iter()
            .flat_map(|language| language.extensions.iter().map(|ext| (*ext).to_owned()))
            .collect()
    }

    /// Run every query of the language `path`'s extension selects over `source`.
    ///
    /// Never fails: an unparseable file yields nothing. A file that parses *with*
    /// `ERROR` nodes is still queried: tree-sitter recovers locally, so the rest of the
    /// tree is as good as ever.
    fn scan(&self, path: &str, source: &str) -> Vec<(Permission, String)> {
        let Some(extension) = Path::new(path).extension().and_then(|e| e.to_str()) else {
            return Vec::new();
        };
        let compiled = self.compiled();
        let Some(language) = compiled
            .iter()
            .find(|language| language.rules.extensions.contains(&extension))
        else {
            return Vec::new();
        };
        let Some(tree) = parse(language, source) else {
            return Vec::new();
        };

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
                record(&mut findings, &captures, rule, source, path);
            }
        }
        findings.into_grants(path)
    }
}

/// Parse `source` with this thread's parser for `language`.
fn parse(language: &Compiled, source: &str) -> Option<tree_sitter::Tree> {
    PARSERS.with(|parsers| {
        let mut parsers = parsers.borrow_mut();
        let parser = match parsers.entry(language.rules.name) {
            Entry::Occupied(occupied) => occupied.into_mut(),
            Entry::Vacant(vacant) => {
                let mut parser = Parser::new();
                parser.set_language(&language.grammar).ok()?;
                vacant.insert(parser)
            }
        };
        parser.parse(source, None)
    })
}

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
        let implied = match rule.implies {
            Implies::Nothing => None,
            Implies::Network => Some(Permission::Network),
            Implies::Spawn => Some(Permission::Spawn),
        };
        if let Some(permission) = implied {
            findings.add(permission, evidence(relative, anchor, rule));
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
    /// flatten what is left into one `(permission, evidence line)` pair per line.
    ///
    /// A path opened for writing in this file is not *also* evidence of a read - the
    /// generic string-literal query saw the same literal the `fopen`-with-mode query saw,
    /// and only the second one knew what it meant.
    fn into_grants(self, relative: &str) -> Vec<(Permission, String)> {
        let written: Vec<PathBuf> = self
            .hits
            .keys()
            .filter_map(|permission| match permission {
                Permission::WritePath(path) => Some(path.clone()),
                _ => None,
            })
            .collect();

        let mut out = Vec::new();
        for (permission, mut evidence) in self.hits {
            if let Permission::ReadPath(path) = &permission
                && written.contains(path)
            {
                continue;
            }
            if evidence.extra > 0 {
                evidence
                    .lines
                    .push(format!("{relative}: {} more match(es)", evidence.extra));
            }
            for line in evidence.lines {
                out.push((permission.clone(), line));
            }
        }
        out
    }
}
