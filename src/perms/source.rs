//! Permissions inferred by parsing the package's own source code.
//!
//! Every supported source file under a directory is parsed with tree-sitter and matched
//! against a table of tree-sitter *queries* by one of pm's
//! [bundled plugins](crate::plugin::bundled) - a WebAssembly component per language that
//! carries the grammar and the queries together, written against the syntax tree, not
//! against the text. That distinction is the whole point of this module: a query for
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
//! [`Permission::WritePath`]: crate::perms::Permission::WritePath
//! [`Permission::ReadPath`]: crate::perms::Permission::ReadPath
//! [`Provenance::SourceAnalysis`]: crate::perms::Provenance::SourceAnalysis
//! [`call_expression`]: https://tree-sitter.github.io/tree-sitter/using-parsers/queries/
//! [`Enforcement::Audit`]: crate::perms::Enforcement::Audit

use std::{
    fs,
    path::{Path, PathBuf},
};

use miette::{IntoDiagnostic, Result, WrapErr};
use rayon::prelude::*;
use tracing::debug;
use walkdir::WalkDir;

use crate::{
    perms::{Grant, Permissions},
    plugin::{Registry, bundled},
};

/// The bundled plugin that scans one language.
type Scanner = &'static bundled::Loaded;

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
/// The result is always [`Provenance::SourceAnalysis`](crate::perms::Provenance::SourceAnalysis) and always incomplete - see the
/// module documentation for the six things it cannot see. It is meant to be merged with
/// the runtime and ELF signals, and it never justifies enforcing anything on its own.
///
/// # Errors
///
/// Diagnostic if `dir` cannot be walked, or if a bundled scanner fails to load - a bug
/// in pm rather than anything about `dir`.
pub fn scan(dir: &Path) -> Result<Permissions> {
    scan_with(dir, Registry::none())
}

/// As [`scan`], also offering each file to any [`crate::plugin`] component that claimed
/// its extension.
///
/// One walk serves both: a file is read, size-checked, binary-sniffed and UTF-8-checked
/// exactly once, and whatever wants it - a bundled scanner, an installed plugin, or both - gets
/// the same text. A file with an extension *only* a plugin claimed is now collected
/// where before it was skipped, which is the point; a file both understand contributes
/// from both, and [`Permissions::merge`] unifies whatever they agree on.
///
/// Plugin grants carry [`Provenance::Plugin`](crate::perms::Provenance::Plugin) and an evidence line naming the plugin, so
/// the profile says who asked for what. They are merged in exactly like the bundled
/// ones and, exactly like the bundled ones, they are recorded in audit mode and deny
/// nothing until a human promotes the profile.
///
/// # Errors
///
/// As [`scan`]. A plugin that traps or misbehaves costs its own grants and a `warn`
/// line, never the scan.
pub fn scan_with(dir: &Path, plugins: &Registry) -> Result<Permissions> {
    let files = collect(dir, plugins)?;
    debug!(
        dir = %dir.display(),
        files = files.len(),
        plugins = plugins.len(),
        "scanning sources"
    );

    let grants: Vec<Grant> = files
        .par_iter()
        .flat_map_iter(|(path, scanner)| scan_file(dir, path, *scanner, plugins))
        .collect();

    let permissions: Permissions = grants.into_iter().collect();
    debug!(
        dir = %dir.display(),
        grants = permissions.len(),
        "source analysis finished"
    );
    Ok(permissions)
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

/// Bytes sniffed for a NUL before deciding a file is binary.
const BINARY_SNIFF: usize = 8192;

/// Every parseable file under `dir`, paired with the bundled scanner that claims it.
///
/// Walking is serial and deliberately so: it is one `readdir` storm that parallelises
/// badly, and it produces the work list the parallel phase then chews through.
///
/// # Errors
///
/// Diagnostic if a directory cannot be read.
fn collect(dir: &Path, plugins: &Registry) -> Result<Vec<(PathBuf, Option<Scanner>)>> {
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
        let scanner = bundled::scanner_for(extension)?;
        // A file no bundled scanner knows is still worth collecting when a plugin asked for its
        // extension; a file nothing at all wants is skipped as it always was.
        if scanner.is_none() && !plugins.wants_extension(extension) {
            continue;
        }
        match entry.metadata() {
            Ok(metadata) if metadata.len() > MAX_FILE_BYTES => {
                let bytes = metadata.len();
                debug!(path = %entry.path().display(), bytes, "skipping oversized file");
                continue;
            }
            Ok(_) => files.push((entry.path().to_path_buf(), scanner)),
            Err(error) => {
                debug!(path = %entry.path().display(), %error, "skipping unstattable file")
            }
        }
    }
    Ok(files)
}

/// Offer one file to its bundled scanner and every interested plugin.
///
/// The file is read and filtered once here, and `scanner` is `None` for a file that
/// only a plugin asked for. Never fails: an unreadable, binary or non-UTF-8 file yields
/// no grants and a `debug` line, and a scanner that traps costs this file's grants and a
/// `warn` line. Source trees are full of such files and none of them is a reason to
/// abandon the scan.
fn scan_file(root: &Path, path: &Path, scanner: Option<Scanner>, plugins: &Registry) -> Vec<Grant> {
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
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();

    let mut grants = plugins.scan_source(&relative, &source);
    if let Some(scanner) = scanner {
        grants.extend(bundled::scan_source(scanner, &relative, &source));
    }
    grants
}
