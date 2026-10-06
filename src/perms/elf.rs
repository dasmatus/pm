//! Permissions inferred from the ELF objects a build staged.
//!
//! This is the third signal in [`crate::perms`], and the only one that reads what the
//! build actually *produced* rather than what its sources or one traced run suggested.
//! A dynamically linked binary is unambiguous about part of its needs: it names its
//! interpreter in `PT_INTERP`, its shared libraries in `DT_NEEDED`, and the directories
//! it wants them looked up in via `DT_RUNPATH`/`DT_RPATH`. Those become
//! [`Permission::ExecPath`] and [`Permission::ReadPath`] grants with
//! [`Provenance::ElfAnalysis`].
//!
//! # Still incomplete, still audit-only
//!
//! Being static, this signal does not lie about what it saw - but it is no more
//! *complete* than its siblings. It cannot see a `dlopen("libfoo.so")` computed at run
//! time, a plugin directory read from a config file, a `NSS` or `PAM` module the libc
//! loads on demand, or anything the program does once running. So an ELF-derived set is
//! a floor, not a ceiling, and like every derived profile it stays
//! `Enforcement::Audit` until a human promotes it. Nothing
//! here promotes anything.
//!
//! # Hostile bytes
//!
//! These bytes come out of a package, which is to say out of somebody else's build. The
//! parser therefore treats every field as adversarial: it is written with `nom`
//! combinators so that a short read is a parse *error* rather than an out-of-bounds
//! index, every offset and length is bounds-checked against the file before use, every
//! addition is checked, and the two places that could otherwise loop for a long time -
//! the program header table and the dynamic array - are explicitly capped (see
//! `MAX_PROGRAM_HEADERS` and `MAX_DYNAMIC_ENTRIES`). A truncated, corrupt or
//! deliberately absurd ELF produces a [`miette`] diagnostic; it never panics and never
//! hangs.
//!
//! Only little-endian ELF64 is parsed. A 32-bit or big-endian object is reported as an
//! unsupported-class diagnostic rather than silently misread - the one thing worse than
//! failing to derive permissions is deriving the wrong ones.

use std::path::{Path, PathBuf};

use pm_elf::{Inspection, inspect};
pub use pm_elf::{Linkage, interpreter, linkage, needed_libraries, runpath};
use tracing::debug;

use super::{Grant, Permission, Permissions, Provenance};

/// Where the loader looks for a bare `DT_NEEDED` soname when nothing overrides it.
///
/// This is deliberately the union of the usual multilib spellings rather than an attempt
/// to replicate `ld.so`'s cache: over-granting a read on `/usr/lib` is visible in
/// [`Permissions::report`] and can be tightened by a human, whereas under-granting
/// produces a package that fails to start.
const DEFAULT_LIBRARY_DIRS: [&str; 4] = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

/// Read the ELF at `path` and infer what it needs.
///
/// Returns `Ok(None)` if the file is not an ELF binary at all, so a caller can walk a
/// staging tree and hand every regular file to this function without pre-filtering.
///
/// The grants produced are:
///
/// - [`Permission::ExecPath`] for the `PT_INTERP` interpreter, which the kernel executes
///   on the package's behalf before the program's own first instruction runs;
/// - [`Permission::ReadPath`] plus [`Permission::ExecPath`] for the directory each
///   `DT_NEEDED` library loads from - the containing directory when the name has a
///   slash, otherwise the search path (`DEFAULT_LIBRARY_DIRS` and any runpath);
/// - [`Permission::ReadPath`] for every `DT_RUNPATH`/`DT_RPATH` component.
///
/// Note what is *not* granted: the analysed file's own path. It is named by its location
/// in the build's staging tree, which is not where it lives at run time, and recording
/// that path would put a build-machine artefact into a run-time profile.
///
/// The result is a floor. Nothing here observes `dlopen`, and nothing here promotes the
/// profile out of `Enforcement::Audit`.
///
/// # Errors
///
/// Diagnostic if the file cannot be read, is larger than `MAX_FILE_BYTES`, is not
/// little-endian ELF64, or is a malformed ELF - a truncated header, a program header
/// table or dynamic segment running past the end of the file, a `DT_STRTAB` virtual
/// address no `PT_LOAD` segment covers, an unterminated or over-long string, or a count
/// past one of this module's caps.
pub fn analyse(path: &Path) -> miette::Result<Option<Permissions>> {
    let Some(inspection) = inspect(path)? else {
        return Ok(None);
    };
    let permissions: Permissions = grants(path, &inspection).into_iter().collect();
    debug!(
        path = %path.display(),
        needed = inspection.needed.len(),
        runpath = inspection.search_paths.len(),
        grants = permissions.len(),
        "derived permissions from ELF",
    );
    Ok(Some(permissions))
}

/// Turn one inspection into grants.
///
/// Every grant carries [`Provenance::ElfAnalysis`] and evidence naming the tag and its
/// value, so [`Permissions::report`] can answer "why `/usr/lib`?" with `DT_NEEDED
/// libc.so.6` rather than a shrug. Duplicate grants are expected and harmless -
/// [`Permissions::from_grants`] unifies them and merges their evidence, which is how a
/// binary with thirty `DT_NEEDED` entries still yields four directory grants.
fn grants(path: &Path, inspection: &Inspection) -> Vec<Grant> {
    let mut grants = Vec::new();

    if let Some(loader) = &inspection.interpreter {
        grants.push(Grant::new(
            Permission::ExecPath(PathBuf::from(loader)),
            Provenance::ElfAnalysis,
            [format!("PT_INTERP {loader}")],
        ));
    }

    // Runpath components, expanded once and reused as the search path below.
    let mut search: Vec<PathBuf> = Vec::new();
    for (tag, raw) in &inspection.search_paths {
        for dir in components(path, raw) {
            grants.push(Grant::new(
                Permission::ReadPath(dir.clone()),
                Provenance::ElfAnalysis,
                [format!("{tag} {raw}")],
            ));
            search.push(dir);
        }
    }
    search.extend(DEFAULT_LIBRARY_DIRS.iter().map(PathBuf::from));

    // A name holding a slash is a path the loader uses verbatim, so it earns a grant on
    // its own directory and its own evidence line.
    let mut bare: Vec<&str> = Vec::new();
    for library in &inspection.needed {
        match Path::new(library).parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                let why = format!("DT_NEEDED {library}");
                grants.push(Grant::new(
                    Permission::ReadPath(parent.to_path_buf()),
                    Provenance::ElfAnalysis,
                    [why.clone()],
                ));
                grants.push(Grant::new(
                    Permission::ExecPath(parent.to_path_buf()),
                    Provenance::ElfAnalysis,
                    [why],
                ));
            }
            _ => bare.push(library),
        }
    }

    // Bare sonames all resolve along the same search path, so they share one evidence
    // line per directory instead of one per library: a binary with sixty DT_NEEDED
    // entries would otherwise bury its four directory grants under a screenful of
    // near-identical text, and a report nobody reads is a report nobody audits. The full
    // list is always available from `needed_libraries`.
    if !bare.is_empty() {
        let why = format!(
            "DT_NEEDED {}, searched along the library path",
            summarise(&bare)
        );
        for dir in search {
            grants.push(Grant::new(
                Permission::ReadPath(dir.clone()),
                Provenance::ElfAnalysis,
                [why.clone()],
            ));
            grants.push(Grant::new(
                Permission::ExecPath(dir),
                Provenance::ElfAnalysis,
                [why.clone()],
            ));
        }
    }

    grants
}

/// Join library names for an evidence line, naming the first few and counting the rest.
fn summarise(libraries: &[&str]) -> String {
    /// How many names to print before falling back to a count.
    const SHOWN: usize = 3;
    let mut head = String::new();
    for (position, library) in libraries.iter().take(SHOWN).enumerate() {
        if position > 0 {
            head.push_str(", ");
        }
        head.push_str(library);
    }
    match libraries.len().checked_sub(SHOWN) {
        Some(0) | None => head,
        Some(rest) => format!("{head} and {rest} more"),
    }
}

/// Split one runpath value on `:` and expand the loader's `$ORIGIN` token.
///
/// `$ORIGIN` means "the directory holding the object", so it is expanded against
/// `object`'s parent. That is only the right answer when the object is analysed at a
/// path whose directory layout matches its run-time layout - which is the case for `pm`,
/// because the staging tree is what gets archived and extracted.
///
/// Two kinds of component are dropped rather than guessed at, because a wrong path in a
/// profile is worse than a missing one:
///
/// - anything still holding a `$` after expansion (`$LIB`, `$PLATFORM`), since granting
///   a literal `$LIB` grants a directory that cannot exist;
/// - any `$ORIGIN` component when `object` is not an absolute path, since the expansion
///   would be relative to whatever directory the sandbox happens to start in.
fn components<'a>(object: &'a Path, raw: &'a str) -> impl Iterator<Item = PathBuf> + 'a {
    let origin = object.parent().filter(|_| object.is_absolute());
    raw.split(':')
        .filter(|component| !component.is_empty())
        .filter_map(move |component| {
            let expanded = match origin {
                Some(origin) => component
                    .replace("${ORIGIN}", &origin.to_string_lossy())
                    .replace("$ORIGIN", &origin.to_string_lossy()),
                None => component.to_owned(),
            };
            if expanded.contains('$') {
                debug!(
                    component,
                    "dropping runpath component with an unexpandable token"
                );
                return None;
            }
            Some(PathBuf::from(expanded))
        })
}
