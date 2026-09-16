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

use std::{
    fs,
    path::{Path, PathBuf},
};

use miette::{IntoDiagnostic, WrapErr, miette};
use nom::{
    IResult, Parser,
    bytes::complete::{tag, take, take_till},
    multi::count,
    number::complete::{le_u8, le_u16, le_u32, le_u64},
    sequence::{preceded, terminated},
};
use tracing::debug;

use super::{Grant, Permission, Permissions, Provenance};

/// The four bytes every ELF object starts with.
const ELF_MAGIC: &[u8] = b"\x7fELF";
/// The NUL that terminates a string-table entry.
const NUL: &[u8] = &[0];
/// `EI_CLASS` value for a 64-bit object. Anything else is rejected.
const ELFCLASS64: u8 = 2;
/// `EI_DATA` value for a little-endian object. Anything else is rejected.
const ELFDATA2LSB: u8 = 1;
/// Size of one ELF64 program header. `e_phentsize` may be larger (the excess is padding
/// and is skipped) but never smaller.
const PROGRAM_HEADER_SIZE: usize = 56;
/// Size of one ELF64 dynamic array entry: `d_tag` plus `d_un`.
const DYNAMIC_ENTRY_SIZE: u64 = 16;
/// `PN_XNUM`: `e_phnum` is an escape value and the real count lives in the section
/// header table. Not supported here, and diagnosed rather than misparsed.
const PN_XNUM: u16 = 0xffff;

/// `p_type` of a loadable segment - the only segments that map a virtual address to a
/// file offset.
const PT_LOAD: u32 = 1;
/// `p_type` of the dynamic linking segment.
const PT_DYNAMIC: u32 = 2;
/// `p_type` of the segment naming the program interpreter.
const PT_INTERP: u32 = 3;

/// `d_tag` ending the dynamic array.
const DT_NULL: u64 = 0;
/// `d_tag` of a needed shared library; `d_un` is a string-table offset.
const DT_NEEDED: u64 = 1;
/// `d_tag` of the string table; `d_un` is a **virtual address**.
const DT_STRTAB: u64 = 5;
/// `d_tag` of the string table's size in bytes.
const DT_STRSZ: u64 = 10;
/// `d_tag` of the legacy library search path; `d_un` is a string-table offset.
const DT_RPATH: u64 = 15;
/// `d_tag` of the modern library search path; `d_un` is a string-table offset.
const DT_RUNPATH: u64 = 29;

/// Refuse to read an object larger than this into memory (256 MiB).
///
/// Real binaries are orders of magnitude smaller; this only stops a package from making
/// `pm` allocate a machine's worth of RAM by shipping a sparse "binary".
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Cap on `e_phnum`.
///
/// The field is a `u16`, so the hard ceiling is 65535 - but no real object comes close
/// to 1024 segments, and this keeps the table walk bounded by something a reader can
/// sanity-check rather than by an attacker's choice.
const MAX_PROGRAM_HEADERS: usize = 1024;
/// Cap on the number of dynamic array entries read from `PT_DYNAMIC`.
///
/// `p_filesz` is a `u64`, so without this a segment claiming 2^60 entries would send the
/// walk into an effectively infinite loop. A large binary has a few dozen.
const MAX_DYNAMIC_ENTRIES: usize = 8192;
/// Cap on `DT_STRSZ` (8 MiB). A dynamic string table is normally a few kilobytes.
const MAX_STRTAB_BYTES: u64 = 8 * 1024 * 1024;
/// Cap on one string-table entry. `PATH_MAX` is 4096; a longer "library name" is junk.
const MAX_STRING_BYTES: usize = 4096;

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

/// Shared libraries the binary declares it needs (`DT_NEEDED`).
///
/// Returned in the order the dynamic array lists them, which is the order `readelf -d`
/// prints and the order the loader resolves them in. A static binary, an object with no
/// `PT_DYNAMIC`, and a file that is not an ELF at all all yield an empty vector - "needs
/// no shared libraries" is the honest answer for each.
///
/// # Errors
///
/// Diagnostic if the file cannot be read or is a malformed ELF; see [`analyse`].
pub fn needed_libraries(path: &Path) -> miette::Result<Vec<String>> {
    Ok(inspect(path)?
        .map(|inspection| inspection.needed)
        .unwrap_or_default())
}

/// `DT_RUNPATH` and `DT_RPATH` entries.
///
/// One string per dynamic entry, exactly as recorded, so the output lines up with
/// `readelf -d`. Each string may itself be a colon-separated list and may contain the
/// loader's `$ORIGIN` token; [`analyse`] splits and expands them, this function does
/// not. `DT_RUNPATH` entries come before `DT_RPATH` ones, matching the precedence the
/// loader applies.
///
/// # Errors
///
/// Diagnostic if the file cannot be read or is a malformed ELF; see [`analyse`].
pub fn runpath(path: &Path) -> miette::Result<Vec<String>> {
    Ok(inspect(path)?
        .map(|inspection| {
            inspection
                .search_paths
                .into_iter()
                .map(|(_, value)| value)
                .collect()
        })
        .unwrap_or_default())
}

/// The program interpreter named by `PT_INTERP`, if the object has one.
///
/// `None` for a static binary, a shared library with no interpreter, a relocatable
/// object, or a file that is not an ELF.
///
/// # Errors
///
/// Diagnostic if the file cannot be read or is a malformed ELF; see [`analyse`].
pub fn interpreter(path: &Path) -> miette::Result<Option<String>> {
    Ok(inspect(path)?.and_then(|inspection| inspection.interpreter))
}

/// Everything the four public functions need, read in one pass.
#[derive(Debug, Default)]
struct Inspection {
    /// `PT_INTERP`, the dynamic loader.
    interpreter: Option<String>,
    /// `DT_NEEDED` sonames, in dynamic-array order.
    needed: Vec<String>,
    /// `(tag name, raw value)` for each `DT_RUNPATH` then each `DT_RPATH`.
    search_paths: Vec<(&'static str, String)>,
}

/// Read and parse `path`, or report that it is not an ELF object.
///
/// # Errors
///
/// See [`analyse`].
fn inspect(path: &Path) -> miette::Result<Option<Inspection>> {
    let metadata = fs::metadata(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot stat {}", path.display()))?;
    if metadata.len() > MAX_FILE_BYTES {
        return Err(miette!(
            "{}: {} bytes is too large to parse as an ELF object (cap is {MAX_FILE_BYTES})",
            path.display(),
            metadata.len(),
        ));
    }
    let data = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot read {}", path.display()))?;

    if tag::<_, _, nom::error::Error<&[u8]>>(ELF_MAGIC)
        .parse_complete(data.as_slice())
        .is_err()
    {
        debug!(path = %path.display(), "not an ELF object");
        return Ok(None);
    }
    parse(path, &data).map(Some)
}

/// Parse a byte slice already known to start with the ELF magic.
///
/// # Errors
///
/// See [`analyse`].
fn parse(path: &Path, data: &[u8]) -> miette::Result<Inspection> {
    let (_, header) = header(data)
        .map_err(|_| malformed(path, "the file is too short to hold an ELF64 file header"))?;

    if header.class != ELFCLASS64 {
        return Err(malformed(
            path,
            &format!(
                "EI_CLASS is {} - only little-endian ELF64 (class {ELFCLASS64}) is supported",
                header.class
            ),
        ));
    }
    if header.endian != ELFDATA2LSB {
        return Err(malformed(
            path,
            &format!(
                "EI_DATA is {} - only little-endian ELF64 (data {ELFDATA2LSB}) is supported",
                header.endian
            ),
        ));
    }
    if header.phnum == PN_XNUM {
        return Err(malformed(
            path,
            "e_phnum is PN_XNUM, which moves the real count into the section header table; \
             that form is not supported",
        ));
    }
    if usize::from(header.phnum) > MAX_PROGRAM_HEADERS {
        return Err(malformed(
            path,
            &format!(
                "e_phnum is {}, past the {MAX_PROGRAM_HEADERS} program header cap",
                header.phnum
            ),
        ));
    }
    if header.phnum > 0 && usize::from(header.phentsize) < PROGRAM_HEADER_SIZE {
        return Err(malformed(
            path,
            &format!(
                "e_phentsize is {}, smaller than the {PROGRAM_HEADER_SIZE}-byte ELF64 program \
                 header",
                header.phentsize
            ),
        ));
    }

    let segments = segments(data, header).ok_or_else(|| {
        malformed(
            path,
            "the program header table runs past the end of the file",
        )
    })?;
    debug!(path = %path.display(), segments = segments.len(), "parsed program headers");

    let mut inspection = Inspection {
        interpreter: interp(path, data, &segments)?,
        ..Inspection::default()
    };

    let Some(dynamic) = segments.iter().find(|segment| segment.kind == PT_DYNAMIC) else {
        debug!(path = %path.display(), "no PT_DYNAMIC segment; nothing more to read");
        return Ok(inspection);
    };
    let entries = dynamic_entries(path, data, dynamic)?;

    // Collect the string-table offsets first; only then resolve them, so an object that
    // names nothing never has to have a valid string table.
    let mut needed = Vec::new();
    let mut runpaths = Vec::new();
    let mut rpaths = Vec::new();
    let mut strtab_addr = None;
    let mut strsz = None;
    for (tag, value) in entries {
        match tag {
            DT_NEEDED => needed.push(value),
            DT_RUNPATH => runpaths.push(value),
            DT_RPATH => rpaths.push(value),
            DT_STRTAB => strtab_addr = Some(value),
            DT_STRSZ => strsz = Some(value),
            _ => {}
        }
    }
    if needed.is_empty() && runpaths.is_empty() && rpaths.is_empty() {
        return Ok(inspection);
    }

    let table = string_table(path, data, &segments, strtab_addr, strsz)?;
    inspection.needed = needed
        .into_iter()
        .map(|offset| string_at(path, table, offset, "DT_NEEDED"))
        .collect::<miette::Result<Vec<String>>>()?;
    inspection.search_paths = runpaths
        .into_iter()
        .map(|offset| Ok(("DT_RUNPATH", string_at(path, table, offset, "DT_RUNPATH")?)))
        .chain(
            rpaths
                .into_iter()
                .map(|offset| Ok(("DT_RPATH", string_at(path, table, offset, "DT_RPATH")?))),
        )
        .collect::<miette::Result<Vec<(&'static str, String)>>>()?;
    Ok(inspection)
}

/// Read the `PT_INTERP` string, if there is one.
///
/// # Errors
///
/// Diagnostic if the segment runs past the end of the file or is not NUL-terminated.
fn interp(path: &Path, data: &[u8], segments: &[Segment]) -> miette::Result<Option<String>> {
    let Some(segment) = segments.iter().find(|segment| segment.kind == PT_INTERP) else {
        return Ok(None);
    };
    if segment.filesz == 0 {
        return Err(malformed(path, "the PT_INTERP segment is empty"));
    }
    if segment.filesz > MAX_STRING_BYTES as u64 {
        return Err(malformed(
            path,
            &format!(
                "the PT_INTERP segment claims {} bytes, past the {MAX_STRING_BYTES}-byte cap",
                segment.filesz
            ),
        ));
    }
    let bytes = at(data, segment.offset, take(segment.filesz))
        .ok_or_else(|| malformed(path, "the PT_INTERP segment runs past the end of the file"))?;
    let (_, name) = c_string(bytes)
        .map_err(|_| malformed(path, "the PT_INTERP string is not NUL-terminated"))?;
    let name = text(path, name, "PT_INTERP")?;
    debug!(path = %path.display(), interpreter = %name, "read PT_INTERP");
    Ok(Some(name))
}

/// Read the dynamic array out of `PT_DYNAMIC`, stopping at `DT_NULL`.
///
/// # Errors
///
/// Diagnostic if the segment runs past the end of the file, its size is not a whole
/// number of entries' worth of readable bytes, or it claims more than
/// `MAX_DYNAMIC_ENTRIES` entries.
fn dynamic_entries(path: &Path, data: &[u8], dynamic: &Segment) -> miette::Result<Vec<(u64, u64)>> {
    let claimed = dynamic.filesz / DYNAMIC_ENTRY_SIZE;
    if claimed > MAX_DYNAMIC_ENTRIES as u64 {
        return Err(malformed(
            path,
            &format!(
                "the PT_DYNAMIC segment claims {claimed} entries, past the \
                 {MAX_DYNAMIC_ENTRIES}-entry cap"
            ),
        ));
    }
    let wanted = usize::try_from(claimed)
        .map_err(|_| malformed(path, "the PT_DYNAMIC segment size does not fit in memory"))?;
    let entries = at(data, dynamic.offset, count(dynamic_entry, wanted))
        .ok_or_else(|| malformed(path, "the PT_DYNAMIC segment runs past the end of the file"))?;

    let entries: Vec<(u64, u64)> = entries
        .into_iter()
        .take_while(|&(tag, _)| tag != DT_NULL)
        .collect();
    debug!(path = %path.display(), entries = entries.len(), "parsed dynamic array");
    Ok(entries)
}

/// Resolve `DT_STRTAB` - a **virtual address** - to the string table's bytes in the file.
///
/// This is the step that quietly produces garbage when it is done wrong: treating
/// `d_un` as a file offset happens to be close enough on many binaries to yield
/// plausible-looking nonsense. The address is translated through the `PT_LOAD` segment
/// that contains it, and if none does, that is an error rather than a guess.
///
/// # Errors
///
/// Diagnostic if `DT_STRTAB` or `DT_STRSZ` is missing, if `DT_STRSZ` is past
/// `MAX_STRTAB_BYTES`, if no `PT_LOAD` segment covers the address, or if the resulting
/// range is not inside the file.
fn string_table<'a>(
    path: &Path,
    data: &'a [u8],
    segments: &[Segment],
    strtab_addr: Option<u64>,
    strsz: Option<u64>,
) -> miette::Result<&'a [u8]> {
    let addr = strtab_addr.ok_or_else(|| {
        malformed(
            path,
            "the dynamic array names strings but has no DT_STRTAB entry",
        )
    })?;
    let size = strsz.ok_or_else(|| {
        malformed(
            path,
            "the dynamic array names strings but has no DT_STRSZ entry",
        )
    })?;
    if size > MAX_STRTAB_BYTES {
        return Err(malformed(
            path,
            &format!("DT_STRSZ is {size}, past the {MAX_STRTAB_BYTES}-byte string table cap"),
        ));
    }
    let offset = file_offset(segments, addr).ok_or_else(|| {
        malformed(
            path,
            &format!("DT_STRTAB address {addr:#x} is not inside any PT_LOAD segment"),
        )
    })?;
    let table = at(data, offset, take(size)).ok_or_else(|| {
        malformed(
            path,
            &format!(
                "the {size}-byte string table at file offset {offset:#x} runs past the end of \
                 the file"
            ),
        )
    })?;
    debug!(
        path = %path.display(),
        addr, offset, size,
        "translated DT_STRTAB through PT_LOAD",
    );
    Ok(table)
}

/// Read the NUL-terminated string at `offset` inside the dynamic string table.
///
/// # Errors
///
/// Diagnostic if the offset is outside the table, the string is not terminated inside
/// it, it is longer than `MAX_STRING_BYTES`, or it is not UTF-8.
fn string_at(path: &Path, table: &[u8], offset: u64, tag: &str) -> miette::Result<String> {
    let bytes = at(table, offset, c_string).ok_or_else(|| {
        malformed(
            path,
            &format!(
                "the {tag} string at string-table offset {offset} is outside the table or is \
                 not NUL-terminated"
            ),
        )
    })?;
    text(path, bytes, tag)
}

/// Bound and decode one string-table or `PT_INTERP` byte run.
///
/// # Errors
///
/// Diagnostic if the run is longer than `MAX_STRING_BYTES` or is not UTF-8.
fn text(path: &Path, bytes: &[u8], tag: &str) -> miette::Result<String> {
    if bytes.len() > MAX_STRING_BYTES {
        return Err(malformed(
            path,
            &format!(
                "a {tag} string is {} bytes, past the {MAX_STRING_BYTES}-byte cap",
                bytes.len()
            ),
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| malformed(path, &format!("a {tag} string is not valid UTF-8")))
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
    let head = libraries
        .iter()
        .take(SHOWN)
        .copied()
        .collect::<Vec<&str>>()
        .join(", ");
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
fn components(object: &Path, raw: &str) -> Vec<PathBuf> {
    let origin = object.parent().filter(|_| object.is_absolute());
    raw.split(':')
        .filter(|component| !component.is_empty())
        .filter_map(|component| {
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
        .collect()
}

/// A diagnostic naming the file and what is wrong with it.
fn malformed(path: &Path, what: &str) -> miette::Report {
    miette!("{}: malformed ELF: {what}", path.display())
}

/// The fields of the ELF64 file header this module uses.
///
/// `class` and `endian` come out of `e_ident`, which is byte-order independent; the rest
/// is read little-endian and is only trusted once those two have been checked.
#[derive(Debug, Clone, Copy)]
struct Header {
    /// `e_ident[EI_CLASS]`.
    class: u8,
    /// `e_ident[EI_DATA]`.
    endian: u8,
    /// `e_phoff`: file offset of the program header table.
    phoff: u64,
    /// `e_phentsize`: stride of that table.
    phentsize: u16,
    /// `e_phnum`: number of entries in it.
    phnum: u16,
}

/// The fields of one ELF64 program header this module uses.
#[derive(Debug, Clone, Copy)]
struct Segment {
    /// `p_type`.
    kind: u32,
    /// `p_offset`: where the segment's bytes start in the file.
    offset: u64,
    /// `p_vaddr`: where they are mapped.
    vaddr: u64,
    /// `p_filesz`: how many of them there are in the file.
    filesz: u64,
}

/// Parse the ELF64 file header, magic included.
fn header(input: &[u8]) -> IResult<&[u8], Header> {
    let (rest, _magic) = tag(ELF_MAGIC).parse_complete(input)?;
    let (rest, class) = le_u8(rest)?;
    let (rest, endian) = le_u8(rest)?;
    // EI_VERSION, EI_OSABI, EI_ABIVERSION and EI_PAD: the rest of the 16-byte e_ident.
    let (rest, _ident) = take(10usize).parse_complete(rest)?;
    let (rest, _e_type) = le_u16(rest)?;
    let (rest, _e_machine) = le_u16(rest)?;
    let (rest, _e_version) = le_u32(rest)?;
    let (rest, _e_entry) = le_u64(rest)?;
    let (rest, phoff) = le_u64(rest)?;
    let (rest, _e_shoff) = le_u64(rest)?;
    let (rest, _e_flags) = le_u32(rest)?;
    let (rest, _e_ehsize) = le_u16(rest)?;
    let (rest, phentsize) = le_u16(rest)?;
    let (rest, phnum) = le_u16(rest)?;
    Ok((
        rest,
        Header {
            class,
            endian,
            phoff,
            phentsize,
            phnum,
        },
    ))
}

/// Parse one 56-byte ELF64 program header.
fn segment(input: &[u8]) -> IResult<&[u8], Segment> {
    let (rest, kind) = le_u32(input)?;
    let (rest, _p_flags) = le_u32(rest)?;
    let (rest, offset) = le_u64(rest)?;
    let (rest, vaddr) = le_u64(rest)?;
    let (rest, _p_paddr) = le_u64(rest)?;
    let (rest, filesz) = le_u64(rest)?;
    let (rest, _p_memsz) = le_u64(rest)?;
    let (rest, _p_align) = le_u64(rest)?;
    Ok((
        rest,
        Segment {
            kind,
            offset,
            vaddr,
            filesz,
        },
    ))
}

/// Parse one 16-byte dynamic array entry as `(d_tag, d_un)`.
fn dynamic_entry(input: &[u8]) -> IResult<&[u8], (u64, u64)> {
    let (rest, tag) = le_u64(input)?;
    let (rest, value) = le_u64(rest)?;
    Ok((rest, (tag, value)))
}

/// Parse a NUL-terminated string, returning it without the NUL.
///
/// Requiring the terminator is the point: run this on a slice bounded by `DT_STRSZ` and
/// an unterminated entry is a parse error instead of a read that wanders into the rest
/// of the file.
fn c_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    terminated(take_till(|byte| byte == 0u8), tag(NUL)).parse_complete(input)
}

/// Read the whole program header table, honouring an `e_phentsize` larger than 56.
///
/// `None` if the table does not fit in the file - the caller turns that into a
/// diagnostic. An object with no program headers at all (a relocatable `.o`, where
/// `e_phentsize` is also zero) yields an empty table rather than an error, because "no
/// segments" is a true description of it and a staging tree is full of such files.
fn segments(data: &[u8], header: Header) -> Option<Vec<Segment>> {
    if header.phnum == 0 {
        return Some(Vec::new());
    }
    let padding = usize::from(header.phentsize).checked_sub(PROGRAM_HEADER_SIZE)?;
    at(
        data,
        header.phoff,
        count(
            terminated(segment, take(padding)),
            usize::from(header.phnum),
        ),
    )
}

/// Translate a virtual address to a file offset through the `PT_LOAD` segments.
///
/// `None` when no loadable segment's file-backed range contains the address, which is
/// what a corrupt or hand-written `DT_STRTAB` looks like.
fn file_offset(segments: &[Segment], addr: u64) -> Option<u64> {
    segments
        .iter()
        .filter(|segment| segment.kind == PT_LOAD)
        .find_map(|segment| {
            let end = segment.vaddr.checked_add(segment.filesz)?;
            if addr < segment.vaddr || addr >= end {
                return None;
            }
            segment.offset.checked_add(addr - segment.vaddr)
        })
}

/// Run `parser` at `offset` bytes into `data`.
///
/// The seek is `take(offset)`, so an offset past the end of the input is an ordinary
/// parse failure rather than a slice index that panics - which is the whole reason this
/// module is built out of combinators. `None` covers both a seek past the end and a
/// failure of `parser` itself; callers attach the message.
fn at<'a, O, P>(data: &'a [u8], offset: u64, parser: P) -> Option<O>
where
    P: Parser<&'a [u8], Output = O, Error = nom::error::Error<&'a [u8]>>,
{
    let offset = usize::try_from(offset).ok()?;
    let (_, parsed) = preceded(take(offset), parser).parse_complete(data).ok()?;
    Some(parsed)
}
