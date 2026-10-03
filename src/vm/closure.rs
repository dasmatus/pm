//! Which host files a program needs before it can start inside the guest.
//!
//! The guest boots from an initramfs pm assembles, and it sees nothing of the host
//! filesystem. A dynamically linked entrypoint therefore needs its loader and every
//! shared library it links, transitively, copied in beside it - and so does the
//! guest's init, which is a host binary too. A script needs the interpreter its `#!`
//! line names.
//!
//! Each file goes into the guest at the same absolute path it has on the host. That
//! is what makes resolution line up without rewriting anything: the guest's loader
//! walks the same `DT_RUNPATH` and the same default directories the host's did, and
//! finds each library exactly where it was found here.

use std::{
    collections::{BTreeSet, VecDeque},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use tracing::{debug, warn};

use crate::perms::elf::{Linkage, linkage};

/// Directories the loader searches for a soname after `DT_RUNPATH`.
///
/// The same list [`crate::run`] locates libraries with, for the same reason: the
/// guest's loader is the host's loader, copied in.
const DEFAULT_LIBRARY_DIRS: [&str; 6] = [
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
];

/// The only host directories a file is copied into the guest from.
///
/// The run jail's view of the host: the directories `rootfs("/")` mirrors, plus the
/// Nix store it adds (see [`crate::run`]). Which host files the guest gets is decided
/// by the package - its `PT_INTERP`, `DT_RUNPATH` and `#!` lines - so without this a
/// package could name `$HOME/.ssh` as a library directory and be handed a private key
/// inside its VM. With it, a package's VM never holds a host file its jail could not
/// already have read.
const HOST_ROOTS: [&str; 8] = [
    "/bin",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/sbin",
    "/usr",
    "/nix/store",
];

/// How much of a file is read looking for a `#!` line.
const SHEBANG_BYTES: usize = 256;

/// Every host file `roots` need to run, as absolute host paths.
///
/// Files under `package_root` are walked for what *they* need but never returned:
/// they are already in the guest as part of the package. A soname found nowhere is
/// logged and skipped; the program then fails to start in the guest, with the
/// loader's own message naming the library, which is clearer than anything pm could
/// say in advance.
///
/// Host files outside [`HOST_ROOTS`] are refused, with a warning, and not walked.
///
/// `own` is pm's own init binary, the one object read without the ELF reader's size
/// cap (see [`linkage`]) and the one host file allowed outside [`HOST_ROOTS`]: it
/// is pm's choice, not the package's, and may well be installed under `$HOME`.
pub fn host_files(
    roots: impl IntoIterator<Item = PathBuf>,
    package_root: &Path,
    own: &Path,
) -> BTreeSet<PathBuf> {
    let mut queue: VecDeque<PathBuf> = roots.into_iter().collect();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut needed_from_host = BTreeSet::new();

    while let Some(object) = queue.pop_front() {
        if !seen.insert(object.clone()) {
            continue;
        }
        if !object.starts_with(package_root) && object != own {
            let resolved = object.canonicalize().unwrap_or_else(|_| object.clone());
            if !HOST_ROOTS.iter().any(|root| resolved.starts_with(root)) {
                warn!(
                    file = %object.display(),
                    "refusing to copy a host file outside the system directories into the \
                     guest"
                );
                continue;
            }
            needed_from_host.insert(object.clone());
        }
        for dependency in dependencies(&object, object == own) {
            if !seen.contains(&dependency) {
                queue.push_back(dependency);
            }
        }
    }
    debug!(files = needed_from_host.len(), "host files the guest needs");
    needed_from_host
}

/// What `object` needs directly: its loader, its libraries, or its script
/// interpreter.
fn dependencies(object: &Path, own: bool) -> Vec<PathBuf> {
    let linkage = match linkage(object, own) {
        Ok(Some(linkage)) => linkage,
        Ok(None) => return shebang(object).into_iter().collect(),
        Err(error) => {
            warn!(
                object = %object.display(),
                %error,
                "cannot read how this object links; the guest will not have its libraries"
            );
            return Vec::new();
        }
    };
    let mut found: Vec<PathBuf> = linkage.interpreter.iter().map(PathBuf::from).collect();
    let search = search_path(object, &linkage);
    for soname in &linkage.needed {
        match search
            .iter()
            .map(|dir| dir.join(soname))
            .find(|path| path.is_file())
        {
            Some(library) => found.push(library),
            None => warn!(
                object = %object.display(),
                soname,
                "cannot find a needed library on the host; the guest will not have it"
            ),
        }
    }
    found
}

/// `DT_RUNPATH` with `$ORIGIN` expanded, then the default directories.
fn search_path(object: &Path, linkage: &Linkage) -> Vec<PathBuf> {
    let origin = object.parent().unwrap_or(Path::new("/"));
    let mut search: Vec<PathBuf> = linkage
        .runpath
        .iter()
        .flat_map(|entry| entry.split(':'))
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            PathBuf::from(
                entry
                    .replace("${ORIGIN}", &origin.to_string_lossy())
                    .replace("$ORIGIN", &origin.to_string_lossy()),
            )
        })
        .collect();
    search.extend(DEFAULT_LIBRARY_DIRS.iter().map(PathBuf::from));
    search
}

/// The absolute interpreter a `#!` line names, when there is one.
fn shebang(path: &Path) -> Option<PathBuf> {
    let mut head = [0; SHEBANG_BYTES];
    let read = File::open(path)
        .and_then(|mut file| file.read(&mut head))
        .ok()?;
    let line = head[..read].strip_prefix(b"#!")?;
    let line = line.split(|&byte| byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let interpreter = line.split_whitespace().next()?;
    let interpreter = Path::new(interpreter);
    interpreter.is_absolute().then(|| interpreter.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dynamic_binary_brings_its_loader_and_libc() {
        let Some(sh) = ["/bin/sh", "/usr/bin/sh"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        else {
            return;
        };
        let files = host_files(
            [sh.clone()],
            Path::new("/nonexistent-package-root"),
            Path::new("/"),
        );
        assert!(files.contains(&sh));
        if linkage(&sh, false)
            .unwrap()
            .is_some_and(|l| l.interpreter.is_some())
        {
            assert!(
                files.iter().any(|file| file
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("libc.so"))),
                "{files:?}"
            );
        }
    }

    #[test]
    fn a_package_cannot_pull_in_host_files_outside_the_system_directories() {
        let home = tempfile::tempdir().unwrap();
        let secret = home.path().join("id_ed25519");
        std::fs::write(&secret, "private key\n").unwrap();
        let package = tempfile::tempdir().unwrap();
        let script = package.path().join("tool");
        std::fs::write(&script, format!("#!{}\n", secret.display())).unwrap();

        let files = host_files([script], package.path(), Path::new("/"));
        assert!(!files.contains(&secret), "{files:?}");
    }

    #[test]
    fn files_inside_the_package_are_walked_but_not_returned() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("tool");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        let files = host_files([script.clone()], dir.path(), Path::new("/"));
        assert!(!files.contains(&script));
        if Path::new("/bin/sh").is_file() {
            assert!(files.contains(Path::new("/bin/sh")), "{files:?}");
        }
    }
}
