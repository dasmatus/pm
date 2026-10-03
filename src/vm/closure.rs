//! Which host files a program needs before it can start inside the guest.
//!
//! The guest boots from an initramfs pm assembles, and it sees nothing of the host
//! filesystem. A dynamically linked entrypoint therefore needs its loader and every
//! shared library it links, transitively, copied in beside it - and so does the
//! guest's init, which is a host binary too. A script needs the interpreter its `#!`
//! line names, and the command `env` runs when that interpreter is `env`.
//!
//! Each file goes into the guest at the same absolute path it has on the host. That
//! is what makes resolution line up without rewriting anything: the guest's loader
//! walks the same `DT_RUNPATH` and the same default directories the host's did, and
//! finds each library exactly where it was found here.

use std::{
    collections::{BTreeSet, VecDeque},
    fs::File,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
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

/// Why a file is wanted in the guest, which decides what it has to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// An entrypoint, another program of the package, or init: wanted outright.
    Program,
    /// Named by a `PT_INTERP`: has to be an ELF object.
    Loader,
    /// Found for a `DT_NEEDED`: has to be an ELF object.
    Library,
    /// Named by a `#!` line: has to be an ELF object or an executable script.
    Interpreter,
}

/// Every host file `roots` need to run, as absolute host paths.
///
/// Files under `package_root` are walked for what *they* need but never returned:
/// they are already in the guest as part of the package. A soname found nowhere is
/// logged and skipped; the program then fails to start in the guest, with the
/// loader's own message naming the library, which is clearer than anything pm could
/// say in advance.
///
/// Which host files are wanted is decided by the package - its `PT_INTERP`,
/// `DT_RUNPATH`, `DT_NEEDED` and `#!` lines - so each one is checked before it is
/// copied, and refused with a warning when it fails:
///
/// * it has to be under [`HOST_ROOTS`], so a package cannot name `$HOME/.ssh` as a
///   library directory;
/// * it has to be what it was named as: a loader or library has to be an ELF
///   object, an interpreter an ELF object or an executable script. A package that
///   writes `#!/etc/hostname` gets nothing, rather than a copy of a host
///   configuration file its jail would not have handed it unasked.
///
/// `own` is pm's own init binary, the one object read without the ELF reader's size
/// cap (see [`linkage`]) and the one host file allowed outside [`HOST_ROOTS`]: it
/// is pm's choice, not the package's, and may well be installed under `$HOME`.
pub fn host_files(
    roots: impl IntoIterator<Item = PathBuf>,
    package_root: &Path,
    own: &Path,
) -> BTreeSet<PathBuf> {
    let mut queue: VecDeque<(PathBuf, Role)> = roots
        .into_iter()
        .map(|root| (normalize(&root), Role::Program))
        .collect();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut needed_from_host = BTreeSet::new();

    while let Some((object, role)) = queue.pop_front() {
        if !seen.insert(object.clone()) {
            continue;
        }
        let is_own = object == own;
        let from_host = !object.starts_with(package_root) && !is_own;
        if from_host && !inside_host_roots(&object) {
            warn!(
                file = %object.display(),
                "refusing to copy a host file outside the system directories into the guest"
            );
            continue;
        }

        let linkage = match linkage(&object, is_own) {
            Ok(linkage) => linkage,
            Err(error) => {
                warn!(
                    object = %object.display(),
                    %error,
                    "cannot read how this object links; the guest will not have its libraries"
                );
                None
            }
        };
        let interpreters = if linkage.is_none() {
            shebang(&object)
        } else {
            Vec::new()
        };

        if from_host {
            let acceptable = match role {
                Role::Program => true,
                Role::Loader | Role::Library => linkage.is_some(),
                Role::Interpreter => {
                    linkage.is_some() || (!interpreters.is_empty() && is_executable(&object))
                }
            };
            if !acceptable {
                warn!(
                    file = %object.display(),
                    ?role,
                    "refusing to copy a host file into the guest: the package names it as \
                     something it is not"
                );
                continue;
            }
            needed_from_host.insert(object.clone());
        }

        let dependencies = match &linkage {
            Some(linkage) => libraries(&object, linkage),
            None => interpreters
                .into_iter()
                .map(|interpreter| (interpreter, Role::Interpreter))
                .collect(),
        };
        for (dependency, role) in dependencies {
            let dependency = normalize(&dependency);
            if !seen.contains(&dependency) {
                queue.push_back((dependency, role));
            }
        }
    }
    debug!(files = needed_from_host.len(), "host files the guest needs");
    needed_from_host
}

/// What an ELF object needs directly: its loader and its libraries.
fn libraries(object: &Path, linkage: &Linkage) -> Vec<(PathBuf, Role)> {
    let mut found: Vec<(PathBuf, Role)> = linkage
        .interpreter
        .iter()
        .map(|loader| (PathBuf::from(loader), Role::Loader))
        .collect();
    let search = search_path(object, linkage);
    for soname in &linkage.needed {
        match search
            .iter()
            .map(|dir| dir.join(soname))
            .find(|path| path.is_file())
        {
            Some(library) => found.push((library, Role::Library)),
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

/// The programs a `#!` line runs: its interpreter and, for `/usr/bin/env`, the
/// command `env` looks up on the guest's `PATH`.
///
/// `env`'s own options (`-S`, `-i`, `-u NAME`) and `NAME=value` assignments are
/// skipped to find the command. A command that is not found on the host is left
/// out; the script then fails in the guest with `env`'s own message.
fn shebang(path: &Path) -> Vec<PathBuf> {
    let mut head = [0; SHEBANG_BYTES];
    let Ok(read) = File::open(path).and_then(|mut file| file.read(&mut head)) else {
        return Vec::new();
    };
    let Some(line) = head[..read].strip_prefix(b"#!") else {
        return Vec::new();
    };
    let line = line.split(|&byte| byte == b'\n').next().unwrap_or_default();
    let Ok(line) = std::str::from_utf8(line) else {
        return Vec::new();
    };
    let mut words = line.split_whitespace();
    let Some(interpreter) = words.next().map(Path::new) else {
        return Vec::new();
    };
    if !interpreter.is_absolute() {
        return Vec::new();
    }
    let mut programs = vec![interpreter.to_path_buf()];
    if interpreter.file_name().is_some_and(|name| name == "env") {
        let mut skip_value = false;
        let command = words.find(|word| {
            if skip_value {
                skip_value = false;
                return false;
            }
            if *word == "-u" {
                skip_value = true;
                return false;
            }
            !word.starts_with('-') && !word.contains('=')
        });
        if let Some(command) = command.and_then(on_guest_path) {
            programs.push(command);
        }
    }
    programs
}

/// Where `command` is found on the guest's `PATH`, looked up on the host.
fn on_guest_path(command: &str) -> Option<PathBuf> {
    if command.starts_with('/') {
        return Some(PathBuf::from(command));
    }
    if command.contains('/') {
        return None;
    }
    std::env::split_paths(super::GUEST_PATH)
        .map(|dir| dir.join(command))
        .find(|candidate| candidate.is_file() && is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

/// Whether `path`, with symlinks resolved, is under one of [`HOST_ROOTS`].
fn inside_host_roots(path: &Path) -> bool {
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    HOST_ROOTS.iter().any(|root| resolved.starts_with(root))
}

/// `path` with `.` dropped and each `..` taking off the component before it.
///
/// Lexical on purpose. Every directory in the guest is a real directory, so the
/// guest's kernel resolves `/usr/bin/../lib` to `/usr/lib` whatever `/usr/bin` is
/// on the host, and the file has to be stored where the guest will look.
pub(super) fn normalize(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other.as_os_str()),
        }
    }
    normal
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

    #[test]
    fn an_interpreter_that_is_not_a_program_is_not_copied() {
        // /etc is a system directory, but /etc/hostname is neither an ELF file nor
        // an executable script, so naming it as an interpreter does not copy it.
        let package = tempfile::tempdir().unwrap();
        let script = package.path().join("tool");
        std::fs::write(&script, "#!/etc/hostname\n").unwrap();
        let files = host_files([script], package.path(), Path::new("/"));
        assert!(!files.contains(Path::new("/etc/hostname")), "{files:?}");
    }

    #[test]
    fn env_brings_the_command_it_runs() {
        let Some(env) = ["/usr/bin/env", "/bin/env"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        else {
            return;
        };
        let Some(sh) = on_guest_path("sh") else {
            return;
        };
        let package = tempfile::tempdir().unwrap();
        let script = package.path().join("tool");
        std::fs::write(&script, format!("#!{} -S -u HOME sh -e\n", env.display())).unwrap();
        assert_eq!(shebang(&script), [env.clone(), sh.clone()]);
        let files = host_files([script], package.path(), Path::new("/"));
        assert!(files.contains(&env) && files.contains(&sh), "{files:?}");
    }

    #[test]
    fn dot_dot_is_resolved_before_a_path_is_used_in_the_guest() {
        assert_eq!(
            normalize(Path::new("/usr/bin/../lib/./x/libc.so.6")),
            Path::new("/usr/lib/x/libc.so.6")
        );
        assert_eq!(normalize(Path::new("/../../lib")), Path::new("/lib"));
    }
}
