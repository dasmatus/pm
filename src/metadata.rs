//! Package metadata written into each archive.
//!
//! A [`Metadata`] value is serialised to YAML as the `metadata` file at the root of
//! every `.cpkg` archive. It records the package identity, the dependencies bundled
//! under `deps/`, the entrypoints a consumer can run or link against, and the
//! permission profile the runner sandboxes those entrypoints with.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use serde::{Deserialize, Serialize};

use crate::perms::{Enforcement, Permissions};

/// The profile handed out for a package that recorded none.
///
/// [`Metadata::permissions`] hands back a borrow, and a package built before profiles
/// existed has nothing to borrow from, so it borrows this instead. Empty and shared: a
/// package that recorded no profile wants nothing beyond whatever the runner allows
/// unconditionally.
static NO_PROFILE: LazyLock<Permissions> = LazyLock::new(Permissions::default);

/// The package's metadata, stored as YAML at the archive root.
///
/// Construct one with [`Metadata::create`]; the fields are private so the invariant
/// that entrypoint keys are package-relative stays with the caller that walked the
/// staging directory.
///
/// # Reading a package built before profiles existed
///
/// Both permission fields are `#[serde(default)]`, so a `metadata` file written by an
/// older `pm` - which has neither key - still parses. It parses into *no recorded
/// profile* and [`Enforcement::Audit`]: defaulting to [`Enforcement::Enforce`] would
/// hand every such package an empty allow-list and brick it.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Metadata {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
    entrypoints: HashMap<PathBuf, Type>,
    /// `None` means no profile was recorded at all - an old package. `Some` of an
    /// empty set means a profile was derived and came back wanting nothing. The two
    /// are kept apart because they are different facts about the *build*, and
    /// [`Metadata::recorded_permissions`] is how a caller asks which one it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions: Option<Permissions>,
    /// Absent and `Audit` mean the same thing, so this needs no `Option`: a package
    /// with no recorded mode is audited, exactly like a freshly derived profile.
    #[serde(default)]
    enforcement: Enforcement,
}

/// What a single entrypoint inside the package is.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum Type {
    /// An executable meant to be run directly.
    Binary,
    /// A library meant to be linked against, static or dynamic.
    Library(LibraryType),
}

/// How a library entrypoint is linked.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum LibraryType {
    /// A `.a` archive, linked at build time.
    Static,
    /// A `.so` (or versioned `.so.N`) shared object, linked at load time.
    Dynamic,
}

impl Metadata {
    /// Assemble the metadata for a package.
    ///
    /// This is a pure constructor: it touches no filesystem and cannot fail. The
    /// caller is responsible for walking the staging tree, collecting the
    /// dependencies and classifying the entrypoints with [`Metadata::classify`].
    ///
    /// Every key of `entrypoints` and every entry of `dependencies` must be
    /// **relative to the package root**. The archive is extracted somewhere else at
    /// run time, so a build-time absolute path would not resolve there.
    ///
    /// `permissions` is the profile inferred for the built package and `enforcement`
    /// says whether the runner denies against it. Passing a profile here always counts
    /// as recording one, even when it is empty - see
    /// [`Metadata::recorded_permissions`]. Nothing in this constructor promotes
    /// anything: pass [`Enforcement::Audit`] unless a human has already decided
    /// otherwise.
    pub fn create(
        name: String,
        version: Vec<String>,
        dependencies: Vec<PathBuf>,
        entrypoints: HashMap<PathBuf, Type>,
        permissions: Permissions,
        enforcement: Enforcement,
    ) -> Self {
        tracing::debug!(
            %name,
            dependencies = dependencies.len(),
            entrypoints = entrypoints.len(),
            grants = permissions.len(),
            %enforcement,
            "assembling package metadata"
        );
        Self {
            name,
            version,
            dependencies,
            entrypoints,
            permissions: Some(permissions),
            enforcement,
        }
    }

    /// The package name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version components, most significant first (e.g. `["0", "1", "0"]`).
    pub fn version(&self) -> &[String] {
        &self.version
    }

    /// Paths of the bundled dependencies, relative to the package root, borrowed
    /// in place.
    pub fn dependencies(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.dependencies.iter().map(PathBuf::as_path)
    }

    /// Every declared entrypoint, borrowed in place, keyed by its path relative to
    /// the package root.
    pub fn entrypoints(&self) -> impl ExactSizeIterator<Item = (&Path, &Type)> {
        self.entrypoints
            .iter()
            .map(|(path, r#type)| (path.as_path(), r#type))
    }

    /// The runnable subset of [`Self::entrypoints`].
    pub fn binaries(&self) -> impl Iterator<Item = &Path> {
        self.entrypoints()
            .filter(|&(_, r#type)| *r#type == Type::Binary)
            .map(|(path, _)| path)
    }

    /// What the package is allowed to do at run time.
    ///
    /// A package that recorded no profile - anything built before this field existed -
    /// reads back as an empty set, which is the same answer as a profile that was
    /// derived and wanted nothing. Callers that have to tell those apart want
    /// [`Metadata::recorded_permissions`]; callers that just need the allow-list want
    /// this.
    pub fn permissions(&self) -> &Permissions {
        self.permissions.as_ref().unwrap_or(&NO_PROFILE)
    }

    /// The recorded profile, or [`None`] when the package recorded none.
    ///
    /// The distinction matters to anything that reports on a package: "this build
    /// inferred that it needs nothing" and "this package predates permission
    /// inference" are different claims, and only the first is evidence.
    pub fn recorded_permissions(&self) -> Option<&Permissions> {
        self.permissions.as_ref()
    }

    /// Whether [`Self::permissions`] is denied against or merely audited.
    ///
    /// [`Enforcement::Audit`] for a package that recorded nothing.
    pub fn enforcement(&self) -> Enforcement {
        self.enforcement
    }

    /// Promote a profile from audit to enforcing.
    ///
    /// Deliberately explicit and one-way: an observation-derived profile is incomplete
    /// by construction, so turning denial on is a human decision made after reading
    /// [`Permissions::report`], never something a derivation does to itself.
    ///
    /// Promoting a package that recorded no profile is legal but almost certainly a
    /// mistake - it enforces an empty allow-list - so it is logged as a warning rather
    /// than silently obeyed.
    pub fn promote(&mut self) {
        if self.permissions.is_none() {
            tracing::warn!(
                name = %self.name,
                "promoting a package that recorded no permission profile: it will be \
                 enforced against an empty allow-list"
            );
        }
        tracing::info!(name = %self.name, "promoting permission profile to enforcing");
        self.enforcement = Enforcement::Enforce;
    }

    /// Classify one file on disk.
    ///
    /// Returns [`None`] for anything that is not a regular file, which includes
    /// directories and symlinks pointing at directories, as well as paths that
    /// cannot be stat'ed at all (dangling symlinks, missing files).
    ///
    /// A regular file is a [`LibraryType::Dynamic`] library if its name ends in
    /// `.so` or carries a versioned soname suffix such as `.so.1.2.3`, a
    /// [`LibraryType::Static`] library if it ends in `.a`, and a [`Type::Binary`]
    /// otherwise. A file with no extension at all — the usual shape of `bin/mytool`
    /// — is a binary.
    pub fn classify(path: &Path) -> Option<Type> {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "cannot stat, not an entrypoint");
                return None;
            }
        };

        if !metadata.is_file() {
            tracing::trace!(path = %path.display(), "not a regular file, not an entrypoint");
            return None;
        }

        // `file_name` only returns `None` for a path ending in `..` or a root, and
        // neither of those can be a regular file, so this is unreachable in practice
        // — but it stays a `?` rather than an unwrap.
        let name = path.file_name()?.to_string_lossy();
        Some(classify_name(&name))
    }
}

/// Classify a file by name alone, once it is known to be a regular file.
///
/// Split out from [`Metadata::classify`] because [`Path::extension`] is the wrong
/// tool here: for `libfoo.so.1.2.3` it answers `"3"`.
fn classify_name(name: &str) -> Type {
    if name.ends_with(".a") {
        return Type::Library(LibraryType::Static);
    }

    let versioned_soname = name
        .split_once(".so.")
        .is_some_and(|(_, version)| is_soname_version(version));

    if name.ends_with(".so") || versioned_soname {
        Type::Library(LibraryType::Dynamic)
    } else {
        Type::Binary
    }
}

/// Whether `version` is the trailing part of a soname, i.e. a dot-separated run of
/// numbers such as `1` or `1.2.3`.
fn is_soname_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .split('.')
            .all(|component| !component.is_empty() && component.bytes().all(|b| b.is_ascii_digit()))
}
