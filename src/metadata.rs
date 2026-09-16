//! Package metadata written into each archive.
//!
//! A [`Metadata`] value is serialised to YAML as the `metadata` file at the root of
//! every `.cpkg` archive. It records the package identity, the dependencies bundled
//! under `deps/`, and the entrypoints a consumer can run or link against.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// The package's metadata, stored as YAML at the archive root.
///
/// Construct one with [`Metadata::create`]; the fields are private so the invariant
/// that entrypoint keys are package-relative stays with the caller that walked the
/// staging directory.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Metadata {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
    entrypoints: HashMap<PathBuf, Type>,
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
    pub fn create(
        name: String,
        version: Vec<String>,
        dependencies: Vec<PathBuf>,
        entrypoints: HashMap<PathBuf, Type>,
    ) -> Self {
        tracing::debug!(
            %name,
            dependencies = dependencies.len(),
            entrypoints = entrypoints.len(),
            "assembling package metadata"
        );
        Self {
            name,
            version,
            dependencies,
            entrypoints,
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

    /// Paths of the bundled dependencies, relative to the package root.
    pub fn dependencies(&self) -> &[PathBuf] {
        &self.dependencies
    }

    /// The runnable and linkable files of this package, keyed by their path
    /// relative to the package root.
    pub fn entrypoints(&self) -> &HashMap<PathBuf, Type> {
        &self.entrypoints
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
