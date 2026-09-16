use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use miette::{IntoDiagnostic, miette};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
    entrypoints: HashMap<PathBuf, Type>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type {
    Binary,
    Library(LibraryType),
}
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LibraryType {
    Static,
    Dynamic,
}
impl Metadata {
    /// Builds the metadata written alongside a packaged tree.
    ///
    /// `entrypoints` is consumed lazily and only walked here, at the single
    /// point where the map has to exist because it is a serialized field. An
    /// `Err` item aborts the walk on the first failure.
    pub fn create(
        dir: &Path,
        version: Vec<String>,
        entrypoints: impl IntoIterator<Item = miette::Result<(PathBuf, Type)>>,
    ) -> miette::Result<Self> {
        let name = dir
            .file_name()
            .ok_or_else(|| {
                miette!(
                    "{} has no final component to name the package after",
                    dir.display()
                )
            })?
            .display()
            .to_string();
        Ok(Self {
            name,
            version,
            dependencies: WalkDir::new(dir.join("deps"))
                .into_iter()
                .map(|item| item.map(walkdir::DirEntry::into_path).into_diagnostic())
                .collect::<miette::Result<_>>()?,
            entrypoints: entrypoints.into_iter().collect::<miette::Result<_>>()?,
        })
    }

    /// Every declared entrypoint, borrowed in place.
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
}
