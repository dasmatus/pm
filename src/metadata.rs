use std::{
    collections::HashMap,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
    entrypoints: HashMap<PathBuf, Type>,
}
#[derive(Serialize, Deserialize)]
pub enum Type {
    Binary,
    Library(LibraryType),
}
#[derive(Serialize, Deserialize)]
pub enum LibraryType {
    Static,
    Dynamic,
}
impl Metadata {
    pub fn create(
        dir: PathBuf,
        version: Vec<String>,
        entrypoints: HashMap<PathBuf, Type>,
    ) -> miette::Result<Self> {
        Ok(Self {
            name: dir.file_name().unwrap().display().to_string(),
            version,
            dependencies: WalkDir::new(dir.join("deps"))
                .into_iter()
                .map(|item| item.unwrap().into_path())
                .collect(),
            entrypoints,
        })
    }

    pub fn entrypoints(&self) -> &HashMap<PathBuf, Type> {
        &self.entrypoints
    }
}
