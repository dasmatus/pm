use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
}
impl Metadata {
    pub fn create(dir: PathBuf, version: Vec<String>) -> miette::Result<Self> {
        Ok(Self {
            name: dir.file_name().unwrap().display().to_string(),
            version,
            dependencies: WalkDir::new(dir.join("deps"))
                .into_iter()
                .map(|item| item.unwrap().into_path())
                .collect(),
        })
    }
}
