use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{copy, create_dir_all, read_to_string, rename},
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    metadata::{
        LibraryType::{Dynamic, Static},
        Metadata, Type,
    },
    step::Step,
};
use miette::{IntoDiagnostic, miette};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_yaml::{from_str, to_string};
use std::fs::write;
use tempfile::{TempDir, env::temp_dir};
use tracing::info;
use walkdir::WalkDir;

/// Classifies every file under `root` as an entrypoint, lazily.
///
/// Nothing is allocated up front: the walk only advances as the consumer pulls
/// from it, so the caller decides whether the results are ever materialized.
/// Walk failures are yielded as `Err` items rather than panicking, which lets
/// a `collect::<miette::Result<_>>()` short-circuit on the first one.
fn entrypoints(root: &Path) -> impl Iterator<Item = miette::Result<(PathBuf, Type)>> {
    WalkDir::new(root).into_iter().filter_map(|item| {
        let entry = match item.into_diagnostic() {
            Ok(entry) => entry,
            Err(error) => return Some(Err(error)),
        };
        // `file_type` reuses what readdir already reported; `metadata` would
        // cost an extra stat per entry.
        if !entry.file_type().is_file() {
            return None;
        }
        let path = entry.into_path();
        let r#type = match path.extension().and_then(OsStr::to_str) {
            Some("so") => Type::Library(Dynamic),
            Some("a") => Type::Library(Static),
            _ => Type::Binary,
        };
        Some(Ok((path, r#type)))
    })
}

#[derive(Serialize, Deserialize, Default)]
pub struct ConfigFile {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
    steps: Vec<Step>,
}
impl ConfigFile {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            name: "example".into(),
            version: ["0".into(), "1".into(), "0".into()].to_vec(),
            dependencies: [Path::new("/tmp").to_path_buf()].to_vec(),
            steps: [Step {
                stage: crate::step::Stage::Prepare,
                dl_urls: Some(HashMap::new()),
                name: String::new(),
                run: vec![],
            }]
            .to_vec(),
        }
    }
    fn load(path: PathBuf) -> miette::Result<Self> {
        let config_file = from_str(&read_to_string(path).into_diagnostic()?).into_diagnostic()?;
        Ok(config_file)
    }

// todo: make a package for analyzing source code and binaries using strace so that we can add more [`Metadata`] about the package's permissions to it.
    
    fn package(&self) -> miette::Result<PathBuf> {
        info!("Packaging {}", self.name);
        let tmpdir = TempDir::new().into_diagnostic()?;
        let tmpdir = tmpdir.path();
        let polish = tmpdir.join(format!("{}.tar.xz", self.name));
        Command::new("tar")
            .arg("-czvf")
            .arg(tmpdir.join(&self.name))
            .arg("-C")
            .arg(&polish)
            .status()
            .unwrap();
        rename(polish, tmpdir.join(format!("{}.cpkg", self.name))).into_diagnostic()?;
        Ok(tmpdir.join(format!("/tmp/{}.cpkg", self.name)).clone())
    }
    pub fn run(&self) -> miette::Result<()> {
        info!("Resolving dependencies.");
        self.dependencies
            .par_iter()
            .try_for_each(|dep| -> miette::Result<()> {
                if !self.dependencies.is_empty() && dep.exists() {
                    let loaded = Self::load(dep.clone())?;
                    if loaded.name == self.name {
                        return Err(miette!("Recursive dependencies are not allowed."));
                    }
                    loaded.run()?;
                }
                Ok(())
            })?;
        info!("Making package {}, version {:?}", self.name, self.version);
        let tmpdir = TempDir::new().into_diagnostic()?;
        let tmpdir = tmpdir.path();
        let path = tmpdir.join(&self.name);
        create_dir_all(path.join("deps")).into_diagnostic()?;
        if !self.dependencies.is_empty() {
            self.dependencies
                .par_iter()
                .try_for_each(|dep| -> miette::Result<()> {
                    copy(temp_dir().join(dep), path.join("deps").join(dep)).into_diagnostic()?;
                    Ok(())
                })?;
        }
        if !self.steps.is_empty() {
            self.steps
                .iter()
                .try_for_each(|step| -> miette::Result<()> { step.execute(&self.name) })?;
        }
        info!("Finishing up.");
        let metadata = Metadata::create(&path, self.version.clone(), entrypoints(&path))?;
        write(
            path.join("metadata"),
            to_string::<Metadata>(&metadata).into_diagnostic()?,
        )
        .into_diagnostic()?;
        if !self
            .dependencies
            .contains(&Path::new(&self.name).to_path_buf())
        {
            let pkg = self.package()?;
            info!("DONE, located at {}", pkg.display());
        }

        Ok(())
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The declared dependency paths, borrowed in place.
    #[must_use]
    pub fn dependencies(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.dependencies.iter().map(PathBuf::as_path)
    }
}
