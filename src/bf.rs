use std::{
    collections::HashMap, fs::{copy, create_dir_all, read_to_string, rename}, path::{Path, PathBuf}, process::Command
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

#[derive(Serialize, Deserialize, Default)]
pub struct ConfigFile {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
    steps: Vec<Step>,
}
impl ConfigFile {
    pub fn generate() -> Self {
        Self {
            name: "example".into(),
            version: ["0".into(), "1".into(), "0".into()].to_vec(),
            dependencies: [Path::new("/tmp").to_path_buf()].to_vec(),
            steps: [Step {
                stage: crate::step::Stage::Prepare,
                dl_urls: Some(HashMap::new()),
                name: "".to_string(),
                run: vec![]
            }].to_vec()
        }
    }
    fn load(path: PathBuf) -> miette::Result<Self> {
        let config_file = from_str(&read_to_string(path).into_diagnostic()?).into_diagnostic()?;
        Ok(config_file)
    }
    fn package(&self) -> miette::Result<PathBuf> {
        info!("Packaging {}", self.name);
        let tmpdir = TempDir::new().into_diagnostic()?;
        let tmpdir = tmpdir.path();
        let polish = tmpdir.join(format!("{}.tar.xz", self.name));
        Command::new("tar")
            .arg("-Czvf")
            .arg(&polish)
            .arg(tmpdir.join(&self.name))
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
        // collect files
        let files_type = WalkDir::new(&path)
            .into_iter()
            .map(|item| -> (PathBuf, Type) {
                let path1 = item.unwrap().into_path();
                let mut r#type = Type::Binary;
                if path1.metadata().unwrap().is_file() {
                    let fext = path1.extension().unwrap();
                    if fext.eq("so") {
                        r#type = Type::Library(Dynamic)
                    } else if fext.eq("a") {
                        r#type = Type::Library(Static)
                    }
                }
                (path1, r#type)
            })
            .collect();
        info!("Finishing up.");
        write(
            path.join("metadata"),
            to_string::<Metadata>(
                &Metadata::create(path, self.version.clone(), files_type).unwrap(),
            )
            .into_diagnostic()?,
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

    #[must_use]
    pub fn dependencies(&self) -> &[PathBuf] {
        &self.dependencies
    }
}
