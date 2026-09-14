use std::{
    
    fs::{copy, create_dir_all, read_to_string, rename},
    path::{Path, PathBuf},
    process::Command,
};

use crate::{step::Step, metadata::Metadata};
use miette::{IntoDiagnostic, miette};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_yaml::{from_str, to_string};
use tempfile::{TempDir, env::temp_dir};
use std::fs::write;
use tracing::info;

#[derive(Serialize, Deserialize, Default)]
pub struct ConfigFile {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
    steps: Vec<Step>,
}
impl ConfigFile {
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
        write(
            path.join("metadata"),
            to_string::<Metadata>(&Metadata::create(path, self.version.clone()).unwrap())
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
