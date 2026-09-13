use either::Either::{self, Left};
use fetch_data::hash_download;
use miette::{IntoDiagnostic, miette};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_yaml::from_str;
use walkdir::WalkDir;
use std::{collections::HashMap, env::temp_dir, fs::{create_dir_all, read_to_string}, path::PathBuf, process::Command};
use tracing::info;
use url::Url;
#[derive(Serialize, Deserialize)]
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
    pub fn run(&self) -> miette::Result<()> {
        info!("Resolving dependencies.");
        let dep = self.dependencies.par_iter().map(|dep| -> miette::Result<String> {
            let loaded = Self::load(dep.to_path_buf())?;
            if loaded.name == self.name {
                return Err(miette!("Recursive dependencies are not allowed"))
            }
            loaded.run()?;
            Ok(loaded.name)
        });
        info!("Making package {}", self.name);
        create_dir_all(temp_dir().join(&self.name)).into_diagnostic()?;
        dep.try_for_each(|dep|);
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
pub struct Metadata {
    name: String,
    version: Vec<String>,
    dependencies: Vec<PathBuf>,
}
impl Metadata {
    fn create(dir: PathBuf, version: Vec<String>) -> miette::Result<Self> {
        Ok(Self {
            name: dir.file_name().unwrap().display().to_string(),
            version,
            dependencies: WalkDir::new(dir).into_iter().map(|item| item.unwrap().into_path()).collect()
        })
    }
}
impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            dependencies: Left(vec![]),
            name: "".to_string(),
            version: vec![],
            steps: vec![],
        }
    }
}
#[derive(Serialize, Deserialize, Default)]
pub struct Step {
    stage: Stage,
    dl_urls: Option<HashMap<Url, String>>,
    name: String,
    run: Vec<String>,
}

impl Step {
    fn execute(&self) -> miette::Result<()> {
        if let Some(url_sha256s) = &self.dl_urls {
            url_sha256s
                .par_iter()
                .try_for_each(|(url, sha256)| -> miette::Result<()> {
                    let hash = hash_download(
                        url,
                        temp_dir().join(url.to_file_path().unwrap().file_name().unwrap()),
                    )
                    .into_diagnostic()?;
                    if hash != *sha256 {
                        return Err(miette!("Invalid hash: expected {hash}, found {sha256}"));
                    }
                    Ok(())
                })
        } else {
            info!("stage = {:#?}: Running step {}", self.stage, self.name);
            self.run
                .par_iter()
                .try_for_each(|cmd| -> miette::Result<()> {
                    let split: Vec<String> = cmd.split_whitespace().map(|it| it.into()).collect();
                    Command::new(split[0].clone())
                        .args(split[1..split.len()].to_vec())
                        .status()
                        .into_diagnostic()?;
                    Ok(())
                })
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    #[default]
    Prepare,
    Build,
    Install,
    Test,
}
