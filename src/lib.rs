use fetch_data::hash_download;
use miette::{IntoDiagnostic, miette};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_yaml::from_str;
use std::{
    collections::HashMap,
    env::temp_dir,
    fs::{copy, create_dir_all, read_to_string},
    path::{Path, PathBuf},
    process::Command,
};
use tracing::info;
use url::Url;
use walkdir::WalkDir;
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
    pub fn run(&self) -> miette::Result<()> {
        info!("Resolving dependencies.");
        self.dependencies
            .par_iter()
            .try_for_each(|dep| -> miette::Result<()> {
                if !self.dependencies.is_empty() {
                    let loaded = Self::load(dep.to_path_buf())?;
                    if loaded.name == self.name {
                        return Err(miette!("Recursive dependencies are not allowed."));
                    }
                    loaded.run()?;
                }
                Ok(())
            })?;
        info!("Making package {}, version {:?}", self.name, self.version);
        let path = temp_dir().join(&self.name);
        create_dir_all(path.join("deps")).into_diagnostic()?;
        if !self.dependencies.is_empty() {
            self.dependencies
                .par_iter()
                .try_for_each(move |dep| -> miette::Result<()> {
                    copy(temp_dir().join(dep), path.join("deps").join(dep)).into_diagnostic()?;
                    Ok(())
                })?;
        }
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
            dependencies: WalkDir::new(dir.join("deps"))
                .into_iter()
                .map(|item| item.unwrap().into_path())
                .collect(),
        })
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
                    info!("{url} downloaded.");
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
