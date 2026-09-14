use std::{collections::HashMap, env::temp_dir, process::Command};

use fetch_data::hash_download;
use miette::{miette, IntoDiagnostic};
use serde::{Deserialize, Serialize};
use tracing::info;
use url::Url;
use rayon::prelude::*;
#[derive(Serialize, Deserialize, Default)]
pub struct Step {
    stage: Stage,
    dl_urls: Option<HashMap<Url, String>>,
    name: String,
    run: Vec<String>,
}

impl Step {
    pub(crate) fn execute(&self, name: &str) -> miette::Result<()> {
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
                    let split: Vec<String> = cmd
                        .split_whitespace()
                        .map(std::convert::Into::into)
                        .collect();
                    Command::new(split[0].clone())
                        .args(split[1..split.len()].to_vec())
                        .env("DESTDIR", temp_dir().join(name).join("pkg"))
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