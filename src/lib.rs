use either::Either::{self, Left};
use miette::IntoDiagnostic;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Command};
use tracing::info;
use url::Url;
#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    name: String,
    version: Vec<String>,
    dependencies: Either<Vec<PathBuf>, Vec<Url>>,
    steps: Vec<Step>,
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
    name: String,
    run: Vec<String>,
}

impl Step {
    fn execute(&self) -> miette::Result<()> {
        info!("{:#?} Running step {}", self.stage, self.name);
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

#[derive(Serialize, Deserialize, Default, Debug)]
pub enum Stage {
    #[default]
    Prepare,
    Build,
    Install,
    Test,
}
