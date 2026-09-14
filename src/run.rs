use std::{fs::read_to_string, path::PathBuf, process::Command};

use dialoguer::Select;
use hakoniwa::Container;
use miette::IntoDiagnostic;
use serde_yaml::from_str;
use tempfile::TempDir;
use tracing::info;
use rayon::prelude::*;
use crate::metadata::{Metadata, Type};
#[derive(Default)]
pub struct PackageRunner {
    path: PathBuf,
}
impl PackageRunner {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
    pub fn run(&self, bin: Option<String>) -> miette::Result<()> {
        info!("Running {}", self.path.display());
        let tmpdir = TempDir::new().into_diagnostic()?;
        let tmpdir = tmpdir.path();
        let mut to_run = String::new();
        Command::new("tar").arg("-xpvf").arg(&self.path).arg("-C").arg(tmpdir);
        let cfg_file: Metadata = from_str(&read_to_string(tmpdir.join("metadata")).into_diagnostic()?).into_diagnostic()?;
        if bin.is_none() {
            let available_bins: Vec<_> = cfg_file.entrypoints().par_iter().filter(|(_, ty)| **ty == Type::Binary).map(|(it, _)| it.display().to_string()).collect();
            let run = Select::new().items(available_bins.clone()).with_prompt("Select which binary to run:").interact().unwrap();
            to_run = available_bins[run].clone();
        }
        Container::new().command(&to_run).spawn().into_diagnostic()?;
        Ok(())
    }
}
