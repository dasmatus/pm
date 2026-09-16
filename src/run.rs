use std::{fs::read_to_string, path::PathBuf, process::Command};

use crate::metadata::Metadata;
use dialoguer::Select;
use hakoniwa::Container;
use miette::{IntoDiagnostic, miette};
use serde_yaml::from_str;
use tempfile::TempDir;
use tracing::info;
#[derive(Default)]
pub struct PackageRunner {
    path: PathBuf,
}
impl PackageRunner {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
    pub fn run(&self, bin: Option<String>) -> miette::Result<()> {
        info!("Running {}", self.path.display());
        let tmpdir = TempDir::new().into_diagnostic()?;
        let tmpdir = tmpdir.path();
        Command::new("tar")
            .arg("-xpvf")
            .arg(&self.path)
            .arg("-C")
            .arg(tmpdir);
        let cfg_file: Metadata =
            from_str(&read_to_string(tmpdir.join("metadata")).into_diagnostic()?)
                .into_diagnostic()?;
        let to_run = if let Some(bin) = bin {
            bin
        } else {
            // One of the few collects that has to stay: `Select` needs the
            // whole list up front and answers with a *position*, which an
            // iterator cannot be indexed by. Holding `&Path` keeps it to one
            // pointer-sized push per entrypoint, and the strings are built
            // exactly once, inside dialoguer.
            let available_bins: Vec<_> = cfg_file.binaries().collect();
            let selected = Select::new()
                .items(available_bins.iter().map(|path| path.display()))
                .with_prompt("Select which binary to run:")
                .interact()
                .into_diagnostic()?;
            let chosen = available_bins[selected];
            chosen
                .to_str()
                .ok_or_else(|| miette!("{} is not valid UTF-8", chosen.display()))?
                .to_owned()
        };
        Container::new()
            .command(&to_run)
            .spawn()
            .into_diagnostic()?;
        Ok(())
    }
}
