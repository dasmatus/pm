use std::path::PathBuf;

use tracing::info;
#[derive(Default)]
pub struct PackageRunner {
    path: PathBuf,
}
impl PackageRunner {
    pub fn run(&self) -> miette::Result<()> {
        info!("Running {}", self.path.display());

        Ok(())
    }
}
