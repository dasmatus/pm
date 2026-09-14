use clap::Parser;
use miette::IntoDiagnostic;
use pm::bf::ConfigFile;
use serde_yaml::from_str;
use std::{fs::read_to_string, path::PathBuf};
#[derive(Parser)]
#[clap(name = "pm", version, about = "A package manager")]
struct Arge {
    #[arg(short, long)]
    build: Option<PathBuf>,
}

fn main() -> miette::Result<()> {
    let args = Arge::parse();
    if let Some(build) = args.build {
        let cfg_file =
            from_str::<ConfigFile>(&read_to_string(build).into_diagnostic()?).into_diagnostic()?;
        cfg_file.run()?;
    }
    Ok(())
}
