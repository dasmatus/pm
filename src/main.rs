use clap::Parser;
use miette::IntoDiagnostic;
use pm::bf::ConfigFile;
use serde_yaml::{from_str, to_string};
use tracing_subscriber::fmt;
use std::{fs::{read_to_string, write}, path::PathBuf};
#[derive(Parser)]
#[clap(name = "pm", version, about = "A package manager")]
struct Arge {
    #[arg(short, long)]
    build: Option<PathBuf>,
    #[arg(short, long)]
    generate: Option<PathBuf>,
    #[arg(short, long)]
    run: Option<PathBuf>
}

fn main() -> miette::Result<()> {
    let args = Arge::parse();
    fmt().without_time().init();
    if let Some(build) = args.build {
        let cfg_file =
            from_str::<ConfigFile>(&read_to_string(build).into_diagnostic()?).into_diagnostic()?;
        cfg_file.run()?;
    } else if let Some(generate) = args.generate {
        write(generate, to_string(&ConfigFile::default()).into_diagnostic()?).into_diagnostic()?;
    } else if let Some(run) = args.run {
        
    }
    Ok(())
}
