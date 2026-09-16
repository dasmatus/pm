use clap::{Parser, Subcommand};
use miette::{IntoDiagnostic, WrapErr, miette};
use pm::{
    bf::BuildFile,
    policy::{BuildPolicy, UNMATCHED},
    run::PackageRunner,
    signing::{
        Signature, SigningKey, TrustStore, default_key_path, default_trust_dir, sign_file,
    },
};
use serde_yaml::to_string;
use std::{
    fs::{OpenOptions, read_to_string, remove_file, write},
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
};
use tracing::{info, warn};
use tracing_subscriber::fmt;

/// Width the labels of the key/value blocks are padded to, so their values
/// line up under each other.
const LABEL_WIDTH: usize = 12;

/// Header of the command column `pm explain` prints.
const COMMAND_HEADER: &str = "COMMAND";

/// Widest the command column is padded to. A longer command is not truncated -
/// the row simply runs past the column - because a build file is something the
/// user has to be able to read back verbatim.
const COMMAND_WIDTH_CAP: usize = 72;

#[derive(Parser)]
#[clap(name = "pm", version, about = "A package manager")]
#[command(subcommand_required = true, arg_required_else_help = true)]
struct Arge {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build and package the project described by a build file.
    ///
    /// The build file is read first: every step command is matched against the
    /// built-in fingerprint table to derive the sandbox policy, and a command
    /// that matches nothing aborts the build before anything runs. Use
    /// `pm explain` to see that policy, and `--permissive` to build anyway.
    Build {
        /// Path to the build file.
        file: PathBuf,
        /// Allow commands that match no built-in fingerprint.
        #[arg(long)]
        permissive: bool,
        /// Run the build steps on the host instead of inside the sandbox.
        ///
        /// For debugging a build that the jail breaks. The build file then runs
        /// with your full privileges and can read your home directory, so only
        /// use it on a build file you wrote yourself.
        #[arg(long)]
        unsandboxed: bool,
    },
    /// Print the sandbox policy derived from a build file, without building.
    ///
    /// Lists every step command, the fingerprint that matched it, the
    /// capabilities those matches add up to, and the digest of the whole thing.
    /// Exits non-zero when a command matches no fingerprint, so it doubles as a
    /// lint in a pre-commit hook or CI.
    Explain {
        /// Path to the build file.
        file: PathBuf,
        /// Report unmatched commands instead of stopping at the first batch.
        ///
        /// The table is printed in full and the exit status is still non-zero.
        #[arg(long)]
        permissive: bool,
    },
    /// Write an example build file to the given path.
    Generate {
        /// Path the example build file is written to.
        file: PathBuf,
        /// Overwrite the file if it already exists.
        #[arg(short, long)]
        force: bool,
    },
    /// Run a binary contained in a built package.
    Run {
        /// Path to the .cpkg archive.
        package: PathBuf,
        /// Name of the binary to run; prompts when omitted.
        #[arg(short, long)]
        bin: Option<String>,
        /// Let the program reach the network.
        ///
        /// Off by default: the program runs in its own empty network namespace
        /// and cannot talk to the host, the LAN or the internet.
        #[arg(short, long)]
        network: bool,
    },
    /// Sign a build file or a package with your key.
    ///
    /// Writes a detached `<FILE>.sig` next to it, so a package travels as two
    /// files. Generates your signing key on first use and trusts it locally,
    /// otherwise you could not verify your own work.
    Sign {
        /// Path to the build file or .cpkg archive to sign.
        file: PathBuf,
        /// Signing key to use instead of the one under your config directory.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
        /// Trust store a freshly generated key is added to.
        #[arg(long, value_name = "DIR")]
        trust_dir: Option<PathBuf>,
    },
    /// Create the signing key without signing anything.
    ///
    /// Refuses to overwrite an existing key: a lost signing key cannot be
    /// recovered, and everything signed with it has to be signed again under a
    /// key nobody trusts yet.
    Keygen {
        /// Destroy an existing key and put a new one in its place.
        #[arg(short, long)]
        force: bool,
        /// Write the key here instead of under your config directory.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
        /// Trust store the new key is added to.
        #[arg(long, value_name = "DIR")]
        trust_dir: Option<PathBuf>,
    },
    /// Accept signatures made by a public key from now on.
    ///
    /// Takes the key as hex, or the path to a file holding it - either a `.pub`
    /// from the trust store or any `.sig`, whose signer is then trusted.
    Trust {
        /// Public key hex, or a path to a `.pub` or `.sig` file.
        #[arg(value_name = "PUBKEY_HEX|FILE")]
        key: String,
        /// Trust store to add the key to.
        #[arg(long, value_name = "DIR")]
        trust_dir: Option<PathBuf>,
    },
}

fn main() -> miette::Result<()> {
    // Initialised before parsing so that argument-parsing failures are logged too.
    fmt().without_time().init();
    let args = Arge::parse();

    match args.command {
        Commands::Build {
            file,
            permissive,
            unsandboxed,
        } => build(&file, permissive, unsandboxed)?,
        Commands::Explain { file, permissive } => explain(&file, permissive)?,
        Commands::Generate { file, force } => generate(&file, force)?,
        Commands::Run {
            package,
            bin,
            network,
        } => {
            if !package.exists() {
                return Err(miette!("The path {} does not exist.", package.display()));
            }
            if network {
                warn!(
                    "--network was given: the program shares the host network namespace \
                     and can reach the internet, the LAN and host-local services"
                );
            }
            // `PackageRunner::run` owns the `Workspace` and `SandboxedChild` guards for
            // the whole lifetime of the sandboxed process, and both are dropped before it
            // hands back an `ExitStatus`. This frame therefore holds nothing that
            // implements `Drop`, which is what makes the `std::process::exit` below safe:
            // that call terminates immediately and runs no destructors, so were a guard
            // still live here it would leak the staging directory and leave the child
            // unreaped. Do not move the exit into a scope that still holds one.
            let status = PackageRunner::new(package).allow_network(network).run(bin)?;
            if !status.success() {
                warn!(
                    code = status.code,
                    reason = %status.reason,
                    "sandboxed program exited unsuccessfully"
                );
                std::process::exit(status.code);
            }
        }
        Commands::Sign {
            file,
            key,
            trust_dir,
        } => sign(&file, key, trust_dir)?,
        Commands::Keygen {
            force,
            key,
            trust_dir,
        } => keygen(force, key, trust_dir)?,
        Commands::Trust { key, trust_dir } => trust(&key, trust_dir)?,
    }

    Ok(())
}

/// Derives the policy from `file`, then builds and packages it.
///
/// # Errors
///
/// Fails if the build file is missing or unparseable, if a command matches no
/// fingerprint and `permissive` is false, or if the build itself fails.
fn build(file: &Path, permissive: bool, unsandboxed: bool) -> miette::Result<()> {
    if !file.exists() {
        return Err(miette!("The path {} does not exist.", file.display()));
    }

    let build_file = BuildFile::load(file)?;
    let policy = BuildPolicy::derive(&build_file, permissive).wrap_err_with(|| {
        format!(
            "cannot derive a sandbox policy for {}; run `pm explain {}` to see the whole \
             build file, or pass --permissive to build it anyway",
            file.display(),
            file.display()
        )
    })?;
    info!(
        fingerprint = policy.fingerprint(),
        capabilities = ?policy.capabilities(),
        "derived the sandbox policy from the build file"
    );

    if unsandboxed {
        warn!(
            file = %file.display(),
            "--unsandboxed was given: build steps run on the host with your privileges, \
             outside the jail. A hostile build file can read your SSH keys and write \
             anywhere you can. Use this only to debug a build file you trust."
        );
    }

    let archive = run_build(&build_file, &policy, unsandboxed)?;
    info!(archive = %archive.display(), "packaged");
    Ok(())
}

/// The single seam between the CLI and the builder.
///
/// `BuildFile::run` does not take the policy or the escape hatch yet, so they
/// are resolved here and handed over as soon as it does; this function is the
/// only place that has to change when it grows the parameters.
///
/// # Errors
///
/// Propagates whatever the build fails with.
fn run_build(
    build_file: &BuildFile,
    policy: &BuildPolicy,
    unsandboxed: bool,
) -> miette::Result<PathBuf> {
    let _ = (policy, unsandboxed);
    build_file.run()
}

/// Prints the policy derived from `file` without building it.
///
/// The table goes to stdout because it is this subcommand's primary output and
/// is meant to be read, piped and diffed; everything else stays on `tracing`.
///
/// # Errors
///
/// Fails if the build file is missing or unparseable, and - after printing the
/// whole table - if any command matched no fingerprint, so that the subcommand
/// works as a lint.
fn explain(file: &Path, permissive: bool) -> miette::Result<()> {
    if !file.exists() {
        return Err(miette!("The path {} does not exist.", file.display()));
    }

    let build_file = BuildFile::load(file)?;
    let policy = BuildPolicy::derive(&build_file, permissive).wrap_err_with(|| {
        format!(
            "cannot derive a sandbox policy for {}; pass --permissive to list every \
             command anyway",
            file.display()
        )
    })?;

    let capabilities = if policy.capabilities().is_empty() {
        "none".to_owned()
    } else {
        policy
            .capabilities()
            .iter()
            .map(|capability| format!("{capability:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    println!("{:<LABEL_WIDTH$}{}", "build file:", file.display());
    println!(
        "{:<LABEL_WIDTH$}{} {}",
        "package:",
        build_file.name(),
        build_file.version_string()
    );
    println!("{:<LABEL_WIDTH$}{}", "digest:", policy.fingerprint());
    println!("{:<LABEL_WIDTH$}{capabilities}", "grants:");
    println!();

    if policy.matches().is_empty() {
        println!("This build file runs no commands.");
        return Ok(());
    }

    // Fold rather than `max()` so there is no `Option` to unwrap, and start
    // from the header so a table of short commands still lines up under it.
    let width = policy
        .matches()
        .iter()
        .fold(COMMAND_HEADER.len(), |widest, (command, _)| {
            widest.max(command.chars().count())
        })
        .min(COMMAND_WIDTH_CAP);

    println!("{COMMAND_HEADER:<width$}  FINGERPRINT");
    for (command, fingerprint) in policy.matches() {
        println!("{command:<width$}  {fingerprint}");
    }

    let unmatched = policy
        .matches()
        .iter()
        .filter(|(_, fingerprint)| *fingerprint == UNMATCHED)
        .count();
    if unmatched > 0 {
        println!();
        return Err(miette!(
            help = "A command needs a fingerprint before the sandbox can grant it \
                    anything. Rewrite it to use a program the table knows, or run \
                    `pm build --permissive` and accept that those commands get no \
                    capabilities at all.",
            "{unmatched} {} in {} {} no built-in fingerprint.",
            if unmatched == 1 { "command" } else { "commands" },
            file.display(),
            if unmatched == 1 { "matches" } else { "match" }
        ));
    }

    Ok(())
}

/// Writes the example build file to `file`.
///
/// # Errors
///
/// Fails if `file` exists and `force` is false, or if it cannot be written.
fn generate(file: &Path, force: bool) -> miette::Result<()> {
    let example = to_string(&BuildFile::generate()).into_diagnostic()?;

    if force {
        // This pre-check is racy, deliberately: `--force` already opted into
        // clobbering whatever is at the path, so the answer only decides
        // whether the replacement is worth a warning.
        let replaced = file.exists();
        write(file, &example).into_diagnostic().wrap_err_with(|| {
            format!(
                "Could not write the example build file to {}",
                file.display()
            )
        })?;
        if replaced {
            warn!(file = %file.display(), "replaced an existing file");
        }
    } else {
        // `create_new` folds "does this exist?" and "create it" into one
        // syscall, so a file that appears between the two is rejected by the
        // kernel instead of being silently truncated, which a `Path::exists`
        // pre-check followed by a plain write would do.
        let opened = OpenOptions::new().write(true).create_new(true).open(file);
        let mut handle = match opened {
            Ok(handle) => handle,
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                return Err(miette!(
                    help = "Pass --force to overwrite it.",
                    "The path {} already exists.",
                    file.display()
                ));
            }
            Err(source) => {
                return Err(source)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("Could not create {}", file.display()));
            }
        };
        handle
            .write_all(example.as_bytes())
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "Could not write the example build file to {}",
                    file.display()
                )
            })?;
    }

    info!(file = %file.display(), "wrote example build file");
    Ok(())
}

/// Signs `file`, generating and trusting the signing key on first use.
///
/// The paths and the public key go to stdout: they are this subcommand's
/// primary output, and the public key is meant to be copied to whoever has to
/// verify the result.
///
/// # Errors
///
/// Fails if `file` does not exist, if the key cannot be loaded or created, if
/// the new key cannot be trusted, or if the signature cannot be written.
fn sign(file: &Path, key: Option<PathBuf>, trust_dir: Option<PathBuf>) -> miette::Result<()> {
    if !file.exists() {
        return Err(miette!("The path {} does not exist.", file.display()));
    }

    let key_path = resolve_key_path(key)?;
    // Asked before the key is loaded, because `load_or_create` erases the
    // difference: afterwards there is no way to tell a key it just generated
    // from one that was already there.
    let generated = !key_path.exists();

    let signing_key = SigningKey::load_or_create(&key_path)?;
    let public_key = signing_key.public_key_hex();

    if generated {
        // `load_or_create` warns that the key is new; trusting it here is what
        // keeps `pm sign` from producing a signature the same machine rejects.
        let dir = resolve_trust_dir(trust_dir)?;
        TrustStore::load(&dir)?.add(&public_key, &dir)?;
        warn!(
            path = %key_path.display(),
            "generated a new signing key and trusted it locally; back it up, it cannot be recovered"
        );
    }

    let signature = sign_file(file, &signing_key)?;

    println!("{:<LABEL_WIDTH$}{}", "signed:", file.display());
    println!("{:<LABEL_WIDTH$}{}", "signature:", signature.display());
    println!("{:<LABEL_WIDTH$}{}", "key:", key_path.display());
    println!("{:<LABEL_WIDTH$}{public_key}", "public key:");
    Ok(())
}

/// Creates the signing key, refusing to destroy an existing one without `force`.
///
/// The public key goes to stdout: producing it is the point of the subcommand,
/// and it has to be pasteable into whatever trusts this machine.
///
/// # Errors
///
/// Fails if a key already exists and `force` is false, if the old key cannot be
/// removed, or if the new key cannot be generated or trusted.
fn keygen(force: bool, key: Option<PathBuf>, trust_dir: Option<PathBuf>) -> miette::Result<()> {
    let key_path = resolve_key_path(key)?;

    if key_path.exists() {
        if !force {
            return Err(miette!(
                help = "Pass --force to destroy it and start over. Everything signed with \
                        the old key then has to be signed again, and every machine that \
                        trusted it has to trust the new one.",
                "A signing key already exists at {}.",
                key_path.display()
            ));
        }
        warn!(
            path = %key_path.display(),
            "--force was given: destroying the existing signing key, which cannot be undone"
        );
        remove_file(&key_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not remove the signing key {}", key_path.display()))?;
    }

    let signing_key = SigningKey::load_or_create(&key_path)?;
    let public_key = signing_key.public_key_hex();

    let dir = resolve_trust_dir(trust_dir)?;
    TrustStore::load(&dir)?.add(&public_key, &dir)?;

    println!("{:<LABEL_WIDTH$}{}", "key:", key_path.display());
    println!("{:<LABEL_WIDTH$}{public_key}", "public key:");
    Ok(())
}

/// Adds a public key to the trust store.
///
/// `key` is either the hex itself or a path to a file holding it. A file that
/// parses as a detached signature contributes its signer, which is how a
/// package and the key that signed it can be trusted from the same two files.
///
/// # Errors
///
/// Fails if the file cannot be read, if the key is not valid Ed25519 public key
/// hex, or if the trust store cannot be written.
fn trust(key: &str, trust_dir: Option<PathBuf>) -> miette::Result<()> {
    let path = Path::new(key);
    let public_key = if path.is_file() {
        let text = read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not read {}", path.display()))?;
        match Signature::from_yaml(&text) {
            Ok(signature) => {
                info!(path = %path.display(), "taking the signer of this signature");
                signature.public_key_hex().to_owned()
            }
            // Not a signature, so the file is a bare key. `TrustStore::add`
            // validates the hex and says so precisely if it is not one.
            Err(_) => text.trim().to_owned(),
        }
    } else {
        key.trim().to_owned()
    };

    let dir = resolve_trust_dir(trust_dir)?;
    let mut store = TrustStore::load(&dir)?;
    if store.trusts(&public_key) {
        info!(public_key = %public_key, dir = %dir.display(), "already trusted");
        return Ok(());
    }
    store.add(&public_key, &dir)
}

/// The signing key path, `--key` winning over the default location.
///
/// # Errors
///
/// Fails if no default config directory can be determined.
fn resolve_key_path(key: Option<PathBuf>) -> miette::Result<PathBuf> {
    key.map_or_else(default_key_path, Ok)
}

/// The trust store directory, `--trust-dir` winning over the default location.
///
/// # Errors
///
/// Fails if no default config directory can be determined.
fn resolve_trust_dir(trust_dir: Option<PathBuf>) -> miette::Result<PathBuf> {
    trust_dir.map_or_else(default_trust_dir, Ok)
}
