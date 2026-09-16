//! A randomised escape fuzzer for the `pm` sandbox.
//!
//! Every iteration builds a hostile `.cpkg` out of the axes in [`Shape`], hands
//! it to the real `pm` binary, and then asks one question: did anything escape?
//!
//! # What counts as an escape
//!
//! Only these, and the distinction is the whole point of the tool:
//!
//! * a canary file outside the iteration's workspace was created, deleted or
//!   modified,
//! * a file appeared anywhere outside the workspace,
//! * `pm` itself panicked (exit 101) or died on a signal.
//!
//! A non-zero exit and a clean `miette` diagnostic are the sandbox **working**.
//! A fuzzer that reports every error as a finding drowns the real ones and gets
//! switched off, so refusals are counted and discarded.
//!
//! # Running it
//!
//! ```text
//! cargo run --release --bin pm-fuzz -- --iterations 500 --jobs 4
//! cargo run --release --bin pm-fuzz -- --seed 12345 --stop-on-first
//! ```
//!
//! The seed is logged on every run and is the only thing needed to replay a
//! finding, so a crash is always reproducible.

use std::{
    fs::{create_dir_all, read_dir, remove_dir_all, write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use arbitrary::{Arbitrary, Unstructured};
use clap::Parser;
use miette::{IntoDiagnostic, miette};
use rayon::prelude::*;
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt;

/// How long a single `pm` invocation may take before it is killed.
const RUN_TIMEOUT: Duration = Duration::from_secs(20);

/// Exit status Rust uses for a panic. Anything else non-zero is a diagnostic.
const PANIC_EXIT: i32 = 101;

#[derive(Parser)]
#[command(
    name = "pm-fuzz",
    about = "Fuzz the pm sandbox for escapes",
    long_about = "Generates hostile packages and checks that none of them can touch anything \
                  outside their workspace. Only a touched canary, a stray file or a crash in \
                  pm counts as a finding; a clean refusal is the sandbox working."
)]
struct Args {
    /// Seed for the generator. Logged on every run, so a finding replays exactly.
    #[arg(long)]
    seed: Option<u64>,
    /// How many packages to try. `0` runs until interrupted.
    #[arg(long, default_value_t = 200)]
    iterations: u64,
    /// How many iterations to run at once.
    #[arg(long, default_value_t = 4)]
    jobs: usize,
    /// Keep the workspace of every iteration, not just the ones that escaped.
    #[arg(long)]
    keep_failures: bool,
    /// Stop as soon as something escapes.
    #[arg(long)]
    stop_on_first: bool,
    /// Where to work. A temporary directory by default.
    #[arg(long)]
    root: Option<PathBuf>,
}

/// `SplitMix64`, used purely as a reproducible ENTROPY SOURCE.
///
/// It no longer decides anything: [`generate`] hands these bytes to
/// [`arbitrary`], which derives the case structurally. Keeping the stream a
/// pure function of `(seed, iteration)` is what makes a finding replayable from
/// its seed alone.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n`. `n == 0` yields 0 rather than dividing by zero.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// The signature state a generated package ships with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum SigState {
    /// No `.sig` at all.
    Absent,
    /// A `.sig` full of garbage.
    Malformed,
    /// A real signature from a key nothing trusts.
    Untrusted,
    /// A real signature from the trusted key, over the real bytes.
    Valid,
    /// A real signature from the trusted key, over *different* bytes.
    Stale,
}

impl SigState {
    const fn label(self) -> &'static str {
        match self {
            Self::Absent => "sig-absent",
            Self::Malformed => "sig-malformed",
            Self::Untrusted => "sig-untrusted",
            Self::Valid => "sig-valid",
            Self::Stale => "sig-stale",
        }
    }
}

/// How the archive itself is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum Layout {
    /// A well-formed package, so the hostile part is the metadata.
    Ordinary,
    /// A member whose path climbs out with `..`.
    Traversal,
    /// A symlink member aimed at an absolute host path.
    Symlink,
    /// A member with an absolute path.
    AbsoluteMember,
    /// `metadata` is a directory rather than a file.
    MetadataDirectory,
    /// No `metadata` member at all.
    NoMetadata,
    /// Not an archive: random bytes.
    Garbage,
    /// A valid xz stream cut in half.
    Truncated,
    /// An archive with no members.
    Empty,
}

impl Layout {
    const fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "layout-ordinary",
            Self::Traversal => "layout-traversal",
            Self::Symlink => "layout-symlink",
            Self::AbsoluteMember => "layout-absolute-member",
            Self::MetadataDirectory => "layout-metadata-dir",
            Self::NoMetadata => "layout-no-metadata",
            Self::Garbage => "layout-garbage",
            Self::Truncated => "layout-truncated",
            Self::Empty => "layout-empty",
        }
    }
}

/// One generated case.
#[derive(Debug, Clone)]
struct Shape {
    iteration: u64,
    layout: Layout,
    signature: SigState,
    /// The entrypoint map written into `metadata`.
    entrypoints: Vec<String>,
    /// The entrypoint passed as `--bin`, if any.
    bin: Option<String>,
    /// Whether the payload staged in the package tries to break out.
    hostile_payload: bool,
    /// Let the sandbox reach the network.
    network: bool,
}

/// What an iteration turned into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The sandbox held: a refusal, or a run that touched nothing.
    Contained,
    /// A canary moved, a stray file appeared, or `pm` crashed.
    Escaped,
    /// `pm` had to be killed.
    TimedOut,
    /// The case could not be built; not a finding, just skipped.
    Skipped,
}

/// How far into `pm` a case actually got.
///
/// This is the coverage oracle, and it matters as much as the escape oracle. A
/// run where every package is refused at the signature check reports "no
/// escapes" while never once exercising the sandbox, which looks identical to a
/// clean result and is worth nothing. Counting stages makes that visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Rejected before the archive was opened.
    RefusedSignature,
    /// The signature verified, but the archive would not unpack or had no
    /// usable `metadata`.
    RefusedArchive,
    /// The archive unpacked, but no entrypoint resolved inside the package.
    RefusedEntrypoint,
    /// A binary actually ran inside the sandbox. Only these test confinement.
    Executed,
    /// Could not tell.
    Unknown,
}

impl Stage {
    const fn label(self) -> &'static str {
        match self {
            Self::RefusedSignature => "refused-signature",
            Self::RefusedArchive => "refused-archive",
            Self::RefusedEntrypoint => "refused-entrypoint",
            Self::Executed => "executed",
            Self::Unknown => "unknown",
        }
    }

    /// Classify from what `pm` printed. Order matters: the success line
    /// "signature verified" contains the word "signature", so the specific
    /// checks have to come before the general ones.
    fn classify(output: &str) -> Self {
        if output.contains("exited with code") {
            Self::Executed
        } else if output.contains("does not check out") || output.contains("no signature") {
            Self::RefusedSignature
        } else if output.contains("not resolve inside")
            || output.contains("must be a plain")
            || output.contains("no binary entrypoints")
        {
            Self::RefusedEntrypoint
        } else if output.contains("tar failed")
            || output.contains("is not a pm package")
            || output.contains("cannot parse the metadata")
        {
            Self::RefusedArchive
        } else {
            Self::Unknown
        }
    }
}

/// The one entrypoint that really exists in a generated package tree.
const VALID_ENTRYPOINT: &str = "bin/payload";

/// The entrypoint shapes a package can declare, mixing plausible paths with
/// every traversal trick worth trying.
fn entrypoint_shapes(depth: usize, pad: usize) -> Vec<String> {
    let climb = "../".repeat(depth.clamp(1, 8));
    vec![
        "usr/bin/tool".to_owned(),
        "bin/payload".to_owned(),
        format!("{climb}bin/echo"),
        format!("{climb}etc/passwd"),
        format!("sub/{climb}bin/sh"),
        "/bin/echo".to_owned(),
        "/etc/shadow".to_owned(),
        "./bin/payload".to_owned(),
        "./././bin/payload".to_owned(),
        format!("{}/tool", "a".repeat(pad.clamp(1, 240))),
        "bin/../../escape".to_owned(),
        String::new(),
        ".".to_owned(),
        "..".to_owned(),
        "link-to-host".to_owned(),
    ]
}

/// The axes of one case, derived structurally from a byte stream.
///
/// Deriving [`Arbitrary`] rather than drawing from a hand-rolled PRNG is what
/// keeps the distribution honest. The first version of this fuzzer picked each
/// axis with its own modulo and, across twelve iterations, never once produced a
/// validly signed package: every case died at the signature check and the run
/// reported "no escapes" without having exercised the sandbox at all. Letting
/// `arbitrary` do the choosing also means these shapes can be fed straight to
/// `cargo-fuzz` or AFL later without changing the generator.
#[derive(Debug, Arbitrary)]
struct RawShape {
    /// Weight bytes, not the enums directly. See [`weighted_layout`].
    layout_weight: u8,
    signature_weight: u8,
    entrypoint_indices: [u8; 3],
    entrypoint_count: u8,
    bin_from_metadata: bool,
    /// Declare the entrypoint that actually exists alongside the hostile ones.
    include_valid_entrypoint: bool,
    /// Point `--bin` at the real entrypoint rather than a hostile one.
    aim_at_valid: bool,
    hostile_payload: bool,
    network: bool,
    depth: u8,
    pad: u8,
}

/// Pick a signature state, heavily biased toward one that actually verifies.
///
/// Four of the five states are invalid by construction, so choosing uniformly
/// means four in five packages die at the signature check without ever touching
/// the sandbox. Measured on an unweighted run: 168 of 200 cases refused at the
/// signature, and only 2 reached a sandbox at all. The invalid states still
/// matter - they are what proves verification rejects them - but they must not
/// crowd out the cases that test confinement.
const fn weighted_signature(weight: u8) -> SigState {
    match weight {
        0..=152 => SigState::Valid,       // 60%
        153..=178 => SigState::Absent,    // 10%
        179..=204 => SigState::Malformed, // 10%
        205..=229 => SigState::Untrusted, // 10%
        _ => SigState::Stale,             // 10%
    }
}

/// Pick an archive layout, biased toward one that unpacks.
///
/// Same reasoning as [`weighted_signature`]: a malformed archive is rejected
/// before the sandbox exists, so an even spread would spend most of the run
/// re-testing `tar` instead of confinement.
const fn weighted_layout(weight: u8) -> Layout {
    match weight {
        0..=139 => Layout::Ordinary, // 55%
        140..=156 => Layout::Traversal,
        157..=173 => Layout::Symlink,
        174..=190 => Layout::AbsoluteMember,
        191..=207 => Layout::MetadataDirectory,
        208..=221 => Layout::NoMetadata,
        222..=235 => Layout::Garbage,
        236..=245 => Layout::Truncated,
        _ => Layout::Empty,
    }
}

fn generate(bytes: &[u8], iteration: u64) -> Shape {
    let mut u = Unstructured::new(bytes);
    // A short or exhausted buffer still yields a usable value; `arbitrary`
    // fills the remainder with defaults rather than failing, and a default
    // shape is a perfectly good case to run.
    let raw = RawShape::arbitrary(&mut u).unwrap_or(RawShape {
        layout_weight: 0,
        signature_weight: 0,
        entrypoint_indices: [0, 1, 2],
        entrypoint_count: 1,
        bin_from_metadata: true,
        include_valid_entrypoint: true,
        aim_at_valid: true,
        hostile_payload: true,
        network: false,
        depth: 3,
        pad: 8,
    });

    let shapes = entrypoint_shapes(raw.depth as usize, raw.pad as usize);
    let count = 1 + usize::from(raw.entrypoint_count) % 3;
    let mut entrypoints: Vec<String> = raw
        .entrypoint_indices
        .iter()
        .take(count)
        .map(|index| shapes[usize::from(*index) % shapes.len()].clone())
        .collect();

    // Most of the time, ALSO declare the entrypoint that really exists. A
    // package whose every entrypoint is hostile is rejected outright and never
    // reaches the sandbox, so a run made only of those tests path validation
    // over and over and confinement not at all. Mixing a real entrypoint in
    // with the hostile ones is both better coverage and the more interesting
    // question: given a package that legitimately runs, can a hostile
    // entrypoint declared beside it still be reached?
    if raw.include_valid_entrypoint {
        entrypoints.push(VALID_ENTRYPOINT.to_owned());
    }

    let bin = if raw.bin_from_metadata {
        // Sometimes ask for the real one, sometimes for whatever hostile shape
        // came first.
        if raw.aim_at_valid {
            Some(VALID_ENTRYPOINT.to_owned())
        } else {
            entrypoints.first().cloned()
        }
    } else {
        None
    };

    Shape {
        iteration,
        layout: weighted_layout(raw.layout_weight),
        signature: weighted_signature(raw.signature_weight),
        entrypoints,
        bin,
        hostile_payload: raw.hostile_payload,
        network: raw.network,
    }
}

/// A payload that tries every cheap way out of the jail. It writes a marker it
/// *is* allowed to write first, so a test can tell "the payload ran and was
/// contained" apart from "the payload never ran".
fn hostile_script(canary: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         echo ran > /tmp/pm-fuzz-ran 2>/dev/null\n\
         echo pwned > '{canary}' 2>/dev/null\n\
         echo pwned > /etc/pm-fuzz 2>/dev/null\n\
         echo pwned > /usr/pm-fuzz 2>/dev/null\n\
         echo pwned > \"$HOME/pm-fuzz\" 2>/dev/null\n\
         cat /etc/shadow 2>/dev/null\n\
         ls /home 2>/dev/null\n\
         ls /root 2>/dev/null\n\
         exit 0\n",
        canary = canary.display()
    )
}

/// The metadata YAML for a shape.
fn metadata_yaml(shape: &Shape) -> String {
    let entries = shape
        .entrypoints
        .iter()
        .map(|path| format!("  {path:?}: Binary\n"))
        .collect::<String>();
    format!(
        "name: fuzz{}\nversion:\n- '1'\ndependencies: []\nentrypoints:\n{}",
        shape.iteration,
        if entries.is_empty() {
            "  {}\n".to_owned()
        } else {
            entries
        }
    )
}

/// Build the package tree and tar it up. Returns the archive path.
fn build_archive(shape: &Shape, work: &Path, canary: &Path) -> miette::Result<PathBuf> {
    let tree = work.join("tree");
    create_dir_all(tree.join("deps")).into_diagnostic()?;
    create_dir_all(tree.join("bin")).into_diagnostic()?;

    let payload = if shape.hostile_payload {
        hostile_script(canary)
    } else {
        "#!/bin/sh\nexit 0\n".to_owned()
    };
    write(tree.join("bin/payload"), payload).into_diagnostic()?;
    make_executable(&tree.join("bin/payload"))?;

    match shape.layout {
        Layout::NoMetadata | Layout::Empty => {}
        Layout::MetadataDirectory => {
            create_dir_all(tree.join("metadata")).into_diagnostic()?;
        }
        _ => {
            write(tree.join("metadata"), metadata_yaml(shape)).into_diagnostic()?;
        }
    }

    if shape.layout == Layout::Symlink {
        // A symlink aimed at the host. Extraction must not follow it, and the
        // entrypoint check must not resolve through it.
        let link = tree.join("link-to-host");
        let _ = std::os::unix::fs::symlink("/etc", &link);
    }

    let archive = work.join(format!("fuzz{}-1.cpkg", shape.iteration));

    match shape.layout {
        Layout::Garbage => {
            let mut rng = Rng::new(shape.iteration.wrapping_mul(0x5DEE_CE66));
            let bytes: Vec<u8> = (0..4096).map(|_| (rng.below(256)) as u8).collect();
            write(&archive, bytes).into_diagnostic()?;
            return Ok(archive);
        }
        Layout::Empty => {
            run_tar(&["-cJf", &archive.to_string_lossy(), "-T", "/dev/null"])?;
            return Ok(archive);
        }
        _ => {}
    }

    let tree_str = tree.to_string_lossy().to_string();
    let archive_str = archive.to_string_lossy().to_string();
    let mut args: Vec<String> = vec![
        "-cJf".into(),
        archive_str.clone(),
        "-C".into(),
        tree_str,
        ".".into(),
    ];

    if shape.layout == Layout::Traversal {
        args.push("--transform".into());
        args.push("s|^\\./bin/payload|../../escaped-payload|".into());
    } else if shape.layout == Layout::AbsoluteMember {
        args.push("--transform".into());
        args.push("s|^\\./bin/payload|/etc/pm-fuzz-absolute|".into());
    }

    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    // tar refuses `..` members outright and exits non-zero; that refusal is the
    // case working, not a failure to build it.
    let _ = run_tar(&borrowed);

    if shape.layout == Layout::Truncated && archive.is_file() {
        let bytes = std::fs::read(&archive).into_diagnostic()?;
        write(&archive, &bytes[..bytes.len() / 2]).into_diagnostic()?;
    }

    Ok(archive)
}

fn make_executable(path: &Path) -> miette::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).into_diagnostic()?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).into_diagnostic()
}

fn run_tar(args: &[&str]) -> miette::Result<()> {
    let output = Command::new("tar")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .into_diagnostic()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(miette!(
            "tar {:?} failed with {}: {}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Attach the signature state to an archive.
fn apply_signature(
    shape: &Shape,
    pm: &Path,
    archive: &Path,
    trusted_cfg: &Path,
    untrusted_cfg: &Path,
) -> miette::Result<()> {
    let sig = PathBuf::from(format!("{}.sig", archive.display()));
    match shape.signature {
        SigState::Absent => Ok(()),
        SigState::Malformed => write(&sig, b"not a signature at all\n").into_diagnostic(),
        SigState::Valid => sign_with(pm, archive, trusted_cfg),
        SigState::Untrusted => sign_with(pm, archive, untrusted_cfg),
        SigState::Stale => {
            // Sign the real bytes, then change them, so the signature is
            // genuine and trusted but no longer describes the archive.
            sign_with(pm, archive, trusted_cfg)?;
            let mut bytes = std::fs::read(archive).into_diagnostic()?;
            bytes.push(0);
            write(archive, bytes).into_diagnostic()
        }
    }
}

fn sign_with(pm: &Path, archive: &Path, cfg: &Path) -> miette::Result<()> {
    let output = Command::new(pm)
        .arg("sign")
        .arg(archive)
        .env("XDG_CONFIG_HOME", cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .into_diagnostic()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(miette!("pm sign failed with {}", output.status))
    }
}

/// Files planted outside the workspace. If any of them changes, something got
/// out.
struct Canaries {
    dir: PathBuf,
    files: Vec<PathBuf>,
}

impl Canaries {
    const CONTENT: &'static [u8] = b"canary: this file must never change\n";

    fn plant(dir: &Path) -> miette::Result<Self> {
        create_dir_all(dir).into_diagnostic()?;
        let files: Vec<PathBuf> = ["escaped-payload", "canary-a", "canary-b"]
            .iter()
            .map(|name| dir.join(name))
            .collect();
        for file in &files {
            write(file, Self::CONTENT).into_diagnostic()?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            files,
        })
    }

    /// Returns the canaries that were modified, removed, or newly created.
    fn violations(&self) -> Vec<PathBuf> {
        let mut hit: Vec<PathBuf> = self
            .files
            .iter()
            .filter(|file| match std::fs::read(file) {
                Ok(bytes) => bytes != Self::CONTENT,
                // A canary that vanished is as bad as one that changed.
                Err(_) => true,
            })
            .cloned()
            .collect();

        // Anything NEW in the canary directory means a write landed where it
        // should not have.
        if let Ok(entries) = read_dir(&self.dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !self.files.contains(&path) {
                    hit.push(path);
                }
            }
        }
        hit
    }
}

/// Run `pm` and classify what happened.
fn run_case(shape: &Shape, pm: &Path, archive: &Path, cfg: &Path) -> (Outcome, Stage, String) {
    let mut command = Command::new(pm);
    command
        .arg("run")
        .arg(archive)
        .env("XDG_CONFIG_HOME", cfg)
        // No terminal, so the interactive prompt must refuse rather than hang.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(bin) = &shape.bin {
        command.arg("--bin").arg(bin);
    }
    if shape.network {
        command.arg("--network");
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return (
                Outcome::Skipped,
                Stage::Unknown,
                format!("could not spawn pm: {error}"),
            );
        }
    };

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut printed = String::new();
                if let Ok(output) = child.wait_with_output() {
                    printed = format!(
                        "{}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                let stage = Stage::classify(&printed);
                let detail = format!("exit {status}; {}", printed.trim());
                // A panic or a fatal signal is a crash in pm, which is a finding
                // regardless of whether anything escaped.
                let crashed = status.code() == Some(PANIC_EXIT) || status.code().is_none();
                return if crashed {
                    (Outcome::Escaped, stage, format!("pm crashed: {detail}"))
                } else {
                    (Outcome::Contained, stage, detail)
                };
            }
            Ok(None) => {
                if started.elapsed() > RUN_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (
                        Outcome::TimedOut,
                        Stage::Unknown,
                        "pm did not terminate".to_owned(),
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                return (
                    Outcome::Skipped,
                    Stage::Unknown,
                    format!("wait failed: {error}"),
                );
            }
        }
    }
}

/// Write everything needed to reproduce a finding.
fn record_finding(
    findings: &Path,
    shape: &Shape,
    stage: Stage,
    seed: u64,
    detail: &str,
    archive: &Path,
) {
    let dir = findings.join(format!("iter-{:06}", shape.iteration));
    if create_dir_all(&dir).is_err() {
        error!("could not create the findings directory");
        return;
    }
    let report = format!(
        "seed: {seed}\niteration: {}\nstage: {}\nlayout: {}\nsignature: {}\nentrypoints: {:?}\n\
         bin: {:?}\nhostile_payload: {}\nnetwork: {}\ndetail: {detail}\n\nreplay:\n  \
         cargo run --release --bin pm-fuzz -- --seed {seed} --iterations {}\n",
        shape.iteration,
        stage.label(),
        shape.layout.label(),
        shape.signature.label(),
        shape.entrypoints,
        shape.bin,
        shape.hostile_payload,
        shape.network,
        shape.iteration + 1,
    );
    let _ = write(dir.join("finding.txt"), report);
    if archive.is_file() {
        let _ = std::fs::copy(archive, dir.join("package.cpkg"));
    }
}

/// One iteration, start to finish.
fn fuzz_one(args: &Args, seed: u64, iteration: u64, root: &Path, pm: &Path) -> (Outcome, Stage) {
    // The PRNG now only produces ENTROPY; `arbitrary` decides the shape. The
    // seed still reproduces a finding exactly, because the byte stream is a
    // pure function of (seed, iteration).
    let mut rng = Rng::new(seed.wrapping_add(iteration.wrapping_mul(0x9E37_79B9)));
    let entropy: Vec<u8> = (0..64).map(|_| rng.below(256) as u8).collect();
    let shape = generate(&entropy, iteration);

    let work = root.join(format!("iter-{iteration:06}"));
    let canary_dir = work.join("canaries");
    let cfg = root.join("trusted-cfg");

    let cleanup = |outcome: Outcome, stage: Stage| {
        if outcome != Outcome::Escaped && !args.keep_failures {
            let _ = remove_dir_all(&work);
        }
        (outcome, stage)
    };

    if create_dir_all(&work).is_err() {
        return (Outcome::Skipped, Stage::Unknown);
    }
    let canaries = match Canaries::plant(&canary_dir) {
        Ok(canaries) => canaries,
        Err(_) => return cleanup(Outcome::Skipped, Stage::Unknown),
    };

    let archive = match build_archive(&shape, &work, &canary_dir.join("canary-a")) {
        Ok(archive) => archive,
        Err(error) => {
            debug!(iteration, "could not build the case: {error}");
            return cleanup(Outcome::Skipped, Stage::Unknown);
        }
    };

    if apply_signature(&shape, pm, &archive, &cfg, &root.join("untrusted-cfg")).is_err() {
        debug!(iteration, "could not apply the signature state");
    }

    let (mut outcome, stage, detail) = run_case(&shape, pm, &archive, &cfg);

    let violations = canaries.violations();
    if !violations.is_empty() {
        outcome = Outcome::Escaped;
        error!(
            iteration,
            layout = shape.layout.label(),
            signature = shape.signature.label(),
            "ESCAPE: canaries touched: {violations:?}"
        );
    }

    if outcome == Outcome::Escaped {
        error!(
            iteration,
            seed,
            layout = shape.layout.label(),
            signature = shape.signature.label(),
            "ESCAPE: {detail}"
        );
        record_finding(
            &root.join("findings"),
            &shape,
            stage,
            seed,
            &detail,
            &archive,
        );
    } else {
        debug!(
            iteration,
            layout = shape.layout.label(),
            signature = shape.signature.label(),
            "contained: {detail}"
        );
    }

    cleanup(outcome, stage)
}

/// Create the trusted and untrusted signing configs once, up front.
fn prepare_configs(root: &Path, pm: &Path) -> miette::Result<()> {
    for name in ["trusted-cfg", "untrusted-cfg"] {
        let cfg = root.join(name);
        create_dir_all(&cfg).into_diagnostic()?;
        // `pm keygen` creates the key and trusts it locally, which is exactly
        // what both configs need; they differ only in that a package is run
        // against the trusted one.
        let status = Command::new(pm)
            .arg("keygen")
            .env("XDG_CONFIG_HOME", &cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .into_diagnostic()?;
        if !status.success() {
            return Err(miette!("pm keygen failed for {name} with {status}"));
        }
    }
    Ok(())
}

/// Locate the `pm` binary next to this one.
fn find_pm() -> miette::Result<PathBuf> {
    let me = std::env::current_exe().into_diagnostic()?;
    let dir = me
        .parent()
        .ok_or_else(|| miette!("{} has no parent directory", me.display()))?;
    let pm = dir.join("pm");
    if pm.is_file() {
        Ok(pm)
    } else {
        Err(miette!(
            "no `pm` binary next to the fuzzer at {}; build it with `cargo build --bin pm`",
            dir.display()
        ))
    }
}

fn main() -> miette::Result<()> {
    fmt().without_time().init();
    let args = Args::parse();

    let seed = args.seed.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0x1234_5678, |d| d.as_nanos() as u64)
    });

    let pm = find_pm()?;

    let owned_root;
    let root = match &args.root {
        Some(path) => {
            create_dir_all(path).into_diagnostic()?;
            path.clone()
        }
        None => {
            owned_root = tempfile::Builder::new()
                .prefix("pm-fuzz-")
                .tempdir()
                .into_diagnostic()?;
            owned_root.path().to_path_buf()
        }
    };

    info!(seed, iterations = args.iterations, jobs = args.jobs, pm = %pm.display(),
          root = %root.display(), "starting; replay any finding with --seed");

    prepare_configs(&root, &pm)?;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.jobs.max(1))
        .build()
        .into_diagnostic()?;

    let escaped = AtomicU64::new(0);
    let contained = AtomicU64::new(0);
    let timed_out = AtomicU64::new(0);
    let skipped = AtomicU64::new(0);
    let done = AtomicU64::new(0);
    // Coverage, not findings: how far each case got into pm.
    let executed = AtomicU64::new(0);
    let refused_sig = AtomicU64::new(0);
    let refused_archive = AtomicU64::new(0);
    let refused_entry = AtomicU64::new(0);
    let unknown_stage = AtomicU64::new(0);

    // `0` means "until interrupted"; cap it so the loop is still bounded.
    let total = if args.iterations == 0 {
        u64::MAX
    } else {
        args.iterations
    };
    let started = Instant::now();

    pool.install(|| {
        (0..total).into_par_iter().for_each(|iteration| {
            if args.stop_on_first && escaped.load(Ordering::Relaxed) > 0 {
                return;
            }
            let (outcome, stage) = fuzz_one(&args, seed, iteration, &root, &pm);
            match outcome {
                Outcome::Escaped => {
                    escaped.fetch_add(1, Ordering::Relaxed);
                }
                Outcome::Contained => {
                    contained.fetch_add(1, Ordering::Relaxed);
                }
                Outcome::TimedOut => {
                    timed_out.fetch_add(1, Ordering::Relaxed);
                }
                Outcome::Skipped => {
                    skipped.fetch_add(1, Ordering::Relaxed);
                }
            }
            match stage {
                Stage::Executed => executed.fetch_add(1, Ordering::Relaxed),
                Stage::RefusedSignature => refused_sig.fetch_add(1, Ordering::Relaxed),
                Stage::RefusedArchive => refused_archive.fetch_add(1, Ordering::Relaxed),
                Stage::RefusedEntrypoint => refused_entry.fetch_add(1, Ordering::Relaxed),
                Stage::Unknown => unknown_stage.fetch_add(1, Ordering::Relaxed),
            };
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(50) {
                info!(
                    done = n,
                    contained = contained.load(Ordering::Relaxed),
                    escaped = escaped.load(Ordering::Relaxed),
                    timed_out = timed_out.load(Ordering::Relaxed),
                    skipped = skipped.load(Ordering::Relaxed),
                    "progress"
                );
            }
        });
    });

    let escapes = escaped.load(Ordering::Relaxed);
    let timeouts = timed_out.load(Ordering::Relaxed);
    let reached_sandbox = executed.load(Ordering::Relaxed);

    info!(
        executed = reached_sandbox,
        refused_signature = refused_sig.load(Ordering::Relaxed),
        refused_archive = refused_archive.load(Ordering::Relaxed),
        refused_entrypoint = refused_entry.load(Ordering::Relaxed),
        unknown = unknown_stage.load(Ordering::Relaxed),
        "coverage: how far each package got"
    );
    info!(
        seed,
        elapsed = ?started.elapsed(),
        contained = contained.load(Ordering::Relaxed),
        escaped = escapes,
        timed_out = timeouts,
        skipped = skipped.load(Ordering::Relaxed),
        "finished"
    );

    if escapes > 0 {
        warn!(
            "{escapes} escape(s); reproducers in {}",
            root.join("findings").display()
        );
        return Err(miette!(
            "{escapes} package(s) escaped the sandbox; replay with --seed {seed}"
        ));
    }
    if timeouts > 0 {
        warn!(
            "{timeouts} run(s) had to be killed; that is worth a look even though nothing escaped"
        );
    }
    if reached_sandbox == 0 {
        // The escape oracle only means something for packages that ran. Saying
        // "no escapes" when nothing reached the sandbox would be a lie of
        // omission, and it is exactly how a fuzzer quietly stops testing
        // anything.
        return Err(miette!(
            "no package reached the sandbox, so confinement was never exercised: every case \
             was refused earlier. This is a FUZZER defect, not a clean result - check the \
             coverage line above and fix the generator."
        ));
    }
    info!(
        executed = reached_sandbox,
        "no escapes found; the sandbox held for every package that reached it"
    );
    Ok(())
}
