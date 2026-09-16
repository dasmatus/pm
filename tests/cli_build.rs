//! Behavioural tests for the two flags on `pm build`.
//!
//! Both flags are escape hatches, and an escape hatch that silently does
//! nothing is worse than one that does not exist: it reports success while
//! leaving the caller with the opposite of what they asked for. These tests go
//! through the real binary rather than through [`pm::bf::BuildFile`], because
//! the library side already honoured both options - it was the CLI seam that
//! dropped them, and only an end-to-end run can catch that.
//!
//! Each test asserts BOTH directions. A `--permissive` test that only checks
//! the permissive build would still pass if strictness were removed
//! altogether, and an `--unsandboxed` test that only checks the unsandboxed
//! build would still pass if the jail were disabled everywhere.

use std::fs::write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use pm::signing::{SigningKey, TrustStore, sign_file};
use tempfile::tempdir;

/// Writes `yaml` to `<work>/build.yaml`, signs it and trusts the key.
///
/// `pm build` verifies the detached signature before it parses anything, so an
/// unsigned build file never reaches the code under test here.
fn build_file(work: &Path, yaml: &str) -> PathBuf {
    let path = work.join("build.yaml");
    write(&path, yaml).expect("write the build file");

    let key = SigningKey::load_or_create(&config_dir(work).join("pm").join("signing.key"))
        .expect("create a throwaway signing key");
    sign_file(&path, &key).expect("sign the build file");
    let trusted = config_dir(work).join("pm").join("trusted");
    let mut trust = TrustStore::load(&trusted).expect("load the trust store");
    trust
        .add(&key.public_key_hex(), &trusted)
        .expect("trust the throwaway key");

    path
}

/// Config directory holding the throwaway key and trust store, laid out the way
/// `pm` expects under `$XDG_CONFIG_HOME`.
fn config_dir(work: &Path) -> PathBuf {
    work.join("config")
}

/// Runs the `pm` binary from inside `work`.
///
/// The working directory matters: `pm build` writes the finished archive into
/// the directory it was called from, so leaving it at the crate root would
/// litter the repository with `.cpkg` files.
fn pm_build(args: &[&str], work: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(args)
        .current_dir(work)
        .env("XDG_CONFIG_HOME", config_dir(work))
        .stdin(Stdio::null())
        .output()
        .expect("run the pm binary")
}

/// A build file whose single step runs `command`.
fn with_command(command: &str) -> String {
    format!(
        "name: flags\nversion:\n- '0'\ndependencies: []\nsteps:\n- stage: Build\n  dl_urls: \
         null\n  name: only\n  run:\n  - {command}\n"
    )
}

#[test]
fn permissive_builds_a_command_that_matches_no_fingerprint() {
    let work = tempdir().expect("work dir");
    // `basename` is deliberately absent from every pattern in the fingerprint
    // table in src/policy.rs - including the coreutils catch-all - so it
    // classifies as nothing at all, which is exactly what --permissive is for.
    // It is also a real program that exits 0, so the only thing that can fail
    // this build is the classification gate itself.
    let file = build_file(work.path(), &with_command("basename /a/b"));
    let path = file.display().to_string();

    let strict = pm_build(&["build", &path], work.path());
    let stderr = String::from_utf8_lossy(&strict.stderr);
    assert!(
        !strict.status.success(),
        "without --permissive an unclassifiable command must abort the build, but it \
         succeeded:\n{stderr}"
    );

    let permissive = pm_build(&["build", "--permissive", &path], work.path());
    assert!(
        permissive.status.success(),
        "--permissive must let the same build through, got:\n{}",
        String::from_utf8_lossy(&permissive.stderr)
    );
    assert!(
        work.path().join("flags-0.cpkg").is_file(),
        "the permissive build must leave an archive behind"
    );
}

#[test]
fn unsandboxed_runs_the_step_outside_the_jail() {
    let work = tempdir().expect("work dir");
    // The build file's own directory is mounted READ-ONLY inside the jail, so
    // writing into it is precisely the thing confinement forbids and the
    // escape hatch allows. Using that directory rather than some unrelated
    // path keeps the test honest on a machine where the jail cannot start at
    // all: the file is still not created, because nothing ran.
    let escaped = work.path().join("escaped");
    let file = build_file(
        work.path(),
        &with_command(&format!("touch {}", escaped.display())),
    );
    let path = file.display().to_string();

    let jailed = pm_build(&["build", &path], work.path());
    assert!(
        !jailed.status.success(),
        "a build step must not be able to write into its own read-only mount"
    );
    assert!(
        !escaped.exists(),
        "the jailed build created {}, so the mount was not read-only",
        escaped.display()
    );

    let host = pm_build(&["build", "--unsandboxed", &path], work.path());
    assert!(
        host.status.success(),
        "--unsandboxed must run the same step on the host, got:\n{}",
        String::from_utf8_lossy(&host.stderr)
    );
    assert!(
        escaped.exists(),
        "--unsandboxed ran but {} was not created, so the step never left the jail",
        escaped.display()
    );
}
