//! Behavioural tests for build flags and recipe-generator CLI interfaces.
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

#[test]
fn source_path_matches_the_download_api_without_fetching_or_loading_plugins() {
    let work = tempdir().unwrap();
    let url = "https://example.invalid/source.tar.gz?version=2";
    let relative = pm::step::Step::download_path(&url::Url::parse(url).unwrap()).unwrap();
    for (flags, expected) in [
        (
            vec!["source-path", url],
            Path::new("/build").join(&relative),
        ),
        (vec!["source-path", "--relative", url], relative),
    ] {
        let output = pm_build(&flags, work.path());
        assert!(output.status.success(), "{:?}", output);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{}\n", expected.display())
        );
    }
    assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);
}

#[test]
fn source_path_rejects_urls_without_a_filename() {
    let work = tempdir().unwrap();
    for url in ["https://example.invalid/", "not-a-url"] {
        let output = pm_build(&["source-path", url], work.path());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn explain_yaml_is_stable_and_contains_policy_and_download_paths() {
    let work = tempdir().unwrap();
    let file = build_file(
        work.path(),
        &format!(
            "name: desktop\nversion: ['1', '2']\ndependencies: []\nsteps:\n\
             - stage: Prepare\n  name: fetch\n  dl_urls:\n\
             \x20   https://example.invalid/z/source.tar.gz: '{}'\n\
             \x20   https://example.invalid/a/source.tar.gz: '{}'\n\
             \x20 run:\n  - tar --version\n  - make --version\n",
            "0".repeat(64),
            "1".repeat(64)
        ),
    );
    let path = file.to_str().unwrap();
    let args = ["--no-plugins", "explain", path, "--format", "yaml"];
    let output = pm_build(&args, work.path());
    assert!(output.status.success(), "{:?}", output);
    let data: serde_yaml::Value = serde_yaml::from_slice(&output.stdout).unwrap();
    assert_eq!(data["schema_version"], 1);
    assert_eq!(data["name"], "desktop");
    assert_eq!(data["version"][0], "1");
    assert_eq!(data["version"][1], "2");
    assert_eq!(data["capabilities"][0], "Toolchain");
    assert!(
        data["capabilities"]
            .as_sequence()
            .unwrap()
            .iter()
            .any(|cap| cap == "Network")
    );
    assert_eq!(data["commands"][0]["command"], "tar --version");
    assert_eq!(data["commands"][0]["matched"], true);
    assert_eq!(data["commands"][1]["fingerprint"], "make");
    assert_eq!(data["plugins"].as_sequence().unwrap().len(), 0);
    assert_eq!(data["symbols"].as_mapping().unwrap().len(), 0);
    let downloads = data["downloads"].as_sequence().unwrap();
    assert_eq!(downloads.len(), 2);
    assert_eq!(
        downloads[0]["url"],
        "https://example.invalid/a/source.tar.gz"
    );
    for download in downloads {
        let url = download["url"].as_str().unwrap();
        let queried = pm_build(&["source-path", url], work.path());
        assert!(queried.status.success());
        assert_eq!(
            download["path"].as_str().unwrap(),
            String::from_utf8(queried.stdout).unwrap().trim()
        );
        assert_eq!(download["step"], "fetch");
    }
    assert_eq!(output.stdout, pm_build(&args, work.path()).stdout);

    let text = pm_build(&["--no-plugins", "explain", path], work.path());
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("grants:"));
    assert!(text.contains(data["fingerprint"].as_str().unwrap()));
}

#[test]
fn explain_yaml_keeps_unmatched_commands_and_failure_status() {
    let work = tempdir().unwrap();
    let file = build_file(work.path(), &with_command("unrecognised-build-tool"));
    let args = [
        "--no-plugins",
        "explain",
        file.to_str().unwrap(),
        "--format",
        "yaml",
    ];
    let strict = pm_build(&args, work.path());
    assert!(!strict.status.success());
    assert!(strict.stdout.is_empty());

    let mut permissive = args.to_vec();
    permissive.push("--permissive");
    let output = pm_build(&permissive, work.path());
    assert!(!output.status.success());
    let data: serde_yaml::Value = serde_yaml::from_slice(&output.stdout).unwrap();
    assert_eq!(data["commands"][0]["matched"], false);
    assert_eq!(data["commands"][0]["fingerprint"], "<unmatched>");
    assert!(data["capabilities"].as_sequence().unwrap().is_empty());
}

#[test]
fn explain_yaml_handles_empty_recipes_and_still_requires_a_trusted_signature() {
    let work = tempdir().unwrap();
    let file = build_file(
        work.path(),
        "name: empty\nversion: ['0']\ndependencies: []\nsteps: []\n",
    );
    let args = [
        "--no-plugins",
        "explain",
        file.to_str().unwrap(),
        "--format",
        "yaml",
    ];
    let output = pm_build(&args, work.path());
    assert!(output.status.success(), "{:?}", output);
    let data: serde_yaml::Value = serde_yaml::from_slice(&output.stdout).unwrap();
    assert!(data["commands"].as_sequence().unwrap().is_empty());
    assert!(data["downloads"].as_sequence().unwrap().is_empty());
    write(&file, "name: tampered\n").unwrap();
    let rejected = pm_build(&args, work.path());
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
}
