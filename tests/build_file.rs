//! Integration tests for [`pm::bf::BuildFile`]: serialisation round-trips,
//! loading from disk, and version formatting.

use std::ffi::OsStr;
use std::fs::{read_to_string, write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use pm::bf::BuildFile;
use serde_yaml::{from_str, to_string};
use tempfile::{TempDir, tempdir};

/// Writes `yaml` into a fresh temporary directory and hands back both the
/// directory guard (keep it alive for the duration of the test) and the path.
fn build_file_with(yaml: &str) -> (TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("temporary directory");
    let path = dir.path().join("build.yaml");
    write(&path, yaml).expect("write the build file");
    (dir, path)
}

#[test]
fn generate_round_trips_through_yaml() {
    let generated = BuildFile::generate();
    let yaml = to_string(&generated).expect("the generated build file must serialise");
    assert!(
        !yaml.trim().is_empty(),
        "a generated build file must not serialise to nothing"
    );

    let parsed: BuildFile = from_str(&yaml).expect("the generated YAML must parse back");

    assert_eq!(parsed.name(), generated.name());
    assert_eq!(parsed.version(), generated.version());
    assert_eq!(
        parsed.dependencies().collect::<Vec<_>>(),
        generated.dependencies().collect::<Vec<_>>()
    );
    assert_eq!(parsed.version_string(), generated.version_string());
}

#[test]
fn generate_produces_a_file_that_load_accepts() {
    let generated = BuildFile::generate();
    let yaml = to_string(&generated).expect("serialise");
    let (_dir, path) = build_file_with(&yaml);

    let loaded =
        BuildFile::load_unverified(&path).expect("a generated build file must load from disk");

    assert_eq!(loaded.name(), generated.name());
    assert_eq!(loaded.version(), generated.version());
    assert_eq!(loaded.version_string(), generated.version_string());
}

#[test]
fn load_of_a_missing_path_is_an_error_not_a_panic() {
    let dir = tempdir().expect("temporary directory");
    let missing = dir.path().join("does-not-exist.yaml");
    assert!(!missing.exists());

    assert!(
        BuildFile::load_unverified(&missing).is_err(),
        "loading a nonexistent build file must return a diagnostic"
    );
}

#[test]
fn load_of_a_directory_is_an_error_not_a_panic() {
    let dir = tempdir().expect("temporary directory");

    assert!(
        BuildFile::load_unverified(dir.path()).is_err(),
        "loading a directory as a build file must return a diagnostic"
    );
}

#[test]
fn load_of_malformed_yaml_is_an_error() {
    // Unterminated flow sequence: not valid YAML at all.
    let (_dir, path) = build_file_with("name: [1, 2\nversion: {\n");

    assert!(
        BuildFile::load_unverified(&path).is_err(),
        "syntactically broken YAML must return a diagnostic"
    );
}

#[test]
fn load_of_valid_yaml_with_the_wrong_shape_is_an_error() {
    // Parses as YAML, but it is a sequence rather than a build file mapping.
    let (_dir, path) = build_file_with("- just\n- a\n- list\n");

    assert!(
        BuildFile::load_unverified(&path).is_err(),
        "well-formed YAML of the wrong shape must return a diagnostic"
    );
}

#[test]
fn load_of_a_build_file_missing_required_fields_is_an_error() {
    let (_dir, path) = build_file_with("name: nameonly\n");

    assert!(
        BuildFile::load_unverified(&path).is_err(),
        "a build file without a version must return a diagnostic"
    );
}

#[test]
fn version_string_joins_components_with_dots() {
    let (_dir, path) = build_file_with(
        "name: multi\nversion:\n  - '1'\n  - '22'\n  - '333'\ndependencies: []\nsteps: []\n",
    );
    let loaded = BuildFile::load_unverified(&path).expect("load");

    let components: Vec<&str> = loaded.version().iter().map(String::as_str).collect();
    assert_eq!(components, ["1", "22", "333"]);
    assert_eq!(loaded.version_string(), "1.22.333");
}

#[test]
fn version_string_of_a_single_component_has_no_separator() {
    let (_dir, path) =
        build_file_with("name: single\nversion:\n  - '7'\ndependencies: []\nsteps: []\n");
    let loaded = BuildFile::load_unverified(&path).expect("load");

    assert_eq!(loaded.version_string(), "7");
}

#[test]
fn version_string_of_an_empty_version_is_empty() {
    let (_dir, path) = build_file_with("name: empty\nversion: []\ndependencies: []\nsteps: []\n");
    let loaded = BuildFile::load_unverified(&path).expect("load");

    assert_eq!(loaded.version_string(), "");
}

#[test]
fn dependencies_are_preserved_across_a_load() {
    let (_dir, path) = build_file_with(
        "name: withdeps\nversion:\n  - '0'\ndependencies:\n  - /tmp/one.yaml\n  - /tmp/two.yaml\nsteps: []\n",
    );
    let loaded = BuildFile::load_unverified(&path).expect("load");

    let deps: Vec<&Path> = loaded.dependencies().collect();
    assert_eq!(
        deps,
        [Path::new("/tmp/one.yaml"), Path::new("/tmp/two.yaml")]
    );
}

/// Runs the `pm` binary cargo just built for this test, with stdin closed so
/// nothing can block waiting for input.
fn pm(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run the pm binary")
}

#[test]
fn generate_writes_a_build_file_that_load_accepts() {
    let dir = tempdir().expect("temporary directory");
    let path = dir.path().join("build.yaml");

    let output = pm(&[OsStr::new("generate"), path.as_os_str()]);

    assert!(
        output.status.success(),
        "pm generate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let generated = BuildFile::load_unverified(&path).expect("the generated file must load");
    assert_eq!(generated.name(), BuildFile::generate().name());
}

#[test]
fn generate_refuses_to_clobber_an_existing_file() {
    let dir = tempdir().expect("temporary directory");
    let path = dir.path().join("build.yaml");

    let first = pm(&[OsStr::new("generate"), path.as_os_str()]);
    assert!(
        first.status.success(),
        "the first generate must succeed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    // Edit the file the way a user would, so clobbering it is destructive.
    let mine = read_to_string(&path).expect("read the generated file") + "# my own notes\n";
    write(&path, &mine).expect("edit the generated file");

    let second = pm(&[OsStr::new("generate"), path.as_os_str()]);

    assert!(
        !second.status.success(),
        "generating over an existing file must fail without --force"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains(&path.display().to_string()),
        "the diagnostic must name the path it refused to write, got: {stderr}"
    );
    assert_eq!(
        read_to_string(&path).expect("read the file back"),
        mine,
        "a refused generate must leave the existing file untouched"
    );
}

#[test]
fn generate_force_replaces_an_existing_file() {
    let dir = tempdir().expect("temporary directory");
    let path = dir.path().join("build.yaml");
    write(
        &path,
        "name: mine\nversion: []\ndependencies: []\nsteps: []\n",
    )
    .expect("write the file that is about to be replaced");

    let forced = pm(&[
        OsStr::new("generate"),
        path.as_os_str(),
        OsStr::new("--force"),
    ]);

    assert!(
        forced.status.success(),
        "--force must overwrite: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let replaced = read_to_string(&path).expect("read the replaced file");
    assert!(
        !replaced.contains("name: mine"),
        "the old contents survived a --force generate: {replaced}"
    );
    let loaded = BuildFile::load_unverified(&path).expect("the replaced file must load");
    assert_eq!(loaded.name(), BuildFile::generate().name());
}
