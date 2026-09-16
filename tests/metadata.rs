//! Integration tests for [`pm::metadata::Metadata`]: file classification and
//! the YAML representation that ends up inside every archive.

use std::collections::HashMap;
use std::fs::{create_dir, write};
use std::path::{Path, PathBuf};

use pm::metadata::{LibraryType, Metadata, Type};
use pm::perms::{Enforcement, Grant, Permission, Permissions, Provenance};
use serde_yaml::{from_str, to_string};
use tempfile::{TempDir, tempdir};

/// Creates a real regular file with the given name and returns it together with
/// the directory guard that owns it.
fn file_named(name: &str) -> (TempDir, PathBuf) {
    let dir = tempdir().expect("temporary directory");
    let path = dir.path().join(name);
    write(&path, b"\x7fELF not really, but a real regular file").expect("write the file");
    (dir, path)
}

#[test]
fn classify_recognises_a_dynamic_library() {
    let (_dir, path) = file_named("libfoo.so");

    assert_eq!(
        Metadata::classify(&path),
        Some(Type::Library(LibraryType::Dynamic))
    );
}

#[test]
fn classify_recognises_a_versioned_soname() {
    // `libfoo.so.1.2.3` has the extension "3" as far as `Path` is concerned;
    // classification has to look at the whole file name.
    let (_dir, path) = file_named("libfoo.so.1.2.3");

    assert_eq!(
        Metadata::classify(&path),
        Some(Type::Library(LibraryType::Dynamic))
    );
}

#[test]
fn classify_recognises_a_single_digit_soname() {
    let (_dir, path) = file_named("libbar.so.1");

    assert_eq!(
        Metadata::classify(&path),
        Some(Type::Library(LibraryType::Dynamic))
    );
}

#[test]
fn classify_recognises_a_static_library() {
    let (_dir, path) = file_named("libfoo.a");

    assert_eq!(
        Metadata::classify(&path),
        Some(Type::Library(LibraryType::Static))
    );
}

#[test]
fn classify_of_an_extensionless_file_is_a_binary() {
    // This is the case that used to panic on `extension().unwrap()`.
    let (_dir, path) = file_named("mytool");

    assert_eq!(Metadata::classify(&path), Some(Type::Binary));
}

#[test]
fn classify_of_a_file_with_an_unrelated_extension_is_a_binary() {
    let (_dir, path) = file_named("data.conf");

    assert_eq!(Metadata::classify(&path), Some(Type::Binary));
}

#[test]
fn classify_of_a_dotfile_is_a_binary() {
    // A leading dot is not an extension, and must not be mistaken for one.
    let (_dir, path) = file_named(".keep");

    assert_eq!(Metadata::classify(&path), Some(Type::Binary));
}

#[test]
fn classify_of_a_directory_is_none() {
    let dir = tempdir().expect("temporary directory");
    let subdir = dir.path().join("usr");
    create_dir(&subdir).expect("create the directory");

    assert_eq!(
        Metadata::classify(&subdir),
        None,
        "a directory is not an entrypoint"
    );
}

#[test]
fn classify_of_a_directory_named_like_a_library_is_none() {
    let dir = tempdir().expect("temporary directory");
    let subdir = dir.path().join("libfoo.so");
    create_dir(&subdir).expect("create the directory");

    assert_eq!(
        Metadata::classify(&subdir),
        None,
        "the file type wins over the name"
    );
}

#[test]
fn classify_of_a_missing_path_is_none() {
    let dir = tempdir().expect("temporary directory");

    assert_eq!(Metadata::classify(&dir.path().join("absent")), None);
}

/// The entrypoint map every metadata test below round-trips.
fn sample_entrypoints() -> HashMap<PathBuf, Type> {
    let mut entrypoints = HashMap::new();
    entrypoints.insert(PathBuf::from("usr/bin/mytool"), Type::Binary);
    entrypoints.insert(
        PathBuf::from("usr/lib/libfoo.so"),
        Type::Library(LibraryType::Dynamic),
    );
    entrypoints.insert(
        PathBuf::from("usr/lib/libbar.a"),
        Type::Library(LibraryType::Static),
    );
    entrypoints
}

#[test]
fn metadata_yaml_round_trip_keeps_the_entrypoint_map_intact() {
    let entrypoints = sample_entrypoints();
    let metadata = Metadata::create(
        "demo".into(),
        vec!["0".into(), "1".into(), "0".into()],
        vec![PathBuf::from("deps/other.cpkg")],
        entrypoints.clone(),
        Permissions::default(),
        Enforcement::Audit,
    );

    let yaml = to_string(&metadata).expect("metadata must serialise");
    let parsed: Metadata = from_str(&yaml).expect("metadata must parse back");

    assert_eq!(parsed.name(), "demo");
    let version: Vec<&str> = parsed.version().iter().map(String::as_str).collect();
    assert_eq!(version, ["0", "1", "0"]);
    let deps: Vec<&Path> = parsed.dependencies().collect();
    assert_eq!(deps, [Path::new("deps/other.cpkg")]);
    assert_eq!(
        parsed
            .entrypoints()
            .map(|(p, t)| (p.to_path_buf(), *t))
            .collect::<HashMap<_, _>>(),
        entrypoints
    );
}

#[test]
fn create_stores_exactly_what_it_is_given_without_touching_the_filesystem() {
    // The paths below do not exist: `create` is infallible and must not walk.
    let entrypoints = sample_entrypoints();
    let metadata = Metadata::create(
        "nowhere".into(),
        vec!["9".into()],
        vec![PathBuf::from("/definitely/not/here.cpkg")],
        entrypoints.clone(),
        Permissions::default(),
        Enforcement::Audit,
    );

    assert_eq!(metadata.name(), "nowhere");
    assert_eq!(metadata.version().len(), 1);
    assert_eq!(metadata.dependencies().len(), 1);
    assert_eq!(
        metadata
            .entrypoints()
            .map(|(p, t)| (p.to_path_buf(), *t))
            .collect::<HashMap<_, _>>(),
        entrypoints
    );
}

#[test]
fn metadata_with_no_entrypoints_round_trips() {
    let metadata = Metadata::create(
        "bare".into(),
        vec!["1".into()],
        Vec::new(),
        HashMap::new(),
        Permissions::default(),
        Enforcement::Audit,
    );

    let yaml = to_string(&metadata).expect("serialise");
    let parsed: Metadata = from_str(&yaml).expect("parse back");

    assert_eq!(parsed.name(), "bare");
    assert_eq!(parsed.dependencies().len(), 0);
    assert_eq!(parsed.entrypoints().len(), 0);
}

#[test]
fn a_binary_entrypoint_is_distinguishable_from_a_library_after_a_round_trip() {
    // Pins the enum representation: a `Type::Binary` must not deserialise into
    // a library variant, otherwise the runner would offer libraries to run.
    let mut entrypoints = HashMap::new();
    entrypoints.insert(PathBuf::from("bin/tool"), Type::Binary);
    let metadata = Metadata::create(
        "pin".into(),
        vec!["0".into()],
        Vec::new(),
        entrypoints,
        Permissions::default(),
        Enforcement::Audit,
    );

    let parsed: Metadata = from_str(&to_string(&metadata).expect("serialise")).expect("parse back");

    let binaries: Vec<&Path> = parsed.binaries().collect();
    assert_eq!(binaries, [&PathBuf::from("bin/tool")]);
}

/// A profile with two grants of different kinds and real evidence, so a round trip
/// has something to lose.
fn sample_permissions() -> Permissions {
    Permissions::from_grants([
        Grant::new(
            Permission::ReadPath(PathBuf::from("/etc/ssl")),
            Provenance::SourceAnalysis,
            ["src/net.c:42: call to SSL_CTX_new"],
        ),
        Grant::new(
            Permission::Network,
            Provenance::RuntimeMonitor,
            ["connect(2) to 127.0.0.1:443"],
        ),
    ])
}

#[test]
fn the_recorded_profile_survives_the_yaml_round_trip_with_its_evidence() {
    let metadata = Metadata::create(
        "profiled".into(),
        vec!["1".into()],
        Vec::new(),
        sample_entrypoints(),
        sample_permissions(),
        Enforcement::Audit,
    );

    let parsed: Metadata = from_str(&to_string(&metadata).expect("serialise")).expect("parse back");

    assert_eq!(parsed.permissions(), &sample_permissions());
    assert!(parsed.permissions().wants_network());
    let reads: Vec<&Path> = parsed.permissions().read_paths().collect();
    assert_eq!(reads, [Path::new("/etc/ssl")]);
    // Evidence is the whole point of recording provenance; losing it in the archive
    // would leave `pm explain` with nothing to explain.
    let evidence: Vec<&str> = parsed
        .permissions()
        .grants()
        .iter()
        .flat_map(|grant| grant.evidence().iter().map(String::as_str))
        .collect();
    assert!(
        evidence.contains(&"src/net.c:42: call to SSL_CTX_new"),
        "evidence was dropped: {evidence:?}"
    );
    assert_eq!(parsed.enforcement(), Enforcement::Audit);
}

#[test]
fn metadata_written_before_profiles_existed_parses_as_audit_with_no_profile() {
    // Verbatim shape of an old `metadata` file: no `permissions`, no `enforcement`,
    // plus the `policy_fingerprint` key `bf` splices in and `Metadata` ignores.
    let legacy = "\
name: legacy
version:
- '0'
- '3'
dependencies: []
entrypoints:
  bin/old: Binary
policy_fingerprint: deadbeef
";

    let parsed: Metadata = from_str(legacy).expect("an old metadata file must still parse");

    assert_eq!(parsed.name(), "legacy");
    let binaries: Vec<&Path> = parsed.binaries().collect();
    assert_eq!(binaries, [Path::new("bin/old")]);
    assert_eq!(
        parsed.recorded_permissions(),
        None,
        "an absent key must read back as no profile, not as an empty one"
    );
    assert!(parsed.permissions().is_empty());
    // The one default that must never drift: enforcing an old package against an
    // empty allow-list would brick every package ever built.
    assert_eq!(parsed.enforcement(), Enforcement::Audit);
    assert!(!parsed.enforcement().denies());
}

#[test]
fn an_empty_recorded_profile_is_distinguishable_from_no_profile_at_all() {
    let recorded = Metadata::create(
        "empty".into(),
        vec!["1".into()],
        Vec::new(),
        HashMap::new(),
        Permissions::default(),
        Enforcement::Audit,
    );

    let yaml = to_string(&recorded).expect("serialise");
    assert!(
        yaml.contains("permissions:"),
        "an empty profile must still be written out: {yaml}"
    );
    let parsed: Metadata = from_str(&yaml).expect("parse back");

    assert_eq!(parsed.recorded_permissions(), Some(&Permissions::default()));
    assert!(parsed.permissions().is_empty());
    // Same allow-list, different fact about the build.
    assert_eq!(parsed.permissions(), recorded.permissions());
}

#[test]
fn a_fresh_profile_audits_and_only_promote_turns_denial_on() {
    let mut metadata = Metadata::create(
        "promotable".into(),
        vec!["2".into()],
        Vec::new(),
        sample_entrypoints(),
        sample_permissions(),
        Enforcement::Audit,
    );
    assert!(!metadata.enforcement().denies());

    metadata.promote();

    assert_eq!(metadata.enforcement(), Enforcement::Enforce);
    assert!(metadata.enforcement().denies());
    // Promotion changes the mode and nothing else; the grants a reviewer approved
    // must be exactly the grants that get enforced.
    assert_eq!(metadata.permissions(), &sample_permissions());

    let parsed: Metadata = from_str(&to_string(&metadata).expect("serialise")).expect("parse back");
    assert_eq!(parsed.enforcement(), Enforcement::Enforce);
    assert_eq!(parsed.permissions(), &sample_permissions());
}

#[test]
fn recording_a_profile_leaves_entrypoint_keys_relative_to_the_package_root() {
    let metadata = Metadata::create(
        "relative".into(),
        vec!["1".into()],
        vec![PathBuf::from("deps/other.cpkg")],
        sample_entrypoints(),
        sample_permissions(),
        Enforcement::Enforce,
    );

    let parsed: Metadata = from_str(&to_string(&metadata).expect("serialise")).expect("parse back");

    for (path, _) in parsed.entrypoints() {
        assert!(
            path.is_relative(),
            "entrypoint key {} must stay relative to the package root",
            path.display()
        );
    }
    for path in parsed.dependencies() {
        assert!(
            path.is_relative(),
            "dependency {} must stay relative",
            path.display()
        );
    }
    // Profile paths are the exception: they name host paths and are absolute on
    // purpose, so recording one must not have been normalised into the package.
    let reads: Vec<&Path> = parsed.permissions().read_paths().collect();
    assert_eq!(reads, [Path::new("/etc/ssl")]);
}
