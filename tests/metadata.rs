//! Integration tests for [`pm::metadata::Metadata`]: file classification and
//! the YAML representation that ends up inside every archive.

use std::collections::HashMap;
use std::fs::{create_dir, write};
use std::path::{Path, PathBuf};

use pm::metadata::{LibraryType, Metadata, Type};
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
    );

    let yaml = to_string(&metadata).expect("metadata must serialise");
    let parsed: Metadata = from_str(&yaml).expect("metadata must parse back");

    assert_eq!(parsed.name(), "demo");
    let version: Vec<&str> = parsed.version().iter().map(String::as_str).collect();
    assert_eq!(version, ["0", "1", "0"]);
    let deps: Vec<&Path> = parsed.dependencies().iter().map(PathBuf::as_path).collect();
    assert_eq!(deps, [Path::new("deps/other.cpkg")]);
    assert_eq!(parsed.entrypoints(), &entrypoints);
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
    );

    assert_eq!(metadata.name(), "nowhere");
    assert_eq!(metadata.version().len(), 1);
    assert_eq!(metadata.dependencies().len(), 1);
    assert_eq!(metadata.entrypoints(), &entrypoints);
}

#[test]
fn metadata_with_no_entrypoints_round_trips() {
    let metadata = Metadata::create("bare".into(), vec!["1".into()], Vec::new(), HashMap::new());

    let yaml = to_string(&metadata).expect("serialise");
    let parsed: Metadata = from_str(&yaml).expect("parse back");

    assert_eq!(parsed.name(), "bare");
    assert!(parsed.dependencies().is_empty());
    assert!(parsed.entrypoints().is_empty());
}

#[test]
fn a_binary_entrypoint_is_distinguishable_from_a_library_after_a_round_trip() {
    // Pins the enum representation: a `Type::Binary` must not deserialise into
    // a library variant, otherwise the runner would offer libraries to run.
    let mut entrypoints = HashMap::new();
    entrypoints.insert(PathBuf::from("bin/tool"), Type::Binary);
    let metadata = Metadata::create("pin".into(), vec!["0".into()], Vec::new(), entrypoints);

    let parsed: Metadata = from_str(&to_string(&metadata).expect("serialise")).expect("parse back");

    let binaries: Vec<&PathBuf> = parsed
        .entrypoints()
        .iter()
        .filter(|(_, ty)| **ty == Type::Binary)
        .map(|(path, _)| path)
        .collect();
    assert_eq!(binaries, [&PathBuf::from("bin/tool")]);
}
