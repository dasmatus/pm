//! Behavioural tests for the iterator accessors on [`ConfigFile`].

use std::path::Path;

use pm::bf::ConfigFile;
use serde_yaml::{from_str, to_string};

#[test]
fn generate_declares_a_single_dependency() {
    let config = ConfigFile::generate();

    assert_eq!(
        config.dependencies().collect::<Vec<_>>(),
        [Path::new("/tmp")]
    );
}

#[test]
fn dependencies_reports_its_length_up_front() {
    let config = ConfigFile::generate();

    // `ExactSizeIterator` is what lets a caller size a buffer before iterating,
    // which is the capability a `&[PathBuf]` return used to provide.
    assert_eq!(config.dependencies().len(), 1);
    assert_eq!(config.dependencies().count(), 1);
}

#[test]
fn dependencies_preserve_declaration_order() {
    let yaml = "
name: ordered
version: ['1', '0', '0']
dependencies:
  - /pkg/zlib
  - /pkg/atk
  - /pkg/brotli
steps: []
";
    let config: ConfigFile = from_str(yaml).expect("the fixture is valid yaml");

    assert_eq!(
        config.dependencies().collect::<Vec<_>>(),
        [
            Path::new("/pkg/zlib"),
            Path::new("/pkg/atk"),
            Path::new("/pkg/brotli"),
        ],
        "the accessor must not reorder what the build file declared"
    );
    assert_eq!(config.dependencies().len(), 3);
}

#[test]
fn an_empty_dependency_list_yields_nothing() {
    let yaml = "
name: leaf
version: ['0', '1', '0']
dependencies: []
steps: []
";
    let config: ConfigFile = from_str(yaml).expect("the fixture is valid yaml");

    assert_eq!(config.name(), "leaf");
    assert_eq!(config.dependencies().len(), 0);
    assert!(config.dependencies().next().is_none());
}

#[test]
fn dependencies_survive_a_yaml_round_trip() {
    let original = ConfigFile::generate();
    let yaml = to_string(&original).expect("a generated config is serializable");
    let reloaded: ConfigFile = from_str(&yaml).expect("what we just wrote must parse back");

    assert_eq!(reloaded.name(), original.name());
    assert_eq!(
        reloaded.dependencies().collect::<Vec<_>>(),
        original.dependencies().collect::<Vec<_>>()
    );
}
