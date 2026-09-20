//! Behavioural tests for the iterator accessors on [`BuildFile`].

use std::path::Path;

use pm::bf::BuildFile;
use serde_yaml::{from_str, to_string};

#[test]
fn generate_declares_no_dependencies() {
    let config = BuildFile::generate();

    // The generated example used to declare `/tmp` as a dependency. A
    // dependency path now has to name either a build file or a `.cpkg`, and a
    // missing one is a hard error rather than a silent skip, so that
    // placeholder would make the example fail to build the moment anyone ran
    // it.
    assert_eq!(config.dependencies().len(), 0);
    assert!(config.dependencies().next().is_none());
}

#[test]
fn dependencies_reports_its_length_up_front() {
    let yaml = "
name: sized
version: ['1']
dependencies:
  - /pkg/zlib
  - /pkg/atk
steps: []
";
    let config: BuildFile = from_str(yaml).expect("the fixture is valid yaml");

    // `ExactSizeIterator` is what lets a caller size a buffer before iterating,
    // which is the capability a `&[PathBuf]` return used to provide.
    assert_eq!(config.dependencies().len(), 2);
    assert_eq!(config.dependencies().count(), 2);
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
    let config: BuildFile = from_str(yaml).expect("the fixture is valid yaml");

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
    let config: BuildFile = from_str(yaml).expect("the fixture is valid yaml");

    assert_eq!(config.name(), "leaf");
    assert_eq!(config.dependencies().len(), 0);
    assert!(config.dependencies().next().is_none());
}

#[test]
fn dependencies_survive_a_yaml_round_trip() {
    let original = BuildFile::generate();
    let yaml = to_string(&original).expect("a generated config is serializable");
    let reloaded: BuildFile = from_str(&yaml).expect("what we just wrote must parse back");

    assert_eq!(reloaded.name(), original.name());
    assert_eq!(
        reloaded.dependencies().collect::<Vec<_>>(),
        original.dependencies().collect::<Vec<_>>()
    );
}
