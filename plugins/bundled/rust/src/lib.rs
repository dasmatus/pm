//! Cargo and rustc. The Rust grammar is `rust-source`.

use bundled::{Fingerprint, Table};

/// The fingerprints, in precedence order.
static FINGERPRINTS: Table = Table::new(&[Fingerprint {
    name: "cargo",
    // Cargo resolves and downloads the dependency graph itself.
    pattern: bundled::program!(r"cargo|rustc"),
    capabilities: &bundled::FETCHING_TOOLCHAIN,
}]);

bundled::plugin! {
    name: "rust",
    summary: "cargo and rustc",
    commands: &FINGERPRINTS,
    sources: &bundled::NoSources,
}
