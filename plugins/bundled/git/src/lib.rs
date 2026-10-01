//! Version control.

use bundled::{Capability, Fingerprint, Table};

/// The fingerprints, in precedence order.
static FINGERPRINTS: Table = Table::new(&[Fingerprint {
    name: "git",
    // Cloning and fetching are the point of invoking git in a build.
    pattern: bundled::program!(r"git"),
    capabilities: &[
        Capability::VersionControl,
        Capability::Network,
        Capability::Coreutils,
    ],
}]);

bundled::plugin! {
    name: "git",
    summary: "git, which a build invokes to clone and fetch",
    commands: &FINGERPRINTS,
    sources: &bundled::NoSources,
}
