//! Node.js and its package managers.
//!
//! There is no JavaScript scanner to go with it: a plugin that claims `.js` without
//! reading it well would do more harm than none.

use bundled::{Fingerprint, Table};

/// The fingerprints, in precedence order.
static FINGERPRINTS: Table = Table::new(&[Fingerprint {
    name: "node",
    pattern: bundled::program!(r"npm|yarn|pnpm|npx|node"),
    capabilities: &bundled::FETCHING_TOOLCHAIN,
}]);

bundled::plugin! {
    name: "node",
    summary: "npm, yarn, pnpm, npx and node",
    commands: &FINGERPRINTS,
    sources: &bundled::NoSources,
}
