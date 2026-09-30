//! Node.js and its package managers.
//!
//! No grammar: pm has no JavaScript scanner, and a plugin that claims `.js` without
//! reading it well would do more harm than none.

use super::{Builtin, FETCHING_TOOLCHAIN};
use crate::policy::Fingerprint;

pub(super) static PLUGIN: Builtin = Builtin {
    name: "node",
    summary: "npm, yarn, pnpm, npx and node",
    fingerprints: FINGERPRINTS,
    languages: &[],
};

static FINGERPRINTS: &[Fingerprint] = &[Fingerprint {
    name: "node",
    pattern: program!(r"npm|yarn|pnpm|npx|node"),
    capabilities: &FETCHING_TOOLCHAIN,
}];
