//! Version control.

use super::Builtin;
use crate::policy::{Capability, Fingerprint};

pub(super) static PLUGIN: Builtin = Builtin {
    name: "git",
    summary: "git, which a build invokes to clone and fetch",
    fingerprints: FINGERPRINTS,
    languages: &[],
};

static FINGERPRINTS: &[Fingerprint] = &[Fingerprint {
    name: "git",
    // Cloning and fetching are the point of invoking git in a build.
    pattern: program!(r"git"),
    capabilities: &[
        Capability::VersionControl,
        Capability::Network,
        Capability::Coreutils,
    ],
}];
