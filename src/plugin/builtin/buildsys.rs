//! The build systems: they drive a toolchain and run recipe lines through a shell.
//!
//! Language-neutral on purpose. `make` builds C as happily as it builds anything else,
//! so it belongs to no one language's plugin.

use super::{BUILD_SYSTEM, Builtin};
use crate::policy::Fingerprint;

pub(super) static PLUGIN: Builtin = Builtin {
    name: "buildsys",
    summary: "make, autotools configure scripts, CMake, Ninja and Meson",
    fingerprints: FINGERPRINTS,
    languages: &[],
};

static FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        name: "make",
        // GNU make and the `gmake` spelling it carries on non-GNU systems.
        pattern: program!(r"g?make"),
        // `make` runs every recipe line through /bin/sh, and those lines are
        // overwhelmingly compiler and coreutils invocations.
        capabilities: &BUILD_SYSTEM,
    },
    Fingerprint {
        name: "configure",
        // `./configure`, `../configure` and `/src/configure`; a generated
        // configure script is a shell script that probes the toolchain.
        pattern: program!(r"configure"),
        capabilities: &BUILD_SYSTEM,
    },
    Fingerprint {
        name: "cmake",
        pattern: program!(r"cmake|ctest|cpack"),
        capabilities: &BUILD_SYSTEM,
    },
    Fingerprint {
        name: "ninja",
        pattern: program!(r"ninja|samu"),
        capabilities: &BUILD_SYSTEM,
    },
    Fingerprint {
        name: "meson",
        pattern: program!(r"meson"),
        capabilities: &BUILD_SYSTEM,
    },
];
