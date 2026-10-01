//! The build systems: they drive a toolchain and run recipe lines through a shell.
//!
//! Language-neutral on purpose. `make` builds C as happily as it builds anything else,
//! so it belongs to no one language's plugin.

use bundled::{Fingerprint, Table};

/// The fingerprints, in precedence order.
static FINGERPRINTS: Table = Table::new(&[
    Fingerprint {
        name: "make",
        // GNU make and the `gmake` spelling it carries on non-GNU systems.
        pattern: bundled::program!(r"g?make"),
        // `make` runs every recipe line through /bin/sh, and those lines are
        // overwhelmingly compiler and coreutils invocations.
        capabilities: &bundled::BUILD_SYSTEM,
    },
    Fingerprint {
        name: "configure",
        // `./configure`, `../configure` and `/src/configure`; a generated
        // configure script is a shell script that probes the toolchain.
        pattern: bundled::program!(r"configure"),
        capabilities: &bundled::BUILD_SYSTEM,
    },
    Fingerprint {
        name: "cmake",
        pattern: bundled::program!(r"cmake|ctest|cpack"),
        capabilities: &bundled::BUILD_SYSTEM,
    },
    Fingerprint {
        name: "ninja",
        pattern: bundled::program!(r"ninja|samu"),
        capabilities: &bundled::BUILD_SYSTEM,
    },
    Fingerprint {
        name: "meson",
        pattern: bundled::program!(r"meson"),
        capabilities: &bundled::BUILD_SYSTEM,
    },
]);

bundled::plugin! {
    name: "buildsys",
    summary: "make, autotools configure scripts, CMake, Ninja and Meson",
    commands: &FINGERPRINTS,
    sources: &bundled::NoSources,
}
