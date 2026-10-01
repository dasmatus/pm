//! The C and C++ toolchain: compilers, binutils and pkg-config. The grammars are
//! `c-source` and `cpp-source`.

use bundled::{Capability, Fingerprint, Table};

/// The fingerprints, in precedence order.
static FINGERPRINTS: Table = Table::new(&[
    Fingerprint {
        name: "pkg-config",
        pattern: bundled::program!(r"pkg-config|pkgconf"),
        capabilities: &[Capability::Toolchain],
    },
    Fingerprint {
        name: "compiler",
        // `cc`, `gcc`, `g++`, `clang`, `clang++`, their versioned spellings
        // (`gcc-14`) and their cross-compiler spellings.
        pattern: bundled::prefixed_program!(
            r"(?:cc|c\+\+|gcc|g\+\+|clang|clang\+\+)(?:-\d+(?:\.\d+)*)?"
        ),
        capabilities: &[Capability::Toolchain, Capability::Coreutils],
    },
    Fingerprint {
        name: "ld",
        // The linker and the rest of binutils, including cross spellings.
        pattern: bundled::prefixed_program!(
            r"ld|ld\.bfd|ld\.gold|ld\.lld|lld|ar|ranlib|nm|strip|objcopy"
        ),
        capabilities: &[Capability::Toolchain],
    },
]);

bundled::plugin! {
    name: "c",
    summary: "C and C++ compilers, binutils and pkg-config",
    commands: &FINGERPRINTS,
    sources: &bundled::NoSources,
}
