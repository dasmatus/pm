//! pip and the Python interpreter. The Python grammar is `python-source`.

use bundled::{Capability, Fingerprint, Table};

/// The fingerprints, in precedence order.
static FINGERPRINTS: Table = Table::new(&[
    Fingerprint {
        name: "pip",
        pattern: bundled::program!(r"pip[23]?"),
        capabilities: &bundled::FETCHING_TOOLCHAIN,
    },
    Fingerprint {
        name: "python",
        // `python setup.py build` and friends. Deliberately NOT granted
        // Network: a setup.py that needs to download says so with `dl_urls`
        // or reaches for pip, and both of those grant it explicitly.
        pattern: bundled::program!(r"python[23]?(?:\.\d+)?"),
        capabilities: &[Capability::Toolchain, Capability::Coreutils],
    },
]);

bundled::plugin! {
    name: "python",
    summary: "pip and python",
    commands: &FINGERPRINTS,
    sources: &bundled::NoSources,
}
