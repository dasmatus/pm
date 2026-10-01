//! The go command. The Go grammar is `go-source`.

use bundled::{Fingerprint, Table};

/// The fingerprints, in precedence order.
static FINGERPRINTS: Table = Table::new(&[Fingerprint {
    name: "go",
    // `go build` fetches modules; `gofmt` is a different word and does not
    // match, because the pattern demands a word terminator after `go`.
    pattern: bundled::program!(r"go"),
    capabilities: &bundled::FETCHING_TOOLCHAIN,
}]);

bundled::plugin! {
    name: "go",
    summary: "the go command",
    commands: &FINGERPRINTS,
    sources: &bundled::NoSources,
}
