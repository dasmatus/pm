//! A fixture that asks for more than it published.
//!
//! Declares a ceiling of `Toolchain` alone and then returns a verdict demanding
//! `Network` and `Shell` as well. pm is expected to keep the `Toolchain` and drop the
//! other two, so `tests/plugins.rs` can assert that the published ceiling is enforced
//! rather than merely printed.
//!
//! It also publishes two symbols: one ordinary, and one whose value carries whitespace
//! and would therefore turn a build file's
//! `install -Dm644 foo %{greedy:injected}/foo` into a command with three extra
//! arguments in it. pm is expected to drop that one at load, so `tests/symbols.rs` can
//! assert that a symbol can only ever fill in part of an argument a build file already
//! wrote.

wit_bindgen::generate!({ path: "../../../wit", world: "plugin" });

use pm::plugin::types::{Capability, Hook, Symbol};

struct Greedy;

impl Guest for Greedy {
    fn describe() -> Manifest {
        Manifest {
            name: "greedy".into(),
            version: "0.1.0".into(),
            summary: "Asks for capabilities outside the ceiling it published".into(),
            hooks: vec![Hook::ClassifyCommand],
            grants_at_most: vec![Capability::Toolchain],
            source_extensions: Vec::new(),
            symbols: vec![
                Symbol {
                    name: "ok".into(),
                    value: "/opt/greedy".into(),
                    summary: "an ordinary symbol".into(),
                },
                Symbol {
                    name: "injected".into(),
                    value: "/tmp --strip-all /etc/shadow".into(),
                    summary: "three arguments wearing a path's clothes".into(),
                },
            ],
        }
    }

    fn classify_command(command: String) -> Option<Verdict> {
        command.starts_with("greedy").then(|| Verdict {
            fingerprint: "greedy".into(),
            capabilities: vec![
                Capability::Toolchain,
                Capability::Network,
                Capability::Shell,
            ],
        })
    }

    fn scan_source(_file: SourceFile) -> Vec<Grant> {
        Vec::new()
    }
}

export!(Greedy);
