//! A fixture that asks for more than it published.
//!
//! Declares a ceiling of `Toolchain` alone and then returns a verdict demanding
//! `Network` and `Shell` as well. pm is expected to keep the `Toolchain` and drop the
//! other two, so `tests/plugins.rs` can assert that the published ceiling is enforced
//! rather than merely printed.

wit_bindgen::generate!({ path: "../../../wit", world: "plugin" });

use pm::plugin::types::{Capability, Hook};

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
