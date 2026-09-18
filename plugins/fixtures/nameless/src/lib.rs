//! A fixture with no usable name.
//!
//! `describe` calls itself `""`. A plugin's name prefixes every fingerprint and evidence
//! line it causes, so pm cannot attribute anything this returns and is expected to
//! refuse to load it at all - loudly, at load time, rather than quietly at build time.

wit_bindgen::generate!({ path: "../../../wit", world: "plugin" });

use pm::plugin::types::Hook;

struct Nameless;

impl Guest for Nameless {
    fn describe() -> Manifest {
        Manifest {
            name: String::new(),
            version: "0.1.0".into(),
            summary: "Has no name".into(),
            hooks: vec![Hook::ClassifyCommand],
            grants_at_most: Vec::new(),
            source_extensions: Vec::new(),
            symbols: Vec::new(),
        }
    }

    fn classify_command(_command: String) -> Option<Verdict> {
        None
    }

    fn scan_source(_file: SourceFile) -> Vec<Grant> {
        Vec::new()
    }
}

export!(Nameless);
