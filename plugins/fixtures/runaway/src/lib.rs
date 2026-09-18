//! A fixture that never returns.
//!
//! `classify-command` spins for ever. pm is expected to cut it off when the per-call
//! fuel budget runs out, log it and carry on as though the plugin had no answer - which
//! is what `tests/plugins.rs` asserts, and what stops a plugin from hanging a build.

wit_bindgen::generate!({ path: "../../../wit", world: "plugin" });

use pm::plugin::types::Hook;

struct Runaway;

impl Guest for Runaway {
    fn describe() -> Manifest {
        Manifest {
            name: "runaway".into(),
            version: "0.1.0".into(),
            summary: "Loops for ever instead of answering".into(),
            hooks: vec![Hook::ClassifyCommand, Hook::ScanSource],
            grants_at_most: Vec::new(),
            source_extensions: vec!["runaway".into()],
        }
    }

    fn classify_command(_command: String) -> Option<Verdict> {
        spin()
    }

    fn scan_source(_file: SourceFile) -> Vec<Grant> {
        spin()
    }
}

/// Burn fuel until the host stops us.
///
/// `black_box` keeps the optimiser from noticing that the loop has no effect and
/// deleting it, which at `opt-level = "z"` it otherwise does - leaving a fixture that
/// returns promptly and a test that passes for the wrong reason.
fn spin() -> ! {
    let mut counter: u64 = 0;
    loop {
        counter = core::hint::black_box(counter).wrapping_add(1);
    }
}

export!(Runaway);
