//! A fixture that wants more of the host than pm lends a plugin.
//!
//! Exports the world correctly and then reads a file and an environment variable, which
//! drags `wasi:filesystem`, `wasi:cli` and their dependencies into the component's
//! imports. pm's linker defines exactly one function - `pm:plugin/host.log` - so this
//! cannot instantiate, and `tests/plugins.rs` asserts that it does not.
//!
//! That assertion is the sandbox claim in `plugins/README.md` stated as a test: a plugin
//! has no filesystem, no clock, no randomness, no network and no environment, *by
//! construction*, because nothing else is ever linked in for it to call. Should anyone
//! add a second `add_to_linker` to `src/plugin/engine.rs`, this fixture starts loading
//! and the test goes red.
//!
//! Built for `wasm32-wasip2`, unlike every other crate here, because that is the target
//! that links a WASI libc. `rustc` emits a component directly for it, so `plugins/build.sh`
//! skips the encoding step for this one.

wit_bindgen::generate!({ path: "../../../wit", world: "plugin" });

use pm::plugin::types::Hook;

struct Wasi;

impl Guest for Wasi {
    fn describe() -> Manifest {
        Manifest {
            name: "wasi".into(),
            version: "0.1.0".into(),
            // Two syscalls pm does not lend anybody, in the one export pm calls first.
            summary: std::fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| std::env::var("HOME").unwrap_or_default()),
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

export!(Wasi);
