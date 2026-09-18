//! Turn a core WebAssembly module into a component.
//!
//! `cargo build --target wasm32-unknown-unknown` produces a *core module*, not a
//! component: the canonical-ABI shims `wit-bindgen` generated are in it, but nothing has
//! wrapped them in a component's type section yet. `wasm-tools component new` does that
//! job, and so does this - in thirty lines and with no `cargo install`, so
//! `plugins/build.sh` works on a machine that has nothing but a Rust toolchain.
//!
//! Use `wasm-tools` instead if you already have it; the output is the same encoder.
//!
//! ```sh
//! encoder <core module> <component>
//! ```

use std::{env::args_os, ffi::OsString, fs, path::PathBuf, process::ExitCode};

use wit_component::ComponentEncoder;

fn main() -> ExitCode {
    let arguments: Vec<OsString> = args_os().skip(1).collect();
    let [input, output] = arguments.as_slice() else {
        eprintln!("usage: encoder <core module.wasm> <component.wasm>");
        return ExitCode::FAILURE;
    };
    let (input, output) = (PathBuf::from(input), PathBuf::from(output));

    let module = match fs::read(&input) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {}: {error}", input.display());
            return ExitCode::FAILURE;
        }
    };

    // `validate` is the point of doing this in a build step rather than at load: a
    // component that does not validate is caught here, where the author is looking,
    // instead of in pm, where the user is.
    let encoded = ComponentEncoder::default()
        .module(&module)
        .and_then(|encoder| encoder.validate(true).encode());
    let bytes = match encoded {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!(
                "cannot encode {} as a component: {error:?}",
                input.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = fs::write(&output, &bytes) {
        eprintln!("cannot write {}: {error}", output.display());
        return ExitCode::FAILURE;
    }
    println!("{} ({} bytes)", output.display(), bytes.len());
    ExitCode::SUCCESS
}
