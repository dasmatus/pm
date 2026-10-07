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

use std::{env::args_os, ffi::OsString, fs, path::PathBuf};

use miette::{IntoDiagnostic, WrapErr, miette};
use wit_component::ComponentEncoder;

fn main() -> miette::Result<()> {
    let arguments: Vec<OsString> = args_os().skip(1).collect();
    let [input, output] = arguments.as_slice() else {
        return Err(miette!(
            help = "usage: encoder <core module.wasm> <component.wasm>",
            "expected two arguments, got {}",
            arguments.len()
        ));
    };
    let (input, output) = (PathBuf::from(input), PathBuf::from(output));

    let module = fs::read(&input)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot read {}", input.display()))?;

    // `validate` is the point of doing this in a build step rather than at load: a
    // component that does not validate is caught here, where the author is looking,
    // instead of in pm, where the user is.
    let bytes = ComponentEncoder::default()
        .module(&module)
        .and_then(|encoder| encoder.validate(true).encode())
        // wit-component's errors are anyhow's, whose `Debug` carries the whole chain
        // of causes; `Display` would keep only the outermost.
        .map_err(|error| miette!("{error:?}"))
        .wrap_err_with(|| format!("cannot encode {} as a component", input.display()))?;

    fs::write(&output, &bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot write {}", output.display()))?;
    println!("{} ({} bytes)", output.display(), bytes.len());
    Ok(())
}
