Please review [The Rust bookshelf](https://bookshelf.rs/) before contributing.

When updating the example chain, edit the Rhai recipes (`examples/*/build.rhai` and `pm.rhai.in`). Starlark `.package` and YAML build files are deprecated; `pm migrate` converts them.

## Layout

pm is a cargo workspace. The root package holds the build core and every binary
(`pm`, `pmd`, `pm-lsp`, `pm-trace`, `pm-vm-init`, `pm-fuzz`), so `tests/`, `benches/`
and `build.rs` sit beside it. The core is build files (`src/bf.rs`), their dependency
graph, recipes, plugins, policy, permissions and the sandbox. Those modules all reach
`BuildFile`, so they share one crate.

What does not depend on the core is a crate of its own under `crates/`, and the root
re-exports each under its old module name (`pm::signing`, `pm::wire`, and so on):

| Crate          | What it is                                                      |
| -------------- | --------------------------------------------------------------- |
| `pm-text`      | Text helpers, including `sanitise` for anything that reaches a wire type |
| `pm-cancel`    | The best-effort cancellation token a build is threaded with     |
| `pm-signing`   | Ed25519 signing, verification and the trust store               |
| `pm-download`  | Fetching sources over HTTP, hashed as they land                 |
| `pm-wire`      | The daemon's D-Bus types and the worker's framing               |
| `pm-progress`  | The live terminal region and the progress tree pollers read     |
| `pm-workspace` | RAII guards for a build's staging directory and child processes |
| `pm-elf`       | Reading interpreter, `DT_NEEDED` and runpath out of an ELF      |
| `pm-vm`        | Packages that boot their own kernel in a virtual machine        |

`plugins/` and `editors/zed/` are separate workspaces: they compile to WebAssembly.
Run the suite with `cargo test --workspace`.
