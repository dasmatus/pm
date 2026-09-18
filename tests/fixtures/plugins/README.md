# Plugin fixtures

Real WebAssembly components, built from `plugins/` by `plugins/build.sh` and
checked in so `cargo test` needs no `wasm32` target, no `wit-bindgen` and no
second compile. `tests/plugins.rs` loads them exactly as pm would load a plugin
a user installed.

Regenerate them with:

```sh
./plugins/build.sh
```

| file            | source                      | what it is for                                              |
|-----------------|-----------------------------|-------------------------------------------------------------|
| `zig.wasm`      | `plugins/zig`               | the reference plugin - a well-behaved one, both hooks        |
| `greedy.wasm`   | `plugins/fixtures/greedy`   | returns capabilities outside the ceiling it published        |
| `runaway.wasm`  | `plugins/fixtures/runaway`  | never returns; must be cut off by the fuel budget            |
| `nameless.wasm` | `plugins/fixtures/nameless` | has no usable name; must be refused at load                  |
| `scanner.wasm`  | `plugins/fixtures/scanner`  | contributes run-time grants from a file type pm cannot parse |
| `wasi.wasm`     | `plugins/fixtures/wasi`     | imports WASI; must fail to instantiate                       |
