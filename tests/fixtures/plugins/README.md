# Plugin test fixtures

`build.rs` compiles the plugin examples and adversarial fixtures into Cargo's
build output for integration tests. The generated components are not checked into
the source tree or embedded in pm's executable.

| fixture | source | purpose |
|---|---|---|
| `zig` | `plugins/zig` | well-behaved plugin with both hooks |
| `systemd`, `sysupdate`, `sysext` | `plugins/` | example plugins tested together |
| `greedy` | `plugins/fixtures/greedy` | asks for capabilities above its ceiling |
| `runaway` | `plugins/fixtures/runaway` | exceeds the per-call fuel budget |
| `nameless` | `plugins/fixtures/nameless` | has no usable name |
| `scanner` | `plugins/fixtures/scanner` | scans a file type pm has no grammar for |
| `wasi` | `plugins/fixtures/wasi` | requests imports pm does not provide |
