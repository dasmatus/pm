# pm

`pm` is an experimental package manager focused on **constrained builds** and
**constrained package execution**.

It takes a signed YAML build file, derives a sandbox policy from the build
commands, builds inside a jail, and outputs a signed `.cpkg` archive that can
be executed under an inferred runtime permission profile.

## What it does

- Builds packages from declarative YAML build files.
- Resolves build-file dependencies and builds them as a graph.
- Derives build sandbox policy from known command fingerprints (instead of
  trusting the build file to declare policy).
- Signs and verifies build files, packages, and plugins.
- Runs packaged binaries with an auditable/enforceable runtime profile.
- Supports optional WebAssembly plugins for extra command/source
  classification.

## CLI overview

```text
pm build <file>       # build and package
pm explain <file>     # show derived sandbox policy
pm generate <file>    # write a starter build file
pm run <package>      # run a packaged binary
pm profile <package>  # inspect recorded runtime profile
pm promote <package>  # promote profile from audit to enforce
pm sign <file>        # create detached signature (.sig)
pm keygen             # create signing key
pm plugins            # list loaded plugins
pm trust <key|file>   # trust a signer key
```

Run `pm --help` or `pm <command> --help` for full options.

## Build-file format (quick reference)

Top-level fields:

- `name`: package name
- `version`: list of strings (joined by `.`)
- `dependencies`: list of paths to other build files
- `steps`: list of build steps

Step fields:

- `stage`: `Prepare | Build | Install | Test`
- `name`: label for logging/diagnostics
- `run`: list of command strings
- `dl_urls`: optional map of URL → SHA-256

Generate an example skeleton:

```sh
pm generate build.yaml
```

## Quickstart

1. Build `pm`:

   ```sh
   cargo build
   ```

2. Create a signing key (first-time setup):

   ```sh
   cargo run --bin pm -- keygen
   ```

3. Generate and sign a build file:

   ```sh
   cargo run --bin pm -- generate /tmp/build.yaml
   cargo run --bin pm -- sign /tmp/build.yaml
   ```

4. Build a package:

   ```sh
   cargo run --bin pm -- build /tmp/build.yaml
   ```

## End-to-end demo

This repository includes an example dependency chain and a demo script:

```sh
bash examples/demo.sh
```

See `examples/README.md` for detailed behavior and format notes.

## Plugins

Plugins are signed WebAssembly components loaded from your pm config plugin
directory (or `--plugin-dir`).

They can:

- classify previously unknown build commands
- scan additional source types for runtime-permission inference
- expose `%{plugin:symbol}` values for build command substitution

Plugin authoring details are in `plugins/README.md` and the interface
definition is in `wit/plugin.wit`.

## Development

Common checks used by CI:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Sandbox-specific ignored tests:

```sh
cargo test --all-features --test sandbox -- --ignored
cargo test --all-features --test landlock -- --ignored
```

These are Linux-only confinement checks and require kernel support for Landlock
plus unprivileged user namespaces; on environments without that support, use the
default test suite as the baseline and run these where those features are
available.
