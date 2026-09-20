# pm

Build signed recipes into `.cpkg` archives and run their entrypoints in a Linux
sandbox. See [the examples](examples/README.md) for recipe syntax and signing.

## Integration with distribution build tools

Projects such as `dichhead/losos-desktop` generate recipes and assemble system
images from their outputs. Use these interfaces instead of duplicating pm's
internal download hashing or parsing its human-readable policy table.

### Locate a source download

```sh
pm source-path 'https://example.org/project-1.0.tar.xz'
pm source-path --relative 'https://example.org/project-1.0.tar.xz'
```

The first command prints the source's absolute path inside the build jail
(`/build/.../project-1.0.tar.xz`). The second prints a path relative to the build
working directory, useful for unconfined builds. Both print only one path to
stdout, perform no downloads, create no files and load no plugins. Use exactly
the URL in the recipe's `dl_urls` map, including its query string. URLs without a
usable filename fail with a nonzero exit status.

Rust consumers can use `pm::step::Step::download_path(&url)`. The downloader uses
this same function; consumers should not depend on the digest algorithm. Resolve
paths with the pm version that will build the generated recipe. Hash verification
still happens during the build, not during a path query.

### Machine-readable policy gates

```sh
pm explain build.yaml --format yaml
pm explain build.yaml --format yaml --permissive
```

YAML output is a single document on stdout; diagnostics stay on stderr. It
contains:

| Field | Meaning |
| --- | --- |
| `schema_version` | Currently `1`; reject unsupported versions in consumers. |
| `name`, `version`, `dependencies` | Package name, version components and declared dependency recipe paths. |
| `fingerprint` | The same policy change-detection digest as the text report, not a cryptographic signature. |
| `capabilities` | Sorted capability names, including `Network` when granted. |
| `commands` | Ordered records with `command`, `fingerprint` and boolean `matched`. |
| `plugins` | Loaded plugin `name`, `version`, `sha256` and `trust`. |
| `symbols` | Referenced plugin symbols mapped to their expanded values. |
| `downloads` | Records with `step`, `url`, expected `sha256` and in-jail `path`, sorted by URL within each step. |

The report covers the specified recipe, **not its dependency closure**. It
expands symbols and derives policy without running build commands or fetching
sources. Signature verification and plugin trust rules are identical to text
mode. Existing text output remains the default.

Always check the process exit status, even when stdout contains a valid report.
With `--permissive`, unmatched commands are included with `matched: false`, but
the command still exits nonzero. Without it, policy derivation fails before a
report is emitted. Missing/untrusted recipes and unusable plugins also fail.

### Desktop payloads and current limits

Regular files are binary entrypoints only when at least one Unix executable bit
is set. Libraries (`.a`, `.so`, `.so.N`) remain library entrypoints without
executable bits. Non-executable systemd units, desktop entries, icons, headers
and configuration files remain in the archive but are not offered as programs.

pm is not yet a system package installer or image composer. Dependencies are
bundled as nested archives, not automatically merged into a build sysroot or
runtime root. An image builder must preserve the complete required payload
(including `/etc` and `/var`, not only `/usr`), handle file conflicts and symlinks,
and keep build-only pkg-config prefix rewrites out of the final image. Service
activation, sysusers, presets, architecture-aware image manifests and transactional
system updates remain the distribution's responsibility. These interfaces do not
make `pm run` a replacement for systemd service management.
