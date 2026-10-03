# pm

Build signed recipes into `.cpkg` archives and run their entrypoints in a Linux
sandbox. See [the examples](examples/README.md) for `.package` recipe syntax and signing.

## Build files are Starlark

Recipes are [Starlark](https://github.com/bazelbuild/starlark) programs in
`*.package` files that call `package(...)` once, with `step(...)` for each
build step. Loops, functions and comprehensions generate steps and commands;
evaluation is hermetic (no I/O, no `load()`) and happens before the policy is
derived and before anything runs.

```python
package(
    name = "hello",
    version = "1.0.0",
    steps = [
        step(Install, "stage", ["install -Dm755 /usr/bin/echo /dest/usr/bin/hello"]),
    ],
)
```

* `pm generate build.package` writes a starter file.
* `pm migrate build.yaml` converts a YAML recipe (`-r` follows its YAML
  dependencies). YAML recipes still load but are deprecated; migrated files are
  unsigned, so run `pm sign` on them.
* `pm-lsp` is a language server (diagnostics, completion, hover) for `.package`
  files, and [`editors/`](editors/README.md) has tree-sitter queries and
  Zed and Neovim integrations that use it.

## Shipping a kernel

A package can ship its own Linux kernel. Install the image into `DESTDIR` with
the package's steps and name it in `package(...)`:

```python
package(
    name = "hello",
    version = "1.0.0",
    steps = [
        step(Install, "stage", [
            "install -Dm644 /path/to/vmlinuz /dest/boot/vmlinuz",
            "install -Dm755 /path/to/hello /dest/usr/bin/hello",
        ]),
    ],
    kernel = kernel(image = "boot/vmlinuz", cmdline = "mitigations=off"),
)
```

`image` is relative to `DESTDIR`. The build fails if the steps did not install
it or if it is not a Linux kernel image (a bzImage, a vmlinux, or an arm64 or
RISC-V `Image`), and the image is never offered as a program. `cmdline` is
optional and is appended to the kernel command line.

`pm run` boots such a package's kernel in a QEMU virtual machine instead of
running it in the namespace jail on the host's kernel:

* The guest's root filesystem is an initramfs pm assembles for each run. It
  holds the package at `/pkg`, the host loader and shared libraries the
  package's binaries link (at their host paths), and `pm-vm-init`, which runs
  the entrypoint, reports its exit code to the host and powers the machine off.
  Nothing else from the host is visible, the machine has no network device and
  no disk, and the recorded landlock profile is not applied inside it.
* The console is your terminal, so the program's output and input work as they
  do in the jail. Its exit code is `pm run`'s exit code.
* It needs `qemu-system-x86_64` on `PATH`, and uses KVM when `/dev/kvm` is
  usable (emulation otherwise, which is slow). Only x86-64 hosts can boot a
  package kernel today.
* The kernel needs initramfs support, an 8250/16550 serial console and ELF
  support built in, which distribution `generic` and `virtual` kernels have.
* `--network` and `--audit` are refused, because the guest has no NIC and a
  traced host process cannot see into a VM. `pm run --host-kernel` runs the
  package in the usual jail and ignores its kernel.

Install `pm-vm-init` beside `pm`: it is copied into every initramfs, and is
much smaller than `pm`, which is used in its place when it is missing.

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
