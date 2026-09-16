# Example build files

A chain of four packages, each depending on the one below it, ending at `pm`'s
own build file. Building the top of the chain builds all of them:

```
examples/01-seed/build.yaml     dependencies: []
        ^
examples/02-lib/build.yaml      dependencies: [../examples/01-seed/build.yaml]
        ^
examples/03-app/build.yaml      dependencies: [../examples/02-lib/build.yaml]
        ^
pm.yaml            (repo root)  dependencies: [../examples/03-app/build.yaml]
```

`pm.yaml` really does compile `pm` with `cargo build --release`, inside the same
jail every other package in the chain gets. The three files under `examples/`
are committed verbatim and are machine-independent; `pm.yaml` is generated from
`pm.yaml.in` because it has to name absolute paths (see
[No `$srcdir`](#no-srcdir)).

```sh
bash examples/demo.sh
```

That builds the chain end to end and then demonstrates both of pm's confinement
layers. It uses a throwaway signing key under `examples/.demo-config` and never
touches your real `~/.config/pm`.

It also points `TMPDIR` at `out/tmp` first, and that is not tidiness. Every
build workspace lives under `TMPDIR` (`Workspace::new`), and compiling pm's own
dependency graph in release mode needs several GB there. Where `/tmp` is a
tmpfs, which is the Fedora default, the build dies partway through `aws-lc-sys`
with `Disk quota exceeded (os error 122)`. Anything building more than a toy
package through `pm` wants `TMPDIR` on real disk.

---

## The format

A build file is plain YAML with exactly four fields, all required
(`BuildFile` in `src/bf.rs`):

| field | type | notes |
|---|---|---|
| `name` | string | archive is named `<name>-<version>.cpkg` |
| `version` | list of **strings** | joined with `.`; quote every component, or YAML hands serde an integer and parsing fails |
| `dependencies` | list of **paths to other build files** | no registry, no names, no version constraints |
| `steps` | list of steps | may be empty |

A step (`Step` in `src/step.rs`):

| field | type | notes |
|---|---|---|
| `stage` | `Prepare` \| `Build` \| `Install` \| `Test` | required — serde does not apply the Rust default |
| `name` | string | diagnostics and logging only |
| `run` | list of strings | commands, in order |
| `dl_urls` | map URL → SHA-256, or `null` | the only optional field |

Steps are sorted by stage and keep their authored order within a stage
(`BuildFile::execute_steps`). `pm generate <file>` writes a minimal skeleton.

### There is no shell

This is the single most surprising thing about the format. A command string is
split on whitespace and `execve`d directly (`Step::execute`). No quoting, no
globbing, no pipes, no redirection, **no variable expansion**.

```yaml
run:
- install -Dm755 /usr/bin/echo /dest/usr/bin/seed   # works
- cp foo $DESTDIR/bin/                              # creates a directory literally named $DESTDIR
- make install                                      # works, and is the intended shape
```

`DESTDIR` is in the environment, set to `/dest`, because that is the Makefile
convention: `make install` reads it and the Makefile's own rules expand
`$(DESTDIR)$(PREFIX)/bin`. A step is meant to be a build-system invocation, not
a hand-written `cp`. Anything that genuinely needs a shell goes in a script
file, invoked as two plain words: `/bin/sh /abs/path/to/script.sh`.

The jailed environment is exactly five variables (`BuildSandbox::run_jailed`):

```
DESTDIR=/dest   PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
HOME=/build     TMPDIR=/tmp     LC_ALL=C
```

with the working directory at `/build`. Nothing else is inherited.

### Every command must be recognised

The sandbox policy is **derived, never declared** (the module doc of `src/policy.rs`):

> A build file is data supplied by whoever wrote the package, so the sandbox it
> runs in must not be configured by that same file: a hostile build file would
> simply ask for everything.

Each command is matched against a built-in fingerprint table, and a command
matching nothing aborts the build before a single step runs. The table:

`make` · `configure` · `cmake`/`ctest`/`cpack` · `ninja`/`samu` · `meson` ·
`cargo`/`rustc` · `go` · `npm`/`yarn`/`pnpm`/`npx`/`node` · `pip` · `python` ·
`pkg-config`/`pkgconf` · `cc`/`c++`/`gcc`/`g++`/`clang`/`clang++` (versioned and
target-prefixed spellings included) · `ld`/`ar`/`ranlib`/`nm`/`strip`/`objcopy` ·
`sh`/`bash`/`dash`/`ash`/`zsh` · `tar`/`unzip`/`xz`/`gzip`/`zstd`/`7z`/`cpio` ·
`git` · and a coreutils catch-all:
`install cp mv rm mkdir rmdir chmod chown ln ls cat echo printf touch true
false test pwd env mktemp sed awk gawk grep find xargs sort head tail cut tr
sync patch`.

An optional leading path is allowed, so `/bin/sh` and `./configure` match, while
`evilmake` does not match `make`. `pm explain <file>` prints the whole table for
a build file and exits non-zero on anything unmatched, which makes it usable as
a lint.

Only `Network` actually changes the jail today (`BuildSandbox::new`). The
other five capabilities — `Toolchain`, `Coreutils`, `Shell`, `Archive`,
`VersionControl` — are derived and reported but alter no mount. Calling this
"capability-scoped build confinement" would be overclaiming; it is a
classification gate plus a network switch.

### Signing is not optional

`pm build` and `pm explain` verify a detached `<FILE>.sig` **before** parsing
the file, against `$XDG_CONFIG_HOME/pm/trusted/` (`BuildFile::load`). How the
top-level file was loaded rides on the value, so dependencies are held to the
same standard all the way down — signed all the way, or not at all
(`BuildFile::build_dependency`). `pm run` and `pm profile` verify the `.cpkg` too.

Editing a build file invalidates its signature, including a comment. `demo.sh`
re-signs everything on each run.

### Dependencies resolve against the *process* working directory

Not against the build file's directory (`BuildFile::build_dependency`). That is
why every `dependencies:` entry here is spelled `../examples/...`: `demo.sh` runs `pm`
from the repo's `out/` directory throughout.

Running from `out/` is deliberate. Archives land in the process working
directory, and the directory holding each dependency archive is bind-mounted
read-only into the dependent package's jail (`BuildFile::read_only_mounts`).
Building from `out/` means a dependent package sees a directory of `.cpkg` files; building
from the repo root would have handed it the whole repository.

A dependency's archive is copied into the dependent's `DESTDIR` as
`deps/<name>-<version>.cpkg` and ships inside the resulting archive. **Nothing
unpacks it**, and nothing sets `-I`/`-L`/`PKG_CONFIG_PATH`. There is no store
and no prefix. Only *direct* dependencies appear in `deps/` — the tree is
carried, not flattened, which `examples/03-app` asserts.

### No `$srcdir`

There is no variable for "the directory this build file lives in". Commands run
with the working directory at `/build`, and the only host directory mounted is
the build file's own, at its own absolute path. So a build file that refers to
its own sources must spell an absolute path.

The three files under `examples/` sidestep this entirely — they stage payloads
copied out of `/usr/bin`, so they need no absolute path and are committed as-is.
`pm.yaml` cannot: cargo needs `--manifest-path`. Hence `pm.yaml.in` and the five
placeholders `@SRCDIR@`, `@HOME@`, `@TRIPLE@`, `@CC@`, `@AR@`.

---

## What a build step can actually touch

The jail (the module doc of `src/sandbox.rs`, and `BuildFile::read_only_mounts`):

| path | access | why |
|---|---|---|
| `/build` | **read-write** | the working directory |
| `/dest` | **read-write** | `DESTDIR` |
| `/bin /etc /lib /lib32 /lib64 /sbin /usr` | read-only | mirrored from the host so the loader and toolchain work |
| toolchain dirs on `PATH` outside those roots | read-only | e.g. `/nix/store`; any `PATH` entry touching `$HOME` is refused |
| the build file's own directory | read-only | sources, patches, helper scripts |
| the directory of each dependency archive | read-only | here, `out/` |
| `/dev` | devfs | minimal |
| `/tmp` | fresh tmpfs | **not** the host's |
| network | absent unless the policy grants `Network` | own empty netns otherwise |

`/build` and `/dest` are the only writable mounts in the whole jail. `/root` and
`/var` are not mounted at all.

### The `/home` nuance, stated precisely

The doc on `toolchain_roots` in `src/sandbox.rs` says the jail "never has a
`/home` at all". On a
checkout that lives under a home directory — like this one — that is not quite
right, and the examples are written to assert the accurate version instead.

The build file's directory must be mounted *at its own absolute path*, so the
path components leading down to it are created inside the jail. `ls /home`
inside a build of this repo prints one entry. But the spine is hollow: it
contains only the next component on the way to the mount. Verified by running
`ls -a` inside the jail:

```
$ ls -a /home/matus            $ ls -a /home/matus/Dokumente
.                              .
..                             ..
Dokumente                      incubator
```

Nothing else in `$HOME` is reachable. `pm.yaml`'s `confine` step asserts the
sharp form with the real `$HOME` substituted in:

```yaml
- test ! -e /home/matus/.ssh
- test ! -e /home/matus/.config
- test ! -e /home/matus/.local
- test ! -e /home/matus/.bashrc
```

All four exist on the host; none exist in the jail. `examples/*/build.yaml`
cannot make that assertion without hard-coding a username, so they assert
`/root`, `/var`, the read-only `/usr` and the host-`/tmp` decoy instead.

---

## The two confinement layers

They are separate mechanisms with separate vocabularies, and the module doc of
`src/bf.rs` is careful never to conflate them.

**The build jail** (hakoniwa namespaces, no landlock) confines the *build*.
Its policy comes from the fingerprint table. This is what the `confine` step in
each example asserts, and what step 8 of the demo shows denying a write.

**The run jail** (hakoniwa + landlock) confines the *built package*. Its policy
is a `Permissions` profile inferred **after** the build from two signals:
tree-sitter analysis of the sources in the working directory, and ELF analysis
(`PT_INTERP`, `DT_NEEDED`, `DT_RUNPATH`) of each staged entrypoint. The package
is extracted read-only at `/pkg` and the entrypoint runs with that as its
working directory.

The build is deliberately **not** traced, and `BuildFile::derive_permissions`
says why. Tracing a build
traces the compiler, and would hand the package every header under
`/usr/include`, the linker's temp files and the tarball fetch. The ptrace
monitor belongs to `pm run --audit`, where it traces the actual entrypoint.

A fresh profile is always recorded in `Audit` and denies nothing, because it
describes what the package was *seen* to need, never what it *can* need.
Promotion to enforcing is a human decision made with `pm promote`; nothing on
the build path can make it.

### Why `03-app` stages two binaries

`usr/bin/hello` is a copy of `/usr/bin/echo`. Everything it needs — its loader
and its libraries — is exactly what ELF analysis records, so it is inside its
own profile.

`usr/bin/leak` is a copy of `/usr/bin/whoami`, which reads `/etc/passwd` to turn
a uid into a name. No signal pm has could know that: the dynamic section does
not mention it, and there is no source to scan because this package compiled
nothing. So `/etc/passwd` is absent from the profile.

Same package, same ruleset, two entrypoints — the only variable is which one you
ask for. That pairing matters: a demo that only showed the denial would be
equally consistent with a sandbox that denies everything and is therefore
useless.

---

## What a run looks like

Real output, trimmed. Every line below was produced by `examples/demo.sh` on a
Fedora host with a Nix toolchain, kernel 7.1.8.

**The chain building.** Note the capability line on each package: only `pm` gets
`Network`, and only `pm` gets the shared-network warning.

```
INFO pm::bf: building seed version 0.1.0
INFO pm::sandbox: build sandbox runs in its own empty network namespace
INFO pm::sandbox: build sandbox configured capabilities=[Coreutils]
                  workdir=/tmp/pm-seed-0.1.0-Pf0Ju6/work destdir=/tmp/pm-seed-0.1.0-Pf0Ju6/pkg
INFO pm::step: Running step stage=Prepare step=confine
INFO pm::step: Running step stage=Install step=stage
INFO pm::bf: derived the run-time permission profile package=seed grants=8
             summary=4 read, 0 write, 4 exec enforcement=Audit
...
INFO pm::bf: building pm version 0.1.0
WARN pm::sandbox: build policy grants network access; the build sandbox SHARES the host network
INFO pm::sandbox: build sandbox configured capabilities=[Toolchain, Coreutils, Network]
INFO pm::step: Running step stage=Prepare step=confine
INFO pm::step: Running step stage=Build step=compile
INFO pm::step: Running step stage=Install step=install
INFO pm::bf: packaged pm at .../out/pm-0.1.0.cpkg
```

Every `confine` step passed. On its own that proves little — the probes might
simply be true everywhere — so the demo pairs it with a control, which it
actually runs first, as step 6.

**The same build file with the jail switched off.** `pm build --unsandboxed`
executes the identical steps on the host. Same file, same signature, same
commands, same derived policy, same `pm`; the only variable is confinement.

```
WARN pm::sandbox: BUILD SANDBOX DISABLED: build steps will run UNCONFINED on this host,
                  with the calling user's full access to $HOME, the network and every
                  file they can reach. This is a debugging aid; never use it on a build
                  file you did not write.
INFO pm::step: Running step stage=Prepare step=confine
WARN pm::sandbox: running a build command UNSANDBOXED on the host step=confine command=test -d /build
Error:   × step confine failed
  ╰─▶ Command `test -d /build` in step `confine` failed with exit status: 1
```

It aborts on the first probe it reaches: `/build` is where the working
directory is mounted *inside* the container, and unconfined there is no such
path. The probes it never reaches are the ones `pm explain` lists in full.

That pairing is the build-jail proof. The probes hold under the jail and stop
holding the moment it is removed, so they are measuring confinement rather than
the machine they run on.

**A build cannot write back to its own directory.**

```
Error:   × step write-back failed
  ╰─▶ Command `touch .../out/escape/escaped` in step `write-back` failed
      inside the build sandbox with code 1 (process(/usr/bin/touch) exited with code 1)
      stderr:
      touch: cannot touch '.../out/escape/escaped': Read-only file system
```

**The profile inferred for `03-app`** — ELF analysis only, because the package
compiled nothing for source analysis to read. No `/etc` anywhere:

```
mode:       audit - accesses outside the profile are reported, none are denied
permissions: 8 grant(s)

read
  /lib        elf  DT_NEEDED libc.so.6, searched along the library path
  /lib64      elf  DT_NEEDED libc.so.6, searched along the library path
  /usr/lib    elf  DT_NEEDED libc.so.6, searched along the library path
  /usr/lib64  elf  DT_NEEDED libc.so.6, searched along the library path
exec
  /lib64      elf  PT_INTERP /lib64/ld-linux-x86-64.so.2
  ...
```

**The run jail, same package, same ruleset, two entrypoints.**

```
$ pm run app-0.1.0.cpkg --bin usr/bin/leak
INFO pm::run: profile recorded in audit mode; NOT enforced grants=8
matus
INFO pm::run: Entrypoint /pkg/usr/bin/leak exited with code 0

$ pm run app-0.1.0.cpkg --bin usr/bin/leak --audit
WARN pm::run: access OUTSIDE the recorded profile syscall="openat" permission=read /etc/ld.so.cache
WARN pm::run: access OUTSIDE the recorded profile syscall="openat" permission=read /etc/nsswitch.conf
WARN pm::run: access OUTSIDE the recorded profile syscall="openat" permission=read /etc/passwd
WARN pm::run: 4 access(es) fell outside the profile. Promoting to enforce would need these grants:
  read  /etc/ld.so.cache  /etc/nsswitch.conf  /etc/passwd

$ pm run app-0.1.0.cpkg --bin usr/bin/hello --enforce
INFO pm::run: ENFORCING the recorded profile with landlock grants=8
INFO pm::run: Entrypoint /pkg/usr/bin/hello exited with code 0

$ pm run app-0.1.0.cpkg --bin usr/bin/leak --enforce
INFO pm::run: ENFORCING the recorded profile with landlock grants=8
leak: cannot find name for user ID 1000: Permission denied
INFO pm::run: Entrypoint /pkg/usr/bin/leak exited with code 1
WARN pm: sandboxed program exited unsuccessfully code=1
```

`hello` passing under the identical ruleset is the half that makes the denial
mean something.

**pm, out of its own package.**

```
$ pm run pm-0.1.0.cpkg --bin usr/bin/pm
INFO pm::run: Running entrypoint /pkg/usr/bin/pm in a sandbox
Usage: pm <COMMAND>
...
INFO pm::run: Entrypoint /pkg/usr/bin/pm exited with code 2
```

Exit 2 is clap asking for a subcommand — `pm run` forwards no arguments — not a
sandbox failure.

---

## What this demonstrates, and what it does not

Demonstrated:

- A build step's view of the filesystem is the table above, asserted from inside
  the jail by commands that pass there and stop passing the moment the same
  build file is run with `--unsandboxed`.
- A build cannot write back into the read-only mount it was described by.
- A packaged binary is denied a path outside its inferred profile under
  `--enforce`, while a second binary in the *same* package under the *same*
  ruleset still runs.
- `pm` builds `pm` from source, inside that jail.

Not demonstrated, and not claimed:

- **Capability scoping of builds.** Five of the six capabilities change nothing.
- **Isolation from the network during pm's own build.** The `cargo` fingerprint
  grants `Network`, and pm logs a warning that the jail then *shares the host
  network namespace*. That is the honest trade: cargo resolves and downloads its
  own dependency graph.
- **Protection against a malicious build file that only reads.** The build
  file's own directory and the dependency-archive directory are readable, and
  the policy is derived from a fingerprint table that classifies by program
  name, not by argument.
- **Anything about kernels without landlock.** `Resource::FS` is requested with
  `CompatMode::Enforce`, so `pm run --enforce` fails closed on a kernel older
  than 5.13 rather than running unrestricted.
- **A meaningful run-time profile for `pm` itself.** The profile pm infers for
  its own package is dominated by path literals in its dependencies' source —
  see [pm's own profile](#a-profile-worth-reading-sceptically-pms-own). The
  landlock demonstration deliberately uses `03-app`, whose profile comes from
  ELF analysis alone and is therefore exactly checkable by eye.

---

## A profile worth reading sceptically: pm's own

`03-app` gets 8 grants. `pm` gets 56 — and almost none of them are about `pm`.

`derive_permissions` runs `source::scan` over the **working directory**, on the
stated assumption that "the steps unpacked and patched the package's sources
there, so that tree is what the shipped program was compiled from"
(`BuildFile::derive_permissions`). For a cargo build that assumption does not
hold. The jail
sets `HOME=/build`, so `CARGO_HOME` is `/build/.cargo`, so the working directory
ends up holding the unpacked source of **every downloaded dependency**. The scan
reads all of it.

Of the evidence lines in `pm profile pm-0.1.0.cpkg`, 526 point into
`.cargo/registry/…` and none point into pm's own `src/`:

```
read
  /dev/md124          source  .cargo/registry/…/procfs-core-0.18.0/src/process/mount.rs:622: rust:path-literal
  /etc/hosts.equiv    source  .cargo/registry/…/libc-0.2.189/src/unix/hurd/mod.rs:1553: rust:path-literal
  /etc/default/init   source  .cargo/registry/…/iana-time-zone-0.1.65/src/tz_illumos.rs:8: rust:path-literal
  /dev/zero           source  .cargo/registry/…/nix-0.31.3/test/test_unistd.rs:1324: rust:path-literal
```

`pm` does not read `/etc/hosts.equiv`. That grant exists because a path literal
appears in libc's **GNU Hurd** module. `/etc/default/init` comes from an
**illumos** timezone backend. `/dev/zero` comes from a dependency's **test
file**. None of that code is even compiled into the binary.

This is the same failure `BuildFile::derive_permissions` argues against for tracing —

> Tracing a build traces the **compiler**: the profile would come back holding
> every header under `/usr/include` […] A profile that wide means nothing

— arriving through the source-scan path instead. It is not a safety hole: the
profile is recorded in `Audit`, and a too-wide profile denies too little rather
than too much. But it makes the profile useless as a description of `pm`, and
`pm promote` on this archive would grant a great deal that is never needed.

The fix is not in this directory — the scan would need to exclude the
build-system caches it did not put there — so this is recorded rather than
worked around. For a package whose sources really are unpacked into the working
directory, which is the shape the format is designed for, the scan does what it
says.

---

## Notes on the toolchain

`pm` resolves the **first word** of a step against the *host* `PATH` and hands
`execve` the canonicalised result (`BuildSandbox::resolve`). That is what makes
a toolchain installed outside `/usr` usable at all — `cargo` in a Nix profile
resolves to `/nix/store/…/bin/cargo`, and `/nix/store` is mounted.

It does not extend past that first word. Once cargo is running, *its* lookups of
`rustc` and `cc` go through the container's fixed `PATH`, which only covers
`/usr` and `/bin`. On a host whose toolchain lives under `$HOME`, cargo gets as
far as compiling build scripts and then dies:

```
error: linker `cc` not found
  |
  = note: No such file or directory (os error 2)
```

`pm.yaml` works around it without needing an environment or a shell, by naming
the binaries in cargo's own config:

```
--config target.<triple>.linker="<cc>"  --config env.CC="<cc>"  --config env.AR="<ar>"
```

On a host with `/usr/bin/cc`, none of that is necessary.
