#!/usr/bin/env bash
#
# End-to-end demonstration of pm's two confinement layers.
#
# Builds the whole example chain -- 01-seed -> 02-lib -> 03-app -> pm -- and
# then shows, with real commands and real output, that:
#
#   1. a build step is confined to /build and /dest and cannot see $HOME,
#      /root, /var or the host /tmp (the build jail, hakoniwa) -- shown against
#      an `--unsandboxed` control, the same build file with the jail removed,
#      so the probes are measuring confinement and not the host they run on;
#   2. a build step cannot write to the read-only mount it was described by;
#   3. a packaged program is confined to the profile inferred for it at build
#      time (the run jail, landlock).
#
# Nothing here touches your real pm key or trust store: XDG_CONFIG_HOME is
# pointed at examples/.demo-config, which this script owns.
#
# Usage:  bash examples/demo.sh
set -uo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$HERE/.." && pwd)
OUT="$REPO/out"
PM="$REPO/target/release/pm"
DECOY=/tmp/pm-confinement-decoy

export XDG_CONFIG_HOME="$HERE/.demo-config"

bold=$'\033[1m'; dim=$'\033[2m'; red=$'\033[31m'; green=$'\033[32m'; off=$'\033[0m'

step() { printf '\n%s========================================================================%s\n%s%s%s\n\n' "$dim" "$off" "$bold" "$*" "$off"; }
note() { printf '%s-- %s%s\n' "$dim" "$*" "$off"; }
fail() { printf '%sFAILED: %s%s\n' "$red" "$*" "$off"; exit 1; }

# pm runs from out/ throughout. Dependency paths inside a build file are
# resolved against the PROCESS working directory, not the build file's own
# directory, which is why every dependency in examples/ is spelled
# ../examples/... -- it is relative to here. See BuildFile::build_dependency.
pm() { ( cd "$OUT" && "$PM" "$@" ); }

# ---------------------------------------------------------------------------
step "0. Build pm on the host"
# ---------------------------------------------------------------------------
# The chicken-and-egg step: something has to run the first build. After this,
# pm builds pm.
( cd "$REPO" && cargo build --release ) || fail "host cargo build"
note "using $PM"

mkdir -p "$OUT"
rm -f "$OUT"/*.cpkg "$OUT"/*.sig

# pm puts every build workspace under TMPDIR (Workspace::new), and compiling
# pm's own dependency graph in release mode needs several GB of it. On a distro
# where /tmp is a tmpfs -- the Fedora default, and 7.5G here, shared with
# everything else on the machine -- that is not a safe place for it: the build
# dies partway through aws-lc-sys with "Disk quota exceeded (os error 122)".
# Point it at real disk instead. out/ is gitignored, so this cleans up with the
# rest of the demo.
export TMPDIR="$OUT/tmp"
mkdir -p "$TMPDIR"
note "build workspaces go in $TMPDIR"

# ---------------------------------------------------------------------------
step "1. Plant a decoy on the host, where the build jail must not find it"
# ---------------------------------------------------------------------------
# Inside the jail /tmp is a fresh tmpfs, not the host's, so this file proves
# the host /tmp is not reachable from a build step. Build workspaces are each
# bind-mounted individually at /build, never by way of their parent, so a
# sibling build's tree is not reachable either.
mkdir -p "$DECOY"
printf 'If a pm build step can read this, the build jail is not confining it.\n' > "$DECOY/secret.txt"
note "planted $DECOY/secret.txt"

# ---------------------------------------------------------------------------
step "2. Generate a throwaway signing key"
# ---------------------------------------------------------------------------
# pm build verifies a detached <FILE>.sig BEFORE it parses the build file, and
# every dependency is held to the same standard all the way down
# (BuildFile::load, then BuildFile::build_dependency for each one below it). A
# build file names the commands that will run, so reading an unsigned one is
# already the interesting half of running it.
rm -rf "$XDG_CONFIG_HOME"
pm keygen || fail "keygen"

# ---------------------------------------------------------------------------
step "3. Generate pm.yaml from pm.yaml.in"
# ---------------------------------------------------------------------------
# A build file has no $srcdir. Commands run with the working directory at
# /build, and the only host directory mounted is the build file's OWN
# directory, at its own absolute path -- so anything referring to the source
# tree or to the toolchain has to spell an absolute path. The three example
# build files avoid this entirely and are committed verbatim; only pm's own
# build file needs it, so only it is a template.
TRIPLE=$(rustc -vV | awk '/^host:/ {print $2}')
CC_PATH=$(readlink -f "$(command -v cc)")
AR_PATH=$(readlink -f "$(command -v ar)")
note "srcdir  $REPO"
note "home    $HOME"
note "triple  $TRIPLE"
note "cc      $CC_PATH"
note "ar      $AR_PATH"

sed -e "s#@SRCDIR@#$REPO#g" \
    -e "s#@HOME@#$HOME#g" \
    -e "s#@TRIPLE@#$TRIPLE#g" \
    -e "s#@CC@#$CC_PATH#g" \
    -e "s#@AR@#$AR_PATH#g" \
    "$REPO/pm.yaml.in" > "$REPO/pm.yaml" || fail "generating pm.yaml"

# ---------------------------------------------------------------------------
step "4. Sign every build file in the chain"
# ---------------------------------------------------------------------------
for f in ../examples/01-seed/build.yaml \
         ../examples/02-lib/build.yaml \
         ../examples/03-app/build.yaml \
         ../pm.yaml; do
  pm sign "$f" || fail "signing $f"
done

# ---------------------------------------------------------------------------
step "5. What each build file is allowed to do, before anything runs"
# ---------------------------------------------------------------------------
# The sandbox policy is DERIVED, never declared: each step command is matched
# against a built-in fingerprint table, and a command matching nothing aborts
# the build before a single step runs. See the module doc of src/policy.rs.
# Note that only pm gets Network, and it gets it because `cargo` is in the
# table as a program that resolves and downloads its own dependency graph.
for f in ../examples/01-seed/build.yaml \
         ../examples/02-lib/build.yaml \
         ../examples/03-app/build.yaml \
         ../pm.yaml; do
  pm explain "$f" || fail "explain $f"
  printf '\n'
done

# ---------------------------------------------------------------------------
step "6. The same build file, with the jail switched off"
# ---------------------------------------------------------------------------
# `--unsandboxed` runs the identical steps on the host instead of inside the
# jail. Nothing else changes: same build file, same signature, same commands,
# same derived policy, same pm. So whatever differs between this run and
# step 7 is confinement, and nothing else -- which is what makes this a
# controlled comparison rather than an anecdote about the host.
#
# 01-seed's `confine` step asserts the shape of the jail, so with the jail
# gone those assertions have to stop holding. The build aborts on the first
# one it reaches: /build is where the working directory is mounted INSIDE the
# container, and unconfined there is no such path. The probes it never reaches
# are listed in full by step 5's `pm explain` output.
#
# Two things in the log are worth reading. `BUILD SANDBOX DISABLED` and the
# per-command `running a build command UNSANDBOXED on the host` lines are pm
# saying it has handed the build file the calling user's own privileges.
if pm build --unsandboxed ../examples/01-seed/build.yaml; then
  fail "the unsandboxed build SUCCEEDED, so the confine step is not asserting confinement"
fi
printf '\n%sThe unconfined build failed its first confinement probe, which is the correct outcome.%s\n' "$green" "$off"
note "step 7 runs this exact file again, jailed, and every probe passes"

# ---------------------------------------------------------------------------
step "7. Build the chain: 01-seed -> 02-lib -> 03-app -> pm"
# ---------------------------------------------------------------------------
# One command builds all four. Dependencies are built depth-first and
# sequentially, with a visiting stack that rejects cycles and a memo map so a
# diamond builds once, all of it in BuildFile::build_dependency. pm itself is
# compiled from source by cargo, inside the same jail every other package got.
#
# This downloads and compiles pm's entire dependency graph, so it takes a few
# minutes. CARGO_HOME is /build/.cargo -- inside the workspace -- so the cache
# is per-build and goes away with it.
pm build ../pm.yaml || fail "building the chain"

note "archives produced:"
ls -1 "$OUT"/*.cpkg

# ---------------------------------------------------------------------------
step "8. A build step cannot write to the tree it was described by"
# ---------------------------------------------------------------------------
# The build file's own directory is mounted READ-ONLY, because a build writes
# into its working directory and into DESTDIR, not back into its source
# (BuildFile::read_only_mounts). This build file is deliberately kept out of examples/ so
# the committed chain stays green; it is expected to FAIL, and the failure is
# the demonstration.
ESC="$OUT/escape"
mkdir -p "$ESC"
cat > "$ESC/escape.yaml" <<YAML
name: escape
version:
- '0'
dependencies: []
steps:
- stage: Build
  dl_urls: null
  name: write-back
  run:
  - touch $ESC/escaped
YAML
pm sign escape/escape.yaml || fail "signing the escape build file"
if pm build escape/escape.yaml; then
  fail "the escape build SUCCEEDED -- the read-only mount is not read-only"
fi
printf '\n%sThe build failed, which is the correct outcome.%s\n' "$green" "$off"
test ! -e "$ESC/escaped" || fail "the escape build created $ESC/escaped"
note "confirmed: $ESC/escaped does not exist"

# ---------------------------------------------------------------------------
step "9. The run-time profile pm inferred for 03-app"
# ---------------------------------------------------------------------------
# A second, completely separate profile from the build policy. It is derived
# AFTER the steps run, from tree-sitter analysis of the sources and the ELF
# headers of each staged entrypoint -- never from anything the build file
# asked for. pm run and pm profile both verify the archive's signature.
pm sign app-0.1.0.cpkg || fail "signing app"
pm sign pm-0.1.0.cpkg  || fail "signing pm"
pm profile app-0.1.0.cpkg || fail "profile app"

# ---------------------------------------------------------------------------
step "10. Run jail: same package, same ruleset, two entrypoints"
# ---------------------------------------------------------------------------
# 03-app stages two binaries. usr/bin/hello is a copy of /usr/bin/echo and
# lives entirely inside the profile above. usr/bin/leak is a copy of
# /usr/bin/whoami, which reads /etc/passwd -- something neither ELF analysis
# nor source analysis could have known about, so it is NOT in the profile.
#
# The profile is recorded in audit mode, so by default neither is denied.

note "10a. unenforced -- the profile denies nothing, so leak reads /etc/passwd"
pm run app-0.1.0.cpkg --bin usr/bin/leak || fail "unenforced leak should succeed"

note "10b. --audit -- what enforcing the profile WOULD break"
pm run app-0.1.0.cpkg --bin usr/bin/leak --audit || fail "audit"

note "10c. --enforce on the in-profile entrypoint: still works"
pm run app-0.1.0.cpkg --bin usr/bin/hello --enforce \
  || fail "enforced hello should succeed -- a sandbox that denies everything is useless"

note "10d. --enforce on the out-of-profile entrypoint: landlock denies the read"
if pm run app-0.1.0.cpkg --bin usr/bin/leak --enforce; then
  fail "enforced leak SUCCEEDED -- the landlock ruleset is not being applied"
fi
printf '\n%sDenied, which is the correct outcome.%s\n' "$green" "$off"

# ---------------------------------------------------------------------------
step "11. pm, confined by pm"
# ---------------------------------------------------------------------------
# The binary pm just built, run out of its own package, inside the run jail.
# It exits 2 because clap prints help when given no arguments -- pm run
# forwards none -- and that exit code is reported faithfully.
pm run pm-0.1.0.cpkg --bin usr/bin/pm
printf '\n%s(exit 2 above is clap asking for a subcommand, not a sandbox failure.)%s\n' "$dim" "$off"

step "Done."
note "archives, signatures and the generated pm.yaml are gitignored"
note "remove the demo key with: rm -rf $XDG_CONFIG_HOME"
note "remove the decoy with:    rm -rf $DECOY"
# Steps 6 and 8 are meant to fail, and pm deliberately retains the workspace of
# a failed build so the half-finished tree can be inspected. See
# BuildFile::run_tracked. Those land under TMPDIR, which is out/tmp here, so
# removing out/ takes them with it.
note "two builds here fail on purpose; pm kept their workspaces under $TMPDIR"
note "remove everything with: rm -rf $OUT"
