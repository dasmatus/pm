//! Landlock enforcement of a package's recorded permission profile.
//!
//! Every denial test here is PAIRED with a test showing the same package
//! succeeding when the profile does grant the path. Without the pair, the suite
//! would pass just as well against a sandbox that denies everything - including
//! a broken one - and an over-tight profile that bricks every package is the
//! likeliest way this feature fails in practice.
//!
//! The probe reports through its exit code rather than stdout, so a test can
//! tell "the payload ran and was denied" apart from "the payload never ran":
//! [`BASE`] is returned unconditionally, `+1` if the allowed path was readable
//! and `+2` if the forbidden one was.

use std::fs::{create_dir_all, set_permissions, write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use pm::metadata::{Metadata, Type};
use pm::perms::{Enforcement, Grant, Permission, Permissions, Provenance};
use pm::run::PackageRunner;
use pm::signing::{SigningKey, TrustStore, sign_file};
use serde_yaml::to_string;
use tempfile::tempdir;

const PROBE: &str = r#"
#include <fcntl.h>
#include <unistd.h>

static int readable(const char *path) {
    char buf[1];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, 1);
    close(fd);
    return n >= 0;
}

int main(void) {
    int code = 40;
    if (readable(ALLOWED)) code |= 1;
    if (readable(FORBIDDEN)) code |= 2;
    return code;
}
"#;

/// Returned by the probe whatever happens, so an exit code below it means the
/// program never reached `main` - a loader failure rather than a denial.
const BASE: i32 = 40;
/// The probe could read the path its profile grants.
const ALLOWED_READ: i32 = 1;
/// The probe could read the path its profile does NOT grant.
const FORBIDDEN_READ: i32 = 2;

fn compile_probe(work: &Path, out: &Path, allowed: &str, forbidden: &str) {
    let source = work.join("probe.c");
    write(&source, PROBE).expect("write the probe source");
    let output = Command::new("cc")
        .env("NIX_DONT_SET_RPATH_x86_64_unknown_linux_gnu", "1")
        .arg(&source)
        .arg("-o")
        .arg(out)
        .arg(format!("-DALLOWED=\"{allowed}\""))
        .arg(format!("-DFORBIDDEN=\"{forbidden}\""))
        .arg("-Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2")
        .output()
        .expect("run cc");
    assert!(
        output.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sign(archive: &Path, work: &Path) {
    let key = SigningKey::load_or_create(&work.join("config").join("pm").join("signing.key"))
        .expect("create a throwaway signing key");
    sign_file(archive, &key).expect("sign the package");
    let dir = work.join("config").join("pm").join("trusted");
    let mut trust = TrustStore::load(&dir).expect("load the trust store");
    trust
        .add(&key.public_key_hex(), &dir)
        .expect("trust the throwaway key");
}

fn trust_dir(work: &Path) -> PathBuf {
    work.join("config").join("pm").join("trusted")
}

fn stage(work: &Path, name: &str, perms: Permissions, mode: Enforcement) -> PathBuf {
    let root = work.join(format!("{name}-root"));
    create_dir_all(root.join("usr/bin")).expect("package tree");
    create_dir_all(root.join("share")).expect("package tree");
    write(root.join("share/canary"), b"the package can read itself\n").expect("canary");
    compile_probe(
        work,
        &root.join("usr/bin/probe"),
        "/pkg/share/canary",
        // A REAL file, deliberately not a symlink. Landlock resolves symlinks,
        // so granting `/etc` would not grant `/etc/os-release`, which points at
        // `/usr/lib/os-release` - the test would then fail for a reason that has
        // nothing to do with enforcement.
        "/etc/hostname",
    );
    set_permissions(
        root.join("usr/bin/probe"),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("chmod");

    let metadata = Metadata::create(
        name.into(),
        vec!["0".into(), "1".into()],
        Vec::new(),
        [(PathBuf::from("usr/bin/probe"), Type::Binary)]
            .into_iter()
            .collect(),
        perms,
        mode,
    );
    write(
        root.join("metadata"),
        to_string(&metadata).expect("serialise metadata"),
    )
    .expect("write metadata");

    let archive = work.join(format!("{name}.cpkg"));
    let status = Command::new("tar")
        .arg("-cJf")
        .arg(&archive)
        .arg("-C")
        .arg(&root)
        .arg(".")
        .status()
        .expect("run tar");
    assert!(status.success());
    sign(&archive, work);
    archive
}

/// A profile granting read access to everything under `path`.
fn granting(path: &str) -> Permissions {
    Permissions::from_grants([Grant::new(
        Permission::ReadPath(PathBuf::from(path)),
        Provenance::SourceAnalysis,
        ["hand-written for the test"],
    )])
}

fn run(archive: PathBuf, work: &Path, enforce: bool) -> i32 {
    let mut runner = PackageRunner::new(archive);
    runner.trust_dir(trust_dir(work)).enforce(enforce);
    runner
        .run(Some("usr/bin/probe".into()))
        .expect("the package must run")
        .code
}

const NEEDS_KERNEL: &str = "requires landlock and unprivileged user namespaces; run with `cargo test --test landlock -- --ignored`";

#[test]
#[ignore = "requires landlock and unprivileged user namespaces; run with `cargo test --test landlock -- --ignored`"]
fn enforcing_denies_a_path_the_profile_does_not_grant() {
    let work = tempdir().expect("work dir");
    let archive = stage(
        work.path(),
        "denied",
        granting("/pkg/share"),
        Enforcement::Enforce,
    );

    let code = run(archive, work.path(), true);

    assert!(
        code >= BASE,
        "exit {code} is below {BASE}: the probe never reached main, so this proves nothing \
         about denial - the loader or an unconditional allow is broken ({NEEDS_KERNEL})"
    );
    assert_eq!(
        code & ALLOWED_READ,
        ALLOWED_READ,
        "the granted path must stay readable; exit {code}"
    );
    assert_eq!(
        code & FORBIDDEN_READ,
        0,
        "landlock did not deny the ungranted path; exit {code}. A ruleset whose `restrict` \
         never ran silently allows everything"
    );
}

#[test]
#[ignore = "requires landlock and unprivileged user namespaces; run with `cargo test --test landlock -- --ignored`"]
fn the_same_package_reads_the_path_once_the_profile_grants_it() {
    let work = tempdir().expect("work dir");
    // Identical package, wider profile: /etc is granted this time.
    let mut permissions = granting("/pkg/share");
    permissions = Permissions::merge([permissions, granting("/etc")]);
    let archive = stage(work.path(), "granted", permissions, Enforcement::Enforce);

    let code = run(archive, work.path(), true);

    assert_eq!(
        code,
        BASE | ALLOWED_READ | FORBIDDEN_READ,
        "both paths are granted now, so both must be readable; exit {code}. If this fails \
         while the denial test passes, the sandbox denies everything and the feature is \
         useless"
    );
}

#[test]
#[ignore = "requires landlock and unprivileged user namespaces; run with `cargo test --test landlock -- --ignored`"]
fn a_package_still_runs_under_enforcement() {
    let work = tempdir().expect("work dir");
    // The narrowest profile there is: nothing but the package's own data.
    let archive = stage(
        work.path(),
        "narrow",
        granting("/pkg/share"),
        Enforcement::Enforce,
    );

    let code = run(archive, work.path(), true);

    assert!(
        code >= BASE,
        "exit {code}: the program did not start. The loader and its libraries have to be \
         allowed whatever the profile says, or enforcing means nothing runs at all"
    );
}

#[test]
fn a_fresh_profile_is_never_born_enforcing() {
    let metadata = Metadata::create(
        "fresh".into(),
        vec!["1".into()],
        Vec::new(),
        std::collections::HashMap::new(),
        Permissions::default(),
        Enforcement::default(),
    );

    assert_eq!(
        metadata.enforcement(),
        Enforcement::Audit,
        "a derived profile describes only what was observed, so it must not deny until a \
         human promotes it"
    );
}

#[test]
fn metadata_without_a_profile_still_parses_and_lands_in_audit() {
    // Exactly what a package built before profiles existed carries.
    let yaml = "name: old\nversion:\n- '1'\ndependencies: []\nentrypoints: {}\n";
    let metadata: Metadata = serde_yaml::from_str(yaml).expect("old metadata must still parse");

    assert_eq!(
        metadata.enforcement(),
        Enforcement::Audit,
        "defaulting an absent profile to Enforce would brick every package built before this"
    );
    assert!(metadata.permissions().is_empty());
}

#[test]
fn promotion_flips_audit_to_enforce_and_survives_a_round_trip() {
    let mut metadata = Metadata::create(
        "promoted".into(),
        vec!["1".into()],
        Vec::new(),
        std::collections::HashMap::new(),
        granting("/etc"),
        Enforcement::Audit,
    );
    assert_eq!(metadata.enforcement(), Enforcement::Audit);

    metadata.promote();
    assert_eq!(metadata.enforcement(), Enforcement::Enforce);

    let yaml = to_string(&metadata).expect("serialise");
    let parsed: Metadata = serde_yaml::from_str(&yaml).expect("deserialise");
    assert_eq!(parsed.enforcement(), Enforcement::Enforce);
    assert_eq!(parsed.permissions().grants().len(), 1);
}
