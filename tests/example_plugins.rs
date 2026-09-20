//! Tests for the three systemd plugins in `plugins/`.
//!
//! `tests/plugins.rs` tests the *mechanism* - the sandbox, the trust path, the rules
//! that keep a plugin from widening a decision it should not. This file tests the
//! *examples*: that they classify what they claim to, refuse what they say they refuse,
//! and read a real unit file the way its author meant it.
//!
//! The commands each one classifies matter twice over. They have to be commands pm's
//! built-in table does **not** match, or the plugin is dead code that never gets asked -
//! so every command here is asserted unmatched without plugins before it is asserted
//! matched with them. That also makes this a guard: a future built-in fingerprint that
//! swallowed `systemd-tmpfiles` would turn these red rather than quietly shadowing a
//! shipped plugin.

use std::{
    fs::{copy, create_dir_all, write},
    path::{Path, PathBuf},
};

use pm::{
    bf::BuildFile,
    perms::{Permission, Provenance, source::scan_with},
    plugin::{Hook, Loader, Registry},
    policy::{BuildPolicy, Capability},
};
use tempfile::{TempDir, tempdir};

mod common;
use common::{build_file_yaml, write_build_file};

/// Where the checked-in components live.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/plugins")
        .join(format!("{name}.wasm"))
}

/// All three systemd plugins, loaded together.
///
/// Together on purpose: they are meant to be installed side by side, and loading them
/// as a set is the only way to notice two of them fighting over one command.
fn systemd_plugins() -> (TempDir, Registry) {
    let root = tempdir().expect("a temporary directory");
    let dir = root.path().join("plugins");
    create_dir_all(&dir).expect("create the plugin directory");
    for name in ["systemd", "sysext", "sysupdate"] {
        copy(fixture(name), dir.join(format!("{name}.wasm")))
            .unwrap_or_else(|error| panic!("stage the {name} fixture: {error}"));
    }
    let registry = Loader::new(dir)
        .allow_unsigned(true)
        .load()
        .expect("the three example plugins must load together");
    (root, registry)
}

/// A build file whose single step runs `command`.
fn build_file(dir: &TempDir, command: &str) -> BuildFile {
    let path = write_build_file(
        dir.path().join("build.yaml"),
        &build_file_yaml("p", &["0", "1", "0"], &[], &[command]),
    );
    BuildFile::load_unverified(&path).expect("the build file must parse")
}

/// The fingerprint and capabilities `command` is classified with, or `None` when
/// nothing classifies it.
fn classify(registry: &Registry, command: &str) -> Option<(String, Vec<Capability>)> {
    let dir = tempdir().expect("a temporary directory");
    let build = build_file(&dir, command);
    let policy = BuildPolicy::derive_with(&build, false, registry).ok()?;
    Some((
        policy.matches()[0].1.to_owned(),
        policy.capabilities().to_vec(),
    ))
}

#[test]
fn every_command_the_examples_claim_is_one_pm_would_otherwise_refuse() {
    let dir = tempdir().expect("a temporary directory");
    for command in [
        "systemctl preset foo.service",
        "systemd-tmpfiles --create --root=/dest",
        "systemd-sysusers --root=/dest",
        "systemd-analyze verify /dest/usr/lib/systemd/system/foo.service",
        "udevadm hwdb --update --root=/dest",
        "systemd-sysupdate update",
        "updatectl update",
        "systemd-repart --definitions=repart.d --empty=create foo.raw",
        "mksquashfs tree foo.raw -comp zstd",
        "mkfs.erofs foo.raw tree",
        "systemd-dissect --mtree foo.raw",
    ] {
        let build = build_file(&dir, command);
        assert!(
            BuildPolicy::derive(&build, false).is_err(),
            "`{command}` is matched by a built-in fingerprint, so the plugin claiming it \
             would never be asked"
        );
    }
}

#[test]
fn the_three_plugins_partition_the_commands_between_them() {
    let (_root, registry) = systemd_plugins();

    // Every one of these would be a plausible `systemd-*` match for a plugin matching on
    // a prefix. They match on the whole program name instead, so each command reaches
    // exactly one plugin and the order they are consulted in cannot change the answer.
    for (command, expected) in [
        ("systemctl preset foo.service", "systemd:systemctl"),
        ("systemd-tmpfiles --create", "systemd:tmpfiles"),
        ("systemd-analyze verify foo.service", "systemd:analyze"),
        ("systemd-sysupdate update", "sysupdate:sysupdate"),
        ("updatectl update", "sysupdate:updatectl"),
        ("systemd-repart --empty=create foo.raw", "sysext:repart"),
        ("systemd-sysext refresh", "sysext:sysext"),
        ("mkfs.erofs foo.raw tree", "sysext:mkfs"),
    ] {
        let (fingerprint, _) = classify(&registry, command)
            .unwrap_or_else(|| panic!("`{command}` must be classified"));
        assert_eq!(fingerprint, expected, "for `{command}`");
    }
}

#[test]
fn the_systemd_plugin_never_grants_the_network() {
    let (_root, registry) = systemd_plugins();

    let manifest = registry
        .plugins()
        .iter()
        .map(pm::plugin::Plugin::manifest)
        .find(|manifest| manifest.name == "systemd")
        .expect("the systemd plugin is loaded");
    assert_eq!(
        manifest.grants_at_most,
        [Capability::Coreutils],
        "the published ceiling is the whole claim; Network is the one capability that \
         actually changes the jail pm builds"
    );

    for command in ["systemctl preset foo.service", "systemd-tmpfiles --create"] {
        let (_, capabilities) =
            classify(&registry, command).unwrap_or_else(|| panic!("`{command}` is classified"));
        assert_eq!(capabilities, [Capability::Coreutils], "for `{command}`");
    }
}

#[test]
fn a_tool_that_runs_something_of_its_own_choosing_is_left_unclassified() {
    let (_root, registry) = systemd_plugins();

    // Refusing these is the point, not an oversight: a verdict would size a jail for a
    // container or a distribution nobody has read. pm's own diagnostic naming the
    // command is the better outcome, and `--permissive` is still there for a human who
    // has decided.
    for command in [
        "systemd-nspawn --directory=/dest /bin/sh",
        "systemd-run --scope make",
        "machinectl shell foo",
        "mkosi build",
        "debootstrap stable /dest",
    ] {
        assert!(
            classify(&registry, command).is_none(),
            "`{command}` must stay unclassified"
        );
    }
}

#[test]
fn sysupdate_grants_the_network_only_to_the_tool_that_does_the_fetching() {
    let (_root, registry) = systemd_plugins();

    let (_, fetching) = classify(&registry, "systemd-sysupdate update").expect("classified");
    assert!(
        fetching.contains(&Capability::Network),
        "systemd-sysupdate downloads in the process pm launched: {fetching:?}"
    );

    let (_, local) = classify(&registry, "systemd-sysupdate vacuum").expect("classified");
    assert!(
        !local.contains(&Capability::Network),
        "`vacuum` only deletes what is already on disk: {local:?}"
    );

    let (_, delegated) = classify(&registry, "updatectl update").expect("classified");
    assert!(
        !delegated.contains(&Capability::Network),
        "updatectl asks systemd-sysupdated over D-Bus; the command pm runs opens no \
         socket of its own: {delegated:?}"
    );
}

#[test]
fn a_unit_file_is_read_as_the_declaration_it_is() {
    let tree = tempdir().expect("a temporary directory");
    write(
        tree.path().join("foo.service"),
        "[Unit]\n\
         Description=A service\n\
         Wants=network-online.target\n\
         ConditionPathExists=/etc/foo.conf\n\
         \n\
         [Service]\n\
         Type=forking\n\
         ExecStartPre=-/usr/libexec/foo-setup\n\
         ExecStart=/usr/bin/foo --config /etc/foo.conf\n\
         EnvironmentFile=-/etc/default/foo\n\
         StateDirectory=foo\n\
         ReadWritePaths=/srv/foo \\\n\
         \x20   /srv/foo-spool\n\
         RuntimeDirectory=%N\n\
         PIDFile=/run/foo.pid\n\
         StandardOutput=append:/var/log/foo.out\n",
    )
    .expect("write the unit");

    let (_root, registry) = systemd_plugins();
    let bare = scan_with(tree.path(), Registry::none()).expect("the scan must run");
    assert!(
        bare.is_empty(),
        "pm has no grammar for a unit file on its own"
    );

    let scanned = scan_with(tree.path(), &registry).expect("the scan must run");
    let report = scanned.report();

    let reads = |path: &str| scanned.read_paths().any(|read| read == Path::new(path));
    let writes = |path: &str| scanned.write_paths().any(|write| write == Path::new(path));

    assert!(reads("/etc/foo.conf"), "ConditionPathExists=: {report}");
    assert!(
        reads("/etc/default/foo"),
        "EnvironmentFile=, `-` stripped: {report}"
    );
    assert!(
        scanned
            .exec_paths()
            .any(|exec| exec == Path::new("/usr/bin/foo")),
        "ExecStart= names the program, not the whole command line: {report}"
    );
    assert!(
        scanned
            .exec_paths()
            .any(|exec| exec == Path::new("/usr/libexec/foo-setup")),
        "ExecStartPre=, `-` stripped: {report}"
    );
    assert!(
        writes("/var/lib/foo"),
        "StateDirectory= is a name under /var/lib: {report}"
    );
    assert!(
        writes("/srv/foo"),
        "ReadWritePaths= across a continuation: {report}"
    );
    assert!(
        writes("/srv/foo-spool"),
        "the second half of the continuation: {report}"
    );
    assert!(writes("/run/foo.pid"), "PIDFile=: {report}");
    assert!(
        writes("/var/log/foo.out"),
        "StandardOutput=append:: {report}"
    );
    assert!(
        scanned.wants_network(),
        "Wants=network-online.target: {report}"
    );
    assert!(
        scanned.wants_spawn(),
        "Type=forking and ExecStartPre=: {report}"
    );

    assert!(
        !scanned
            .write_paths()
            .chain(scanned.read_paths())
            .any(|path| path.to_string_lossy().contains('%')),
        "RuntimeDirectory=%N is a specifier and names nothing until systemd expands \
         it: {report}"
    );

    let grant = scanned
        .grants()
        .iter()
        .find(|grant| *grant.permission() == Permission::WritePath("/run/foo.pid".into()))
        .expect("the PIDFile grant");
    assert_eq!(grant.provenance(), [Provenance::Plugin]);
    assert!(
        grant.evidence()[0].contains("foo.service")
            && grant.evidence()[0].contains("systemd")
            && grant.evidence()[0].contains("PIDFile"),
        "the evidence names the file, the plugin and the directive: {:?}",
        grant.evidence()
    );
}

#[test]
fn a_socket_unit_tells_a_port_from_a_path() {
    let tree = tempdir().expect("a temporary directory");
    write(
        tree.path().join("net.socket"),
        "[Socket]\nListenStream=8080\n",
    )
    .expect("write the socket unit");
    write(
        tree.path().join("local.socket"),
        "[Socket]\nListenStream=/run/local.sock\n",
    )
    .expect("write the socket unit");

    let (_root, registry) = systemd_plugins();
    let scanned = scan_with(tree.path(), &registry).expect("the scan must run");
    let report = scanned.report();

    assert!(scanned.wants_network(), "a port is the network: {report}");
    assert!(
        scanned
            .write_paths()
            .any(|path| path == Path::new("/run/local.sock")),
        "a path is a socket file the program creates, not the network: {report}"
    );
}

#[test]
fn private_network_yes_withdraws_the_network_grants_from_its_own_unit() {
    let tree = tempdir().expect("a temporary directory");
    write(
        tree.path().join("confined.service"),
        "[Unit]\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart=/usr/bin/confined\n\
         PrivateNetwork=yes\n",
    )
    .expect("write the unit");

    let (_root, registry) = systemd_plugins();
    let scanned = scan_with(tree.path(), &registry).expect("the scan must run");

    assert!(
        !scanned.wants_network(),
        "the unit denies itself the network, and that beats the positive signal in the \
         same file - the kind of negative fact a source scanner can never establish: {}",
        scanned.report()
    );
    assert!(
        scanned
            .exec_paths()
            .any(|exec| exec == Path::new("/usr/bin/confined")),
        "only the network grants are withdrawn"
    );
}

#[test]
fn a_transfer_definition_is_read_but_an_unrelated_conf_is_not() {
    let tree = tempdir().expect("a temporary directory");
    write(
        tree.path().join("50-sysext.conf"),
        "[Transfer]\n\
         ProtectVersion=%A\n\
         \n\
         [Source]\n\
         Type=url-file\n\
         Path=https://download.example.com/sysext\n\
         MatchPattern=foo_@v.raw\n\
         \n\
         [Target]\n\
         Type=regular-file\n\
         Path=/var/lib/extensions\n\
         MatchPattern=foo_@v.raw\n",
    )
    .expect("write the transfer definition");
    // Same extension, nothing to do with sysupdate. It must contribute nothing at all
    // rather than a plausible-looking guess.
    write(
        tree.path().join("logging.conf"),
        "[Logging]\nPath=/var/log/other.log\nType=url-file\n",
    )
    .expect("write the unrelated conf");

    let (_root, registry) = systemd_plugins();
    let scanned = scan_with(tree.path(), &registry).expect("the scan must run");
    let report = scanned.report();

    assert!(scanned.wants_network(), "Type=url-file fetches: {report}");
    assert!(
        scanned
            .write_paths()
            .any(|path| path == Path::new("/var/lib/extensions")),
        "the target path is written: {report}"
    );
    assert!(
        !scanned
            .read_paths()
            .any(|path| path.to_string_lossy().contains("example.com")),
        "a URL is not a path and must not be recorded as one: {report}"
    );
    assert!(
        !scanned
            .write_paths()
            .any(|path| path == Path::new("/var/log/other.log")),
        "the unrelated .conf has no [Transfer] section and must be left alone: {report}"
    );
}

#[test]
fn the_sysext_plugin_implements_one_hook_and_pm_honours_that() {
    let (_root, registry) = systemd_plugins();

    let manifest = registry
        .plugins()
        .iter()
        .map(pm::plugin::Plugin::manifest)
        .find(|manifest| manifest.name == "sysext")
        .expect("the sysext plugin is loaded");

    assert_eq!(
        manifest.hooks.iter().copied().collect::<Vec<_>>(),
        [Hook::ClassifyCommand],
        "a repart definition describes how an image is assembled, which is not what \
         scan-source asks about"
    );
    assert!(
        manifest.source_extensions.is_empty(),
        "and so it claims no file extensions"
    );
    assert!(
        !registry.wants_extension("conf") || {
            // `sysupdate` claims `.conf`; `sysext` must not be the reason.
            registry
                .plugins()
                .iter()
                .filter(|plugin| plugin.manifest().source_extensions.contains("conf"))
                .all(|plugin| plugin.manifest().name != "sysext")
        },
        "sysext must not be asked about .conf files"
    );
}
