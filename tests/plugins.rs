//! Tests for [`pm::plugin`]: what a WebAssembly plugin may do to a build, and the far
//! longer list of what it may not.
//!
//! Every component these tests load is a real one, built from `plugins/` by
//! `plugins/build.sh` and checked in under `tests/fixtures/plugins/`. They are checked
//! in rather than built here on purpose: `cargo test` then needs no `wasm32` target, no
//! `wit-bindgen` and no second compile, and the thing under test is the same artefact a
//! user would install.
//!
//! The fixtures are deliberately badly behaved, because the interesting claims are about
//! misbehaviour. `greedy` asks for more than it published, `runaway` never returns,
//! `nameless` cannot be attributed, and `toy` contributes run-time grants from a file
//! type pm has no grammar for.

use std::{
    fs::{copy, create_dir_all, write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use pm::{
    bf::BuildFile,
    perms::{Permission, Provenance, source::scan_with},
    plugin::{Hook, Loader, Registry, Trust},
    policy::{BuildPolicy, Capability},
    signing::{SigningKey, TrustStore, sign_file},
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

/// A plugin directory holding `names`, and the temporary directory keeping it alive.
fn plugin_dir(names: &[&str]) -> (TempDir, PathBuf) {
    let root = tempdir().expect("a temporary directory");
    let dir = root.path().join("plugins");
    create_dir_all(&dir).expect("create the plugin directory");
    for name in names {
        copy(fixture(name), dir.join(format!("{name}.wasm")))
            .unwrap_or_else(|error| panic!("stage the {name} fixture: {error}"));
    }
    (root, dir)
}

/// Load `names` with signature checking turned off, which is what most of these tests
/// want: signing is exercised on its own below.
fn unsigned(names: &[&str]) -> (TempDir, Registry) {
    let (root, dir) = plugin_dir(names);
    let registry = Loader::new(dir)
        .allow_unsigned(true)
        .load()
        .expect("the fixtures must load");
    (root, registry)
}

/// A build file whose single step runs `commands`, parsed but never signed.
fn build_file(dir: &TempDir, commands: &[&str]) -> BuildFile {
    let path = write_build_file(
        dir.path().join("build.yaml"),
        &build_file_yaml("p", &["0", "1", "0"], &[], commands),
    );
    BuildFile::load_unverified(&path).expect("the build file must parse")
}

#[test]
fn a_plugin_describes_itself_and_pm_holds_it_to_the_description() {
    let (_root, registry) = unsigned(&["zig"]);

    assert_eq!(registry.len(), 1);
    let manifest = registry.plugins()[0].manifest();
    assert_eq!(manifest.name, "zig");
    assert_eq!(
        manifest.hooks.iter().copied().collect::<Vec<_>>(),
        vec![Hook::ClassifyCommand, Hook::ScanSource],
        "the reference plugin implements both hooks"
    );
    assert!(
        manifest.grants_at_most.contains(&Capability::Toolchain)
            && manifest.grants_at_most.contains(&Capability::Network)
            && !manifest.grants_at_most.contains(&Capability::Shell),
        "the published ceiling is what the plugin declared, no more: {:?}",
        manifest.grants_at_most
    );
    assert!(manifest.source_extensions.contains("zig"));
    assert_eq!(registry.plugins()[0].trust(), Trust::Unverified);
}

#[test]
fn a_plugin_classifies_a_command_the_built_in_table_refuses() {
    let dir = tempdir().expect("a temporary directory");
    let build = build_file(&dir, &["zig build -Doptimize=ReleaseSafe"]);

    // Without the plugin this build file cannot be built at all.
    let refused = BuildPolicy::derive(&build, false);
    assert!(
        refused.is_err(),
        "pm's own table does not know zig, so a strict derivation must refuse it"
    );

    let (_root, registry) = unsigned(&["zig"]);
    let policy = BuildPolicy::derive_with(&build, false, &registry)
        .expect("the plugin must classify the command");

    assert_eq!(
        policy.matches()[0].1,
        "zig:zig",
        "a plugin's fingerprint is recorded under the plugin's own name"
    );
    assert!(policy.grants(Capability::Toolchain));
    assert!(
        policy.grants(Capability::Network),
        "`zig build` resolves build.zig.zon dependencies"
    );
}

#[test]
fn a_plugin_is_never_asked_about_a_command_the_built_in_table_knows() {
    let dir = tempdir().expect("a temporary directory");
    // `greedy` would claim this command and demand Network and Shell for it - but
    // `cargo` matches a built-in fingerprint, so `greedy` is never consulted.
    let build = build_file(&dir, &["greedy cargo build"]);
    let with_builtin = build_file(&dir, &["cargo build"]);

    let (_root, registry) = unsigned(&["greedy"]);

    let hijacked = BuildPolicy::derive_with(&with_builtin, false, &registry)
        .expect("cargo is a built-in fingerprint");
    assert_eq!(
        hijacked.matches()[0].1,
        "cargo",
        "the built-in table wins outright; a plugin cannot reclassify what pm knows"
    );
    assert!(!hijacked.grants(Capability::Shell));

    // And the plugin still works for the command the table does not match, so the test
    // above is not passing merely because the plugin is broken.
    let claimed =
        BuildPolicy::derive_with(&build, false, &registry).expect("greedy claims its own command");
    assert_eq!(claimed.matches()[0].1, "greedy:greedy");
}

#[test]
fn a_verdict_is_held_to_the_ceiling_the_plugin_published() {
    let dir = tempdir().expect("a temporary directory");
    let build = build_file(&dir, &["greedy something"]);
    let (_root, registry) = unsigned(&["greedy"]);

    let policy =
        BuildPolicy::derive_with(&build, false, &registry).expect("greedy classifies its command");

    assert!(
        policy.grants(Capability::Toolchain),
        "the one capability greedy published a ceiling for survives"
    );
    assert_eq!(
        policy.capabilities(),
        [Capability::Toolchain],
        "Network and Shell were asked for and dropped: {:?}",
        policy.capabilities()
    );
}

#[test]
fn a_plugin_that_never_returns_is_cut_off_rather_than_allowed_to_hang() {
    let dir = tempdir().expect("a temporary directory");
    let build = build_file(&dir, &["anything at all"]);
    let (_root, registry) = unsigned(&["runaway"]);

    let started = Instant::now();
    let refused = BuildPolicy::derive_with(&build, false, &registry);
    let took = started.elapsed();

    assert!(
        refused.is_err(),
        "the plugin produced no verdict, so the command is still unclassified"
    );
    assert!(
        took < Duration::from_secs(60),
        "the fuel budget must stop the loop; it took {took:?}"
    );
}

#[test]
fn a_plugin_with_no_usable_name_is_refused_at_load() {
    let (_root, dir) = plugin_dir(&["nameless"]);
    let refused = Loader::new(dir).allow_unsigned(true).load();

    let report = refused.expect_err("a plugin nothing can be attributed to must not load");
    let text = format!("{report:?}");
    assert!(
        text.contains("not a usable name"),
        "the diagnostic must say what is wrong with it: {text}"
    );
}

#[test]
fn two_plugins_cannot_share_one_name() {
    let (_root, dir) = plugin_dir(&["greedy"]);
    copy(fixture("greedy"), dir.join("also-greedy.wasm")).expect("stage a second copy");

    let refused = Loader::new(dir).allow_unsigned(true).load();
    let report = refused.expect_err("one name, one plugin");
    assert!(
        format!("{report:?}").contains("both call themselves"),
        "the diagnostic must name the clash"
    );
}

#[test]
fn a_plugin_that_wants_more_of_the_host_than_log_does_not_instantiate() {
    let (_root, dir) = plugin_dir(&["wasi"]);
    let refused = Loader::new(dir).allow_unsigned(true).load();

    let report = refused.expect_err(
        "the linker defines `log` and nothing else, so a component wanting WASI cannot \
         be instantiated",
    );
    let text = format!("{report:?}");
    assert!(
        text.contains("wasi:"),
        "the diagnostic must name the import that was not there: {text}"
    );

    // This is the sandbox claim stated as a test. The fixture exports the world
    // correctly and only fails because it also reads a file and an environment
    // variable; if a second `add_to_linker` is ever added to `src/plugin/engine.rs`,
    // this starts loading and the assertion above goes red.
}

#[test]
fn a_file_that_is_not_a_component_is_refused() {
    let root = tempdir().expect("a temporary directory");
    let dir = root.path().join("plugins");
    create_dir_all(&dir).expect("create the plugin directory");
    write(dir.join("junk.wasm"), b"not a wasm module at all").expect("write the junk");

    let refused = Loader::new(dir).allow_unsigned(true).load();
    assert!(
        refused.is_err(),
        "a plugin directory holding something unloadable is a configuration error, \
         not something to skip quietly"
    );
}

#[test]
fn an_unsigned_plugin_does_not_load_without_the_escape_hatch() {
    let (root, dir) = plugin_dir(&["zig"]);
    let trust = root.path().join("trusted");
    create_dir_all(&trust).expect("create the trust store");

    let refused = Loader::new(dir.clone()).trust_dir(trust.clone()).load();
    let report = refused.expect_err("a plugin runs inside pm; it has to be signed");
    assert!(
        format!("{report:?}").contains("signature"),
        "the diagnostic must say the signature is the problem"
    );

    // The same directory loads once the escape hatch is given, so the failure above is
    // about the signature and not about the component.
    assert_eq!(
        Loader::new(dir)
            .allow_unsigned(true)
            .load()
            .expect("the component itself is fine")
            .len(),
        1
    );
}

#[test]
fn a_signed_plugin_loads_and_says_so() {
    let (root, dir) = plugin_dir(&["zig"]);
    let trust = root.path().join("trusted");
    create_dir_all(&trust).expect("create the trust store");

    let key = SigningKey::load_or_create(&root.path().join("signing.key")).expect("a signing key");
    let mut store = TrustStore::load(&trust).expect("an empty trust store");
    store
        .add(&key.public_key_hex(), &trust)
        .expect("trust our own key");
    sign_file(&dir.join("zig.wasm"), &key).expect("sign the plugin");

    let registry = Loader::new(dir)
        .trust_dir(trust)
        .load()
        .expect("a signed plugin must load");

    assert_eq!(registry.len(), 1);
    assert_eq!(registry.plugins()[0].trust(), Trust::Signed);
}

#[test]
fn a_plugin_contributes_run_time_grants_that_say_who_asked() {
    let tree = tempdir().expect("a temporary directory");
    write(
        tree.path().join("config.toy"),
        "read /etc/toy.conf\nwrite /var/log/toy.log\nnetwork\n",
    )
    .expect("write the toy file");

    // Nothing in pm has a grammar for `.toy`, so without the plugin the file is not
    // even collected.
    let bare = scan_with(tree.path(), Registry::none()).expect("the scan must run");
    assert!(bare.is_empty(), "pm knows nothing about .toy on its own");

    let (_root, registry) = unsigned(&["scanner"]);
    let scanned = scan_with(tree.path(), &registry).expect("the scan must run");

    assert!(scanned.wants_network(), "the `network` directive was read");
    assert!(
        scanned
            .read_paths()
            .any(|path| path == Path::new("/etc/toy.conf")),
        "the `read` directive was read: {}",
        scanned.report()
    );

    let grant = scanned
        .grants()
        .iter()
        .find(|grant| *grant.permission() == Permission::WritePath("/var/log/toy.log".into()))
        .expect("the `write` directive was read");
    assert_eq!(grant.provenance(), [Provenance::Plugin]);
    assert!(
        grant.evidence()[0].contains("config.toy") && grant.evidence()[0].contains("toy"),
        "the evidence must name the file and the plugin that asked: {:?}",
        grant.evidence()
    );
}

#[test]
fn a_plugin_that_traps_costs_its_own_grants_and_nothing_else() {
    let tree = tempdir().expect("a temporary directory");
    write(tree.path().join("a.runaway"), "anything").expect("write the file");
    write(
        tree.path().join("b.c"),
        "#include <stdio.h>\nint main(void){ FILE *f = fopen(\"/etc/hosts\", \"r\"); return !f; }\n",
    )
    .expect("write the C file");

    let (_root, registry) = unsigned(&["runaway"]);
    let scanned =
        scan_with(tree.path(), &registry).expect("a trapping plugin must not fail the scan");

    assert!(
        scanned
            .read_paths()
            .any(|path| path == Path::new("/etc/hosts")),
        "the built-in C scanner still ran: {}",
        scanned.report()
    );
}

#[test]
fn the_plugin_set_is_part_of_the_policy_digest() {
    let dir = tempdir().expect("a temporary directory");
    let build = build_file(&dir, &["make"]);

    let bare = BuildPolicy::derive(&build, false).expect("make is a built-in fingerprint");
    let (_root, registry) = unsigned(&["zig"]);
    let with_plugin =
        BuildPolicy::derive_with(&build, false, &registry).expect("nothing changed about the file");

    assert_eq!(
        bare.capabilities(),
        with_plugin.capabilities(),
        "the plugin was not consulted, so it cannot have changed the capabilities"
    );
    assert_ne!(
        bare.fingerprint(),
        with_plugin.fingerprint(),
        "but the jail was configured under a different plugin set, and the digest has \
         to say so"
    );
}

#[test]
fn an_empty_registry_digests_a_build_file_exactly_as_a_pm_without_plugins_would() {
    let dir = tempdir().expect("a temporary directory");
    let build = build_file(&dir, &["make"]);

    let (_root, empty) = unsigned(&[]);
    assert!(empty.is_empty());
    assert_eq!(empty.digest(), "");
    assert_eq!(
        BuildPolicy::derive(&build, false)
            .expect("make is a built-in fingerprint")
            .fingerprint(),
        BuildPolicy::derive_with(&build, false, &empty)
            .expect("make is still a built-in fingerprint")
            .fingerprint(),
        "installing no plugins must not move a single digest"
    );
}

#[test]
fn a_missing_plugin_directory_is_no_plugins_rather_than_an_error() {
    let root = tempdir().expect("a temporary directory");
    let registry = Loader::new(root.path().join("nothing-here"))
        .load()
        .expect("not having installed any plugins is the normal state");
    assert!(registry.is_empty());
}

#[test]
fn only_wasm_files_in_the_plugin_directory_are_read() {
    let (_root, dir) = plugin_dir(&["zig"]);
    write(dir.join("README"), "notes about my plugins").expect("write the README");
    write(dir.join("zig.wasm.sig"), "a signature file").expect("write a stray sig");
    create_dir_all(dir.join("sources")).expect("create a subdirectory");
    write(dir.join("sources/other.wasm"), b"junk").expect("write a nested component");

    let registry = Loader::new(dir)
        .allow_unsigned(true)
        .load()
        .expect("the directory holds exactly one plugin");
    assert_eq!(registry.len(), 1);
}

#[test]
fn plugins_are_consulted_in_a_deterministic_order() {
    // Staged in the opposite order to the one they must come back in, so the assertion
    // cannot pass merely because the directory happened to hand them back as created.
    // The order decides which plugin's verdict wins a command both would claim, and a
    // policy digest that depends on a directory's iteration order is not reproducible.
    let root = tempdir().expect("a temporary directory");
    let dir = root.path().join("plugins");
    create_dir_all(&dir).expect("create the plugin directory");
    copy(fixture("zig"), dir.join("zig.wasm")).expect("stage zig first");
    copy(fixture("scanner"), dir.join("aaa-toy.wasm")).expect("stage toy second");

    let registry = Loader::new(dir)
        .allow_unsigned(true)
        .load()
        .expect("both fixtures must load");
    assert_eq!(
        registry
            .plugins()
            .iter()
            .map(|plugin| plugin.manifest().name.as_str())
            .collect::<Vec<_>>(),
        ["toy", "zig"],
        "load order follows the sorted file names, not the directory's own"
    );
}

#[test]
fn the_reference_plugin_respects_word_boundaries_the_way_the_built_in_table_does() {
    let dir = tempdir().expect("a temporary directory");
    let (_root, registry) = unsigned(&["zig"]);

    // `zigzag` and `myzig` are not `zig`, for the same reason `evilmake` is not `make`:
    // the program name has to end where the pattern says it does.
    for command in ["zigzag build", "myzig build", "zig", "zig nonsense"] {
        let build = build_file(&dir, &[command]);
        assert!(
            BuildPolicy::derive_with(&build, false, &registry).is_err(),
            "`{command}` must not be classified as zig"
        );
    }

    // A leading path is still the same program, again matching the built-in table.
    for command in ["/opt/zig/zig build-exe main.zig", "./zig test main.zig"] {
        let build = build_file(&dir, &[command]);
        let policy = BuildPolicy::derive_with(&build, false, &registry)
            .unwrap_or_else(|error| panic!("`{command}` must be classified: {error:?}"));
        assert_eq!(policy.matches()[0].1, "zig:zig");
        assert!(
            !policy.grants(Capability::Network),
            "`{command}` compiles, it does not resolve dependencies"
        );
    }
}

#[test]
fn the_reference_plugin_reads_zig_sources_but_not_their_comments() {
    let tree = tempdir().expect("a temporary directory");
    write(
        tree.path().join("main.zig"),
        r#"const std = @import("std");

pub fn main() !void {
    // std.net would be reached here if this were not a comment.
    const message = "std.http is only mentioned in this string";
    const file = try std.fs.cwd().openFile("/etc/zig.conf", .{});
    _ = message;
    _ = file;
}
"#,
    )
    .expect("write the zig source");

    let (_root, registry) = unsigned(&["zig"]);
    let scanned = scan_with(tree.path(), &registry).expect("the scan must run");

    assert!(
        scanned
            .read_paths()
            .any(|path| path == Path::new("/etc/zig.conf")),
        "the openFile literal is a read: {}",
        scanned.report()
    );
    assert!(
        !scanned.wants_network(),
        "a `std.net` in a comment and a `std.http` in a string are not calls: {}",
        scanned.report()
    );
}

#[test]
fn pm_plugins_lists_what_is_installed_and_pm_explain_names_it() {
    let (root, dir) = plugin_dir(&["zig"]);
    let work = root.path();

    let listed = pm(
        &[
            "plugins",
            "--digests",
            "--plugin-dir",
            &dir.display().to_string(),
            "--allow-unsigned-plugins",
        ],
        work,
    );
    assert!(listed.status.success(), "pm plugins must succeed");
    let text = String::from_utf8_lossy(&listed.stdout);
    for expected in [
        "zig",
        "classify-command",
        "scan-source",
        "Toolchain",
        ".zig",
    ] {
        assert!(
            text.contains(expected),
            "`pm plugins` must report {expected}:\n{text}"
        );
    }

    // And the same set has to show up wherever a policy it shaped is printed, or a
    // digest is unattributable.
    let path = signed_build_file(work, "zig build");
    let explained = pm(
        &[
            "explain",
            &path.display().to_string(),
            "--plugin-dir",
            &dir.display().to_string(),
            "--allow-unsigned-plugins",
        ],
        work,
    );
    assert!(
        explained.status.success(),
        "pm explain must classify the command through the plugin:\n{}",
        String::from_utf8_lossy(&explained.stderr)
    );
    let text = String::from_utf8_lossy(&explained.stdout);
    assert!(
        text.contains("zig:zig"),
        "the table must name the plugin:\n{text}"
    );
    assert!(
        text.contains("plugins:"),
        "the header must name the plugin set:\n{text}"
    );

    // `--no-plugins` puts pm back exactly where it was before any of this existed.
    let bare = pm(
        &[
            "explain",
            &path.display().to_string(),
            "--no-plugins",
            "--plugin-dir",
            &dir.display().to_string(),
        ],
        work,
    );
    assert!(
        !bare.status.success(),
        "without the plugin, `zig build` matches nothing and explain is a failing lint"
    );
}

#[test]
fn pm_plugins_says_so_when_there_are_none() {
    let root = tempdir().expect("a temporary directory");
    let listed = pm(&["plugins", "--no-plugins"], root.path());
    assert!(listed.status.success());
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("No plugins are loaded."),
        "an empty registry is reported, not left to be inferred from an empty table"
    );
}

/// Runs the real `pm` binary from inside `work`, with its config directory there too.
fn pm(args: &[&str], work: &Path) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(args)
        .current_dir(work)
        .env("XDG_CONFIG_HOME", work.join("config"))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the pm binary")
}

/// Writes a build file running `command`, signs it and trusts the key, so the binary
/// under test gets as far as deriving a policy.
fn signed_build_file(work: &Path, command: &str) -> PathBuf {
    let path = work.join("build.yaml");
    write(
        &path,
        build_file_yaml("p", &["0", "1", "0"], &[], &[command]),
    )
    .expect("write the build file");

    let config = work.join("config").join("pm");
    let key = SigningKey::load_or_create(&config.join("signing.key")).expect("a signing key");
    sign_file(&path, &key).expect("sign the build file");
    let trusted = config.join("trusted");
    let mut trust = TrustStore::load(&trusted).expect("load the trust store");
    trust
        .add(&key.public_key_hex(), &trusted)
        .expect("trust the key");
    path
}
