//! Tests for plugin symbols: the `%{<plugin>:<name>}` references a build file may put
//! in a step command.
//!
//! A symbol changes **what command runs**, which is a larger power than anything else
//! in `pm::plugin` hands a plugin - classification only decides what a command is
//! allowed to reach. Two rules bound it, and most of this file is about them:
//!
//! * a symbol's value is one word, so substituting it fills in part of an argument
//!   rather than adding arguments (commands are split on whitespace with no shell);
//! * a symbol may not appear in a command's first word, so a plugin can never choose
//!   the program.
//!
//! The rest is about the substitution being *visible*: derived from the expanded
//! commands, printed by `pm explain`, and folded into the policy digest.

use std::{
    fs::{copy, create_dir_all, write},
    path::{Path, PathBuf},
};

use pm::{
    bf::BuildFile,
    plugin::{Loader, Registry},
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

/// Load `names` with signature checking off.
fn plugins(names: &[&str]) -> (TempDir, Registry) {
    let root = tempdir().expect("a temporary directory");
    let dir = root.path().join("plugins");
    create_dir_all(&dir).expect("create the plugin directory");
    for name in names {
        copy(fixture(name), dir.join(format!("{name}.wasm")))
            .unwrap_or_else(|error| panic!("stage the {name} fixture: {error}"));
    }
    let registry = Loader::new(dir)
        .allow_unsigned(true)
        .load()
        .expect("the fixtures must load");
    (root, registry)
}

/// A parsed build file whose single step runs `commands`.
fn build_file(dir: &TempDir, commands: &[&str]) -> BuildFile {
    let path = write_build_file(
        dir.path().join("build.yaml"),
        &build_file_yaml("p", &["1", "0", "0"], &[], commands),
    );
    BuildFile::load_unverified(&path).expect("the build file must parse")
}

/// A diagnostic rendered with its line wrapping flattened.
///
/// miette wraps a report to the terminal width and indents the continuation, so a
/// sentence an assertion is looking for is rarely contiguous in the raw text. Collapsing
/// runs of whitespace is what makes these assertions about the message rather than about
/// where it happened to break.
fn flattened(report: &miette::Report) -> String {
    format!("{report:?}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The commands of `build` after expansion, as pm would run them.
fn expanded(build: &BuildFile) -> Vec<String> {
    build
        .steps()
        .iter()
        .flat_map(|step| step.run.iter().cloned())
        .collect()
}

#[test]
fn a_symbol_fills_in_part_of_an_argument() {
    let dir = tempdir().expect("a temporary directory");
    let (_root, registry) = plugins(&["systemd"]);
    let mut build = build_file(
        &dir,
        &["install -Dm644 demo.service %{systemd:unitdir}/demo.service"],
    );

    let used = build.expand(&registry).expect("the symbol must resolve");

    assert_eq!(
        expanded(&build),
        ["install -Dm644 demo.service /usr/lib/systemd/system/demo.service"],
        "the reference is substituted inside the word it appeared in"
    );
    assert_eq!(
        used.into_iter().collect::<Vec<_>>(),
        ["systemd:unitdir"],
        "and the reference is reported, so `pm explain` can show it"
    );
}

#[test]
fn the_policy_is_derived_from_the_expanded_command() {
    let dir = tempdir().expect("a temporary directory");
    let (_root, registry) = plugins(&["systemd"]);
    let mut build = build_file(
        &dir,
        &["systemd-analyze verify %{systemd:unitdir}/demo.service"],
    );
    build.expand(&registry).expect("the symbol must resolve");

    let policy = BuildPolicy::derive_with(&build, false, &registry).expect("classified");
    assert_eq!(policy.matches()[0].1, "systemd:analyze");
    assert!(
        policy.matches()[0].0.contains("/usr/lib/systemd/system"),
        "the table has to show what will run, not what was written: {:?}",
        policy.matches()[0].0
    );
}

#[test]
fn a_symbol_may_not_be_the_program() {
    let dir = tempdir().expect("a temporary directory");
    let (_root, registry) = plugins(&["systemd"]);
    // Well-formed, resolvable, and still refused: the first word is what gets exec'd,
    // and a plugin choosing that is a different power from a plugin describing it.
    let mut build = build_file(&dir, &["%{systemd:unitdir}/../../bin/sh -c whatever"]);

    let report = build
        .expand(&registry)
        .expect_err("a reference in the first word must be refused");
    let text = flattened(&report);
    assert!(
        text.contains("as the program to run"),
        "the diagnostic must say what the problem is: {text}"
    );
}

#[test]
fn a_value_that_would_add_arguments_is_dropped_at_load() {
    let (_root, registry) = plugins(&["greedy"]);

    assert!(
        registry.symbol("greedy", "ok").is_some(),
        "the ordinary symbol is kept"
    );
    assert!(
        registry.symbol("greedy", "injected").is_none(),
        "a value holding whitespace would not fill in an argument, it would add \
         arguments, so pm must not offer it at all"
    );

    // And because it does not exist, a build file reaching for it fails loudly rather
    // than running a command nobody wrote.
    let dir = tempdir().expect("a temporary directory");
    let mut build = build_file(&dir, &["install -Dm644 foo %{greedy:injected}/foo"]);
    let report = build
        .expand(&registry)
        .expect_err("the symbol does not exist");
    assert!(
        flattened(&report).contains("no loaded plugin"),
        "the diagnostic must say nothing offers it"
    );
}

#[test]
fn a_well_formed_reference_to_nothing_is_an_error_rather_than_literal_text() {
    let dir = tempdir().expect("a temporary directory");
    let (_root, registry) = plugins(&["systemd"]);
    // One `r` too many. Left literal, this would install into a directory named after
    // the typo and report success.
    let mut build = build_file(&dir, &["install -Dm644 foo %{systemd:unitdirr}/foo"]);

    let report = build.expand(&registry).expect_err("a typo must not be run");
    let text = flattened(&report);
    assert!(
        text.contains("systemd:unitdirr"),
        "names the reference: {text}"
    );
    assert!(
        text.contains("systemd:unitdir"),
        "and lists what is on offer, which is where the typo shows: {text}"
    );
}

#[test]
fn text_that_is_not_shaped_like_a_reference_is_left_alone() {
    let dir = tempdir().expect("a temporary directory");
    let (_root, registry) = plugins(&["systemd"]);
    let commands = [
        // No colon: an rpm-style query format, not a reference.
        "rpm -q --queryformat %{NAME}",
        // A bare percent, and a doubled one. There is no escape character, so both are
        // exactly what they look like.
        "printf %s done",
        "printf 100%% done",
        // Unterminated.
        "echo %{systemd:unitdir",
    ];
    let mut build = build_file(&dir, &commands);

    let used = build
        .expand(&registry)
        .expect("none of these is a reference");
    assert!(used.is_empty(), "nothing was substituted: {used:?}");
    assert_eq!(
        expanded(&build),
        commands,
        "and the commands came through byte for byte"
    );
}

#[test]
fn a_reference_with_no_plugins_loaded_says_so() {
    let dir = tempdir().expect("a temporary directory");
    let mut build = build_file(&dir, &["install -Dm644 foo %{systemd:unitdir}/foo"]);

    let report = build
        .expand(Registry::none())
        .expect_err("nothing can resolve it");
    let text = flattened(&report);
    assert!(
        text.contains("no loaded plugin offers any symbols"),
        "the common mistake is not having installed the plugin, and the diagnostic \
         should say that rather than list an empty set: {text}"
    );
}

#[test]
fn expanding_nothing_leaves_a_build_file_untouched() {
    let dir = tempdir().expect("a temporary directory");
    let (_root, registry) = plugins(&["systemd"]);
    let commands = ["make", "install -Dm755 foo /dest/usr/bin/foo"];

    let mut with_plugins = build_file(&dir, &commands);
    let used = with_plugins.expand(&registry).expect("nothing to do");
    assert!(used.is_empty());
    assert_eq!(expanded(&with_plugins), commands);

    let mut without = build_file(&dir, &commands);
    without.expand(Registry::none()).expect("nothing to do");
    assert_eq!(
        BuildPolicy::derive(&without, false)
            .expect("both are built-in fingerprints")
            .fingerprint(),
        BuildPolicy::derive(&with_plugins, false)
            .expect("both are built-in fingerprints")
            .fingerprint(),
        "a build file that uses no symbols digests the same either way"
    );
}

#[test]
fn what_a_symbol_expands_to_is_part_of_the_policy_digest() {
    let dir = tempdir().expect("a temporary directory");
    let (_root, registry) = plugins(&["systemd"]);

    let mut referenced = build_file(&dir, &["install -Dm644 f %{systemd:unitdir}/f"]);
    referenced.expand(&registry).expect("resolves");
    let with_symbol = BuildPolicy::derive_with(&referenced, false, &registry).expect("derived");

    // The same command, written out by hand. The jail is identical and so is the plugin
    // set, so the only thing left to tell the two apart is the command text - which is
    // now the same, and the digests agree.
    let mut spelled_out = build_file(&dir, &["install -Dm644 f /usr/lib/systemd/system/f"]);
    spelled_out.expand(&registry).expect("nothing to do");
    let without_symbol = BuildPolicy::derive_with(&spelled_out, false, &registry).expect("derived");

    assert_eq!(
        with_symbol.fingerprint(),
        without_symbol.fingerprint(),
        "the digest covers what runs, so a reference and its value are the same build"
    );
    assert!(with_symbol.grants(Capability::Coreutils));
}

#[test]
fn a_signature_covers_the_build_file_as_written_not_as_expanded() {
    // The author signs `%{systemd:unitdir}`, not whatever that is today. Expansion
    // happens after verification, so an installed plugin cannot invalidate a signature
    // and a signature cannot pin a plugin's answer - the effective command is the
    // product of two separately signed things.
    let work = tempdir().expect("a temporary directory");
    let dir = work.path().join("plugins");
    create_dir_all(&dir).expect("create the plugin directory");
    copy(fixture("systemd"), dir.join("systemd.wasm")).expect("stage the plugin");

    let path = work.path().join("build.yaml");
    write(
        &path,
        build_file_yaml(
            "p",
            &["1", "0", "0"],
            &[],
            &["install -Dm644 f %{systemd:unitdir}/f"],
        ),
    )
    .expect("write the build file");

    let config = work.path().join("config").join("pm");
    let key = SigningKey::load_or_create(&config.join("signing.key")).expect("a signing key");
    sign_file(&path, &key).expect("sign the build file");
    let trusted = config.join("trusted");
    let mut trust = TrustStore::load(&trusted).expect("load the trust store");
    trust
        .add(&key.public_key_hex(), &trusted)
        .expect("trust the key");

    let explained = std::process::Command::new(env!("CARGO_BIN_EXE_pm"))
        .args([
            "explain",
            &path.display().to_string(),
            "--plugin-dir",
            &dir.display().to_string(),
            "--allow-unsigned-plugins",
        ])
        .current_dir(work.path())
        .env("XDG_CONFIG_HOME", work.path().join("config"))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the pm binary");

    assert!(
        explained.status.success(),
        "the signature still verifies against the file as written:\n{}",
        String::from_utf8_lossy(&explained.stderr)
    );
    let text = String::from_utf8_lossy(&explained.stdout);
    assert!(
        text.contains("/usr/lib/systemd/system/f"),
        "and the table shows the expanded command:\n{text}"
    );
    assert!(
        text.contains("systemd:unitdir"),
        "alongside the symbol that produced it:\n{text}"
    );
}

#[test]
fn the_resolver_expands_every_package_in_the_graph() {
    // `Graph::resolve` is the real build path - `pm build` never derives a policy any
    // other way - so expansion has to happen there and not only in the CLI's own copy.
    // A reference nothing offers is the cheapest proof: if resolve did not expand, it
    // would classify `%{systemd:unitdir}/f` as an ordinary argument and succeed.
    let dir = tempdir().expect("a temporary directory");
    let path = write_build_file(
        dir.path().join("build.yaml"),
        &build_file_yaml(
            "p",
            &["1", "0", "0"],
            &[],
            &["install -Dm644 f %{systemd:unitdir}/f"],
        ),
    );
    let root = BuildFile::load_unverified(&path).expect("the build file must parse");

    let report = pm::graph::Graph::resolve(&root, pm::bf::BuildOptions::default())
        .expect_err("no plugins are loaded, so the reference resolves to nothing");
    assert!(
        flattened(&report).contains("cannot expand the plugin symbols in p"),
        "resolution must fail while expanding, naming the package: {}",
        flattened(&report)
    );

    // With the plugin present it resolves, which rules out the failure above being
    // about anything other than the symbol.
    let (_keep, registry) = plugins(&["systemd"]);
    let options = pm::bf::BuildOptions {
        plugins: &registry,
        ..pm::bf::BuildOptions::default()
    };
    assert_eq!(
        pm::graph::Graph::resolve(&root, options)
            .expect("the plugin offers the symbol")
            .len(),
        1
    );
}
