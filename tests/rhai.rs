//! Behavioural tests for Rhai (`.rhai`) recipes and `pm migrate`.

use std::{
    fs::{create_dir_all, read_to_string, write},
    path::Path,
    process::{Command, Stdio},
};

use pm::{bf::BuildFile, migrate, recipe, star};
use tempfile::tempdir;

fn eval(text: &str) -> miette::Result<BuildFile> {
    recipe::parse("test.rhai", text.to_owned())
}

fn json(build: &BuildFile) -> serde_json::Value {
    serde_json::to_value(build).expect("a build file serialises")
}

fn error(text: &str) -> String {
    let Err(error) = recipe::evaluate(text) else {
        panic!("{text} must not evaluate");
    };
    error.to_string()
}

#[test]
fn a_minimal_package_evaluates() {
    let build = eval(r#"package(#{ name: "hello", version: "1.2.3" });"#).expect("evaluates");
    assert_eq!(build.name(), "hello");
    assert_eq!(build.version(), ["1", "2", "3"]);
    assert_eq!(build.version_string(), "1.2.3");
    assert_eq!(build.dependencies().len(), 0);
    assert!(build.steps().is_empty());
}

#[test]
fn version_may_be_an_array() {
    let build = eval(r#"package(#{ name: "p", version: ["2", "0"] })"#).expect("evaluates");
    assert_eq!(build.version_string(), "2.0");
}

#[test]
fn steps_can_be_generated_with_loops_and_functions() {
    let build = eval(
        r#"
// Functions cannot see the caller's variables, but the stage constants are
// builtins and work everywhere.
fn probe(path) {
    step(Prepare, "probe " + path, ["test -e " + path])
}

let steps = [];
for path in ["/build", "/dest"] {
    steps.push(probe(path));
}
steps.push(step(
    Install,
    "stage",
    ["install -Dm755 /usr/bin/echo /dest/usr/bin/hello"],
    #{ "https://example.org/a.tar.xz": "0000000000000000000000000000000000000000000000000000000000000000" },
));

package(#{
    name: "gen",
    version: "0.1.0",
    dependencies: ["../lib.rhai"],
    steps: steps,
});
"#,
    )
    .expect("evaluates");

    let names: Vec<_> = build.steps().iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["probe /build", "probe /dest", "stage"]);
    assert_eq!(
        build.dependencies().collect::<Vec<_>>(),
        [Path::new("../lib.rhai")]
    );
    let downloads = build.steps()[2].dl_urls.as_ref().expect("downloads");
    assert_eq!(downloads.len(), 1);
}

#[test]
fn a_step_may_be_written_as_a_map() {
    let build = eval(
        r#"package(#{ name: "p", version: "1", steps: [
            step(#{ stage: Build, name: "compile", run: ["make"] }),
            #{ stage: "Test", name: "check", run: ["make check"] },
        ] });"#,
    )
    .expect("evaluates");
    assert_eq!(build.steps().len(), 2);
    assert_eq!(build.steps()[1].name, "check");
}

#[test]
fn a_file_without_package_is_rejected() {
    assert!(error("let x = 1;").contains("never calls package()"));
}

#[test]
fn calling_package_twice_is_rejected() {
    let message = error(
        r#"
package(#{ name: "a", version: "1" });
package(#{ name: "b", version: "1" });
"#,
    );
    assert!(message.contains("more than once"), "{message}");
    assert!(message.contains("line 3"), "{message}");
}

#[test]
fn package_takes_a_map() {
    let Err(positional) = recipe::evaluate(r#"package("p", "1");"#) else {
        panic!("positional arguments are not a package");
    };
    assert!(
        positional
            .help
            .as_deref()
            .is_some_and(|help| help.contains("object map")),
        "{positional:?}"
    );
    assert!(error(r#"package("p");"#).contains("object map"));
}

#[test]
fn an_unknown_stage_is_rejected() {
    let message =
        error(r#"package(#{ name: "p", version: "1", steps: [step("Deploy", "x", [])] });"#);
    assert!(message.contains("unknown stage"), "{message}");
    let message = error(
        r#"package(#{ name: "p", version: "1", steps: [#{ stage: "Deploy", name: "x", run: [] }] });"#,
    );
    assert!(message.contains("unknown stage"), "{message}");
}

#[test]
fn import_and_eval_are_disabled() {
    // A signature covers one file, so pulling code in from another would let
    // unsigned text run under someone else's signature.
    assert!(
        eval("import \"other\" as other;\npackage(#{ name: \"p\", version: \"1\" });").is_err()
    );
    assert!(eval("eval(\"1\");\npackage(#{ name: \"p\", version: \"1\" });").is_err());
}

#[test]
fn an_endless_loop_is_stopped() {
    let message = error("loop {}\npackage(#{ name: \"p\", version: \"1\" });");
    assert!(message.contains("Too many operations"), "{message}");
    let message = error("fn f(n) { f(n + 1) }\nf(0);");
    assert!(
        message.contains("Stack overflow") || message.contains("f"),
        "{message}"
    );
}

#[test]
fn the_stage_constants_cannot_be_reassigned() {
    assert!(eval("Prepare = \"Build\";\npackage(#{ name: \"p\", version: \"1\" });").is_err());
}

#[test]
fn errors_point_at_the_code() {
    let message = error("package(#{\n    name: undefined_name,\n    version: \"1\",\n});");
    assert!(message.contains("undefined_name"), "{message}");
    assert!(message.contains("line 2"), "{message}");

    let message = error(r#"package(#{ name: "a", version: "1", steps: [stpe(1)] });"#);
    assert!(message.contains("stpe"), "{message}");

    let rendered = format!(
        "{:?}",
        eval(r#"package(#{ name: "a", version: "1", steps: [stpe(1)] });"#)
            .err()
            .expect("an error")
    );
    assert!(rendered.contains("test.rhai"), "{rendered}");
}

#[test]
fn syntax_errors_are_diagnostics() {
    assert!(eval("package(#{").is_err());
    assert!(eval("package(#{ name: \"a\" version: \"1\" });").is_err());
}

#[test]
fn misspelt_keys_are_rejected() {
    let message = error(r#"package(#{ name: "p", version: "1", stesp: [] });"#);
    assert!(message.contains("stesp"), "{message}");
    let message = error(
        r#"package(#{ name: "p", version: "1", steps: [#{ stage: "Build", name: "x", run: [], runn: [] }] });"#,
    );
    assert!(message.contains("unknown key"), "{message}");
    let message = error(
        r#"package(#{ name: "p", version: "1", steps: [step(#{ stage: Build, nmae: "x", run: [] })] });"#,
    );
    assert!(message.contains("nmae"), "{message}");
    let message = error(r#"package(#{ name: "k", version: "1", kernel: #{ imgae: "vmlinuz" } });"#);
    assert!(message.contains("imgae"), "{message}");
}

#[test]
fn missing_keys_are_rejected() {
    assert!(error(r#"package(#{ name: "p" });"#).contains("version"));
}

#[test]
fn a_bad_download_url_is_rejected() {
    assert!(
        eval(r#"package(#{ name: "p", version: "1", steps: [step(Prepare, "x", [], #{ "not a url": "00" })] });"#)
            .is_err()
    );
}

#[test]
fn the_wrong_version_type_is_rejected() {
    let message = error(r#"package(#{ name: "p", version: 1 });"#);
    assert!(message.contains("version must be"), "{message}");
}

#[test]
fn a_kernel_is_declared_with_kernel_and_round_trips() {
    for source in [
        r#"package(#{ name: "k", version: "1", kernel: kernel("boot/vmlinuz", "quiet \"x\"") });"#,
        r#"package(#{ name: "k", version: "1", kernel: kernel(#{ image: "boot/vmlinuz", cmdline: "quiet \"x\"" }) });"#,
    ] {
        let build = eval(source).expect("evaluates");
        let kernel = build.kernel().expect("a kernel was declared");
        assert_eq!(kernel.image, Path::new("boot/vmlinuz"));
        assert_eq!(kernel.cmdline.as_deref(), Some("quiet \"x\""));

        let text = recipe::render(&build).expect("renders");
        assert_eq!(
            json(&eval(&text).expect("evaluates")),
            json(&build),
            "{text}"
        );
    }

    let bare = eval(r#"package(#{ name: "k", version: "1", kernel: kernel("vmlinuz") });"#)
        .expect("evaluates");
    assert_eq!(bare.kernel().expect("declared").cmdline, None);
    let text = recipe::render(&bare).expect("renders");
    assert!(text.contains("kernel: kernel(\"vmlinuz\"),"), "{text}");

    let none = eval(r#"package(#{ name: "k", version: "1", kernel: () });"#).expect("evaluates");
    assert!(none.kernel().is_none());
}

#[test]
fn the_generated_skeleton_round_trips() {
    let generated = BuildFile::generate();
    let text = recipe::render(&generated).expect("renders");
    assert_eq!(json(&eval(&text).expect("evaluates")), json(&generated));
}

const YAML: &str = r#"
name: tricky
version: ['1', '0', '0-rc.1']
dependencies:
  - ../dep/build.yaml
  - /abs/pkg.cpkg
steps:
- stage: Prepare
  name: "quotes \"and\" back\\slash\ttab ${not} `interpolated`"
  run:
  - echo "hi" 'there' \n
  - "multi\nline\u0007bell"
  dl_urls:
    https://example.org/b.tar.gz: BB
    https://example.org/a.tar.gz: AA
- stage: Install
  name: empty
  dl_urls: null
  run: []
- stage: Test
  name: bare downloads
  dl_urls: {}
  run: ["unicode ünï ✓"]
"#;

#[test]
fn migrated_yaml_evaluates_to_the_same_package() {
    let original = BuildFile::from_yaml(YAML).expect("fixture parses");
    let text = migrate::convert_text(YAML).expect("converts");
    let migrated = eval(&text).expect("migrated text evaluates");

    // Version "1.0.0-rc.1" contains a dot, so it must come back as an array.
    assert_eq!(json(&migrated), json(&original), "{text}");
}

#[test]
fn migrated_starlark_evaluates_to_the_same_package() {
    let starlark = r#"
def probe(path):
    return step(stage = Prepare, name = "probe " + path, run = ["test -e " + path])

package(
    name = "gen",
    version = ["1", "0.0"],
    dependencies = ["../lib.package", "/x/y.cpkg"],
    steps = [probe(p) for p in ["/build", "/dest"]] + [
        step(
            stage = Install,
            name = "stage",
            run = ["install -Dm755 /usr/bin/echo /dest/usr/bin/hello"],
            dl_urls = {"https://example.org/a.tar.xz": "00" * 32},
        ),
    ],
    kernel = kernel(image = "boot/vmlinuz", cmdline = "quiet"),
)
"#;
    let original = star::parse("build.package", starlark.to_owned()).expect("fixture evaluates");
    let text = migrate::convert_starlark(starlark).expect("converts");
    let migrated = eval(&text).expect("migrated text evaluates");
    assert_eq!(json(&migrated), json(&original), "{text}");
    assert!(
        text.contains("probe /dest"),
        "loops are written out: {text}"
    );
}

#[test]
fn migrated_download_maps_are_sorted() {
    let text = migrate::convert_text(YAML).expect("converts");
    let a = text.find("a.tar.gz").expect("a present");
    let b = text.find("b.tar.gz").expect("b present");
    assert!(a < b);
}

#[test]
fn target_paths() {
    assert_eq!(
        migrate::target_path(Path::new("a/build.yaml")),
        Path::new("a/build.rhai")
    );
    assert_eq!(
        migrate::target_path(Path::new("pm.yml")),
        Path::new("pm.rhai")
    );
    assert_eq!(
        migrate::target_path(Path::new("a/build.package")),
        Path::new("a/build.rhai")
    );
    assert_eq!(
        migrate::target_path(Path::new("recipe")),
        Path::new("recipe.rhai")
    );
}

#[test]
fn recursive_migration_rewrites_dependencies() {
    let dir = tempdir().expect("tempdir");
    let sub = dir.path().join("lib");
    create_dir_all(&sub).expect("mkdir");
    let leaf = sub.join("build.yaml");
    write(
        &leaf,
        "name: leaf\nversion: ['1']\ndependencies: []\nsteps: []\n",
    )
    .expect("write");
    let middle = dir.path().join("middle.package");
    write(
        &middle,
        format!(
            "package(name = \"middle\", version = \"1\", dependencies = [\"{}\"])\n",
            leaf.display()
        ),
    )
    .expect("write");
    let root = dir.path().join("build.yaml");
    write(
        &root,
        format!(
            "name: root\nversion: ['1']\ndependencies:\n- {}\n- /x/y.cpkg\nsteps: []\n",
            middle.display()
        ),
    )
    .expect("write");

    let converted = migrate::convert_file(&root, true).expect("converts");
    assert_eq!(converted.len(), 3);
    assert_eq!(converted[0].source, root, "the named file comes first");
    assert!(
        converted[0].text.contains("middle.rhai"),
        "{}",
        converted[0].text
    );
    assert!(converted[0].text.contains("/x/y.cpkg"));
    let middle_text = &converted
        .iter()
        .find(|item| item.source == middle)
        .expect("the Starlark dependency is converted")
        .text;
    assert!(middle_text.contains("lib/build.rhai"), "{middle_text}");
    assert!(
        middle_text.contains("Starlark was evaluated"),
        "{middle_text}"
    );

    for item in &converted {
        migrate::write_converted(item, None, false).expect("writes");
    }
    assert!(sub.join("build.rhai").exists());
    assert!(dir.path().join("middle.rhai").exists());
    let again = migrate::write_converted(&converted[0], None, false);
    assert!(again.is_err(), "refuses to overwrite without --force");
    migrate::write_converted(&converted[0], None, true).expect("--force overwrites");

    // Every migrated file loads.
    for item in &converted {
        BuildFile::load_unverified(&item.target).expect("a migrated recipe loads");
    }

    // Non-recursive migration leaves dependency paths alone.
    let shallow = migrate::convert_file(&root, false).expect("converts");
    assert_eq!(shallow.len(), 1);
    assert!(shallow[0].text.contains("middle.package"));
}

#[test]
fn recursive_migration_rewrites_extensionless_dependencies() {
    let dir = tempdir().expect("tempdir");
    let dependency = dir.path().join("leaf");
    write(
        &dependency,
        "name: leaf\nversion: ['1']\ndependencies: []\nsteps: []\n",
    )
    .expect("write");
    let root = dir.path().join("build.yaml");
    write(
        &root,
        format!(
            "name: root\nversion: ['1']\ndependencies:\n- {}\nsteps: []\n",
            dependency.display()
        ),
    )
    .expect("write");

    let converted = migrate::convert_file(&root, true).expect("converts");
    assert_eq!(converted.len(), 2);
    assert_eq!(converted[1].target, dir.path().join("leaf.rhai"));
    assert!(converted[0].text.contains("leaf.rhai"));
}

#[test]
fn recursive_migration_rejects_duplicate_targets() {
    let dir = tempdir().expect("tempdir");
    let first = dir.path().join("leaf.yaml");
    let second = dir.path().join("leaf.package");
    write(
        &first,
        "name: leaf\nversion: ['1']\ndependencies: []\nsteps: []\n",
    )
    .expect("write");
    write(&second, "package(name = \"leaf\", version = \"1\")\n").expect("write");
    let root = dir.path().join("build.yaml");
    write(
        &root,
        format!(
            "name: root\nversion: ['1']\ndependencies:\n- {}\n- {}\nsteps: []\n",
            first.display(),
            second.display()
        ),
    )
    .expect("write");

    let error = migrate::convert_file(&root, true).expect_err("targets collide");
    assert!(format!("{error}").contains("leaf.rhai"), "{error}");
}

#[test]
fn migrating_a_rhai_recipe_is_an_error() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("build.rhai");
    write(&path, r#"package(#{ name: "p", version: "1" });"#).expect("write");
    assert!(migrate::convert_file(&path, false).is_err());
}

#[test]
fn load_unverified_reads_rhai_recipes() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("build.rhai");
    write(&path, r#"package(#{ name: "disk", version: "3.1" });"#).expect("write");
    let build = BuildFile::load_unverified(&path).expect("loads");
    assert_eq!(build.name(), "disk");

    write(&path, "package(").expect("write");
    assert!(BuildFile::load_unverified(&path).is_err());
}

fn pm(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pm"));
    command.current_dir(dir).stdin(Stdio::null());
    command
}

#[test]
fn the_cli_migrates_and_generates() {
    let dir = tempdir().expect("tempdir");
    let yaml = dir.path().join("build.yaml");
    write(&yaml, YAML).expect("write");
    let pm = || pm(dir.path());

    let stdout = pm()
        .args(["migrate", "--stdout", "build.yaml"])
        .output()
        .expect("run");
    assert!(stdout.status.success());
    assert!(String::from_utf8_lossy(&stdout.stdout).contains("package(#{"));
    assert!(
        !dir.path().join("build.rhai").exists(),
        "--stdout writes nothing"
    );

    let wrote = pm().args(["migrate", "build.yaml"]).output().expect("run");
    assert!(wrote.status.success(), "{wrote:?}");
    let text = read_to_string(dir.path().join("build.rhai")).expect("written");
    assert!(eval(&text).is_ok());

    let again = pm().args(["migrate", "build.yaml"]).output().expect("run");
    assert!(!again.status.success(), "must not clobber without --force");
    let forced = pm()
        .args(["migrate", "build.yaml", "--force"])
        .output()
        .expect("run");
    assert!(forced.status.success());

    let generated = pm().args(["generate", "new.rhai"]).output().expect("run");
    assert!(generated.status.success(), "{generated:?}");
    let text = read_to_string(dir.path().join("new.rhai")).expect("generated");
    assert!(eval(&text).is_ok(), "the generated skeleton must evaluate");

    let starlark = pm()
        .args(["generate", "old.package"])
        .output()
        .expect("run");
    assert!(
        !starlark.status.success(),
        "Starlark is not generated any more"
    );
    assert!(String::from_utf8_lossy(&starlark.stderr).contains("old.rhai"));
}

#[test]
fn the_cli_migrates_starlark() {
    let dir = tempdir().expect("tempdir");
    write(
        dir.path().join("build.package"),
        "steps = [step(s, \"s-\" + s, [\"true\"]) for s in [Prepare, Build]]\n\
         package(name = \"p\", version = \"1\", steps = steps)\n",
    )
    .expect("write");
    let wrote = pm(dir.path())
        .args(["migrate", "build.package"])
        .output()
        .expect("run");
    assert!(wrote.status.success(), "{wrote:?}");
    let text = read_to_string(dir.path().join("build.rhai")).expect("written");
    let build = eval(&text).expect("the migrated recipe evaluates");
    assert_eq!(build.steps().len(), 2);
    assert!(
        dir.path().join("build.package").exists(),
        "the old file is left in place"
    );
}

#[test]
fn the_documented_helper_example_evaluates() {
    // Mirrors the helper example in examples/README.md.
    let build = eval(
        r#"
fn ro_probe(path) {
    `test ! -w ${path}`
}

package(#{
    name: "demo",
    version: "0.1.0",
    steps: [
        step(Prepare, "confine", ["/usr", "/etc"].map(ro_probe)),
    ],
});
"#,
    )
    .expect("evaluates");
    assert_eq!(build.steps()[0].run, ["test ! -w /usr", "test ! -w /etc"]);
}
