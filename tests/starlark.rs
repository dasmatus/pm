//! Behavioural tests for Starlark (`.package`) build files and `pm migrate`.

use std::{
    fs::{create_dir_all, read_to_string, write},
    path::Path,
    process::{Command, Stdio},
};

use pm::{bf::BuildFile, migrate, star};
use tempfile::tempdir;

fn eval(text: &str) -> miette::Result<BuildFile> {
    star::parse("test.package", text.to_owned())
}

fn json(build: &BuildFile) -> serde_json::Value {
    serde_json::to_value(build).expect("a build file serialises")
}

#[test]
fn a_minimal_package_evaluates() {
    let build = eval(r#"package(name = "hello", version = "1.2.3")"#).expect("evaluates");
    assert_eq!(build.name(), "hello");
    assert_eq!(build.version(), ["1", "2", "3"]);
    assert_eq!(build.version_string(), "1.2.3");
    assert_eq!(build.dependencies().len(), 0);
    assert!(build.steps().is_empty());
}

#[test]
fn version_may_be_a_list() {
    let build = eval(r#"package(name = "p", version = ["2", "0"])"#).expect("evaluates");
    assert_eq!(build.version_string(), "2.0");
}

#[test]
fn steps_can_be_generated_with_loops_and_functions() {
    let build = eval(
        r#"
def probe(path):
    return step(stage = Prepare, name = "probe " + path, run = ["test -e " + path])

package(
    name = "gen",
    version = "0.1.0",
    dependencies = ["../lib.package"],
    steps = [probe(p) for p in ["/build", "/dest"]] + [
        step(
            stage = Install,
            name = "stage",
            run = ["install -Dm755 /usr/bin/echo /dest/usr/bin/hello"],
            dl_urls = {"https://example.org/a.tar.xz": "00" * 32},
        ),
    ],
)
"#,
    )
    .expect("evaluates");

    let names: Vec<_> = build.steps().iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["probe /build", "probe /dest", "stage"]);
    assert_eq!(
        build.dependencies().collect::<Vec<_>>(),
        [Path::new("../lib.package")]
    );
    let downloads = build.steps()[2].dl_urls.as_ref().expect("downloads");
    assert_eq!(downloads.len(), 1);
}

#[test]
fn top_level_control_flow_is_allowed() {
    let build = eval(
        r#"
steps = []
for stage in [Prepare, Build, Test]:
    steps.append(step(stage, "s-" + stage, ["true"]))
package("p", "1", steps = steps)
"#,
    )
    .expect("evaluates");
    assert_eq!(build.steps().len(), 3);
}

#[test]
fn a_file_without_package_is_rejected() {
    let error = eval("x = 1").err().expect("no package()");
    assert!(format!("{error:?}").contains("never calls package()"));
}

#[test]
fn calling_package_twice_is_rejected() {
    let error = eval(
        r#"
package(name = "a", version = "1")
package(name = "b", version = "1")
"#,
    )
    .err()
    .expect("two packages");
    assert!(format!("{error}").contains("more than once"), "{error}");
}

#[test]
fn an_unknown_stage_is_rejected() {
    let error = eval(r#"package("p", "1", steps = [step("Deploy", "x", [])])"#)
        .err()
        .expect("bad stage");
    assert!(format!("{error}").contains("unknown stage"), "{error}");
}

#[test]
fn load_is_disabled() {
    // A signature covers one file, so pulling code in from another would let
    // unsigned text run under someone else's signature.
    assert!(eval("load(\"other.package\", \"x\")\npackage(\"p\", \"1\")").is_err());
}

#[test]
fn syntax_and_name_errors_are_diagnostics() {
    assert!(eval("package(").is_err());
    assert!(eval(r#"package(name = undefined_name, version = "1")"#).is_err());
}

#[test]
fn a_misspelt_step_key_is_rejected() {
    let error = eval(
        r#"package("p", "1", steps = [{"stage": "Build", "name": "x", "run": [], "runn": []}])"#,
    )
    .err()
    .expect("unknown key");
    assert!(format!("{error}").contains("unknown key"), "{error}");
}

#[test]
fn a_bad_download_url_is_rejected() {
    assert!(
        eval(
            r#"package("p", "1", steps = [step(Prepare, "x", [], dl_urls = {"not a url": "00"})])"#
        )
        .is_err()
    );
}

#[test]
fn the_wrong_version_type_is_rejected() {
    assert!(eval(r#"package("p", 1)"#).is_err());
}

const YAML: &str = r#"
name: tricky
version: ['1', '0', '0-rc.1']
dependencies:
  - ../dep/build.yaml
  - /abs/pkg.cpkg
steps:
- stage: Prepare
  name: "quotes \"and\" back\\slash\ttab"
  run:
  - echo "hi" 'there' \n
  - "multi\nline"
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
fn migrated_text_evaluates_to_the_same_package() {
    let original = BuildFile::from_yaml(YAML).expect("fixture parses");
    let star_text = migrate::convert_text(YAML).expect("converts");
    let migrated = eval(&star_text).expect("migrated text evaluates");

    // Version "1.0.0-rc.1" contains a dot, so it must come back as a list.
    assert_eq!(json(&migrated), json(&original), "{star_text}");
}

#[test]
fn migrated_download_maps_are_sorted() {
    let text = migrate::convert_text(YAML).expect("converts");
    let a = text.find("a.tar.gz").expect("a present");
    let b = text.find("b.tar.gz").expect("b present");
    assert!(a < b);
}

#[test]
fn the_generated_skeleton_round_trips() {
    let generated = BuildFile::generate();
    let text = star::render(&generated).expect("renders");
    assert_eq!(json(&eval(&text).expect("evaluates")), json(&generated));
}

#[test]
fn target_paths() {
    assert_eq!(
        migrate::target_path(Path::new("a/build.yaml")),
        Path::new("a/build.package")
    );
    assert_eq!(
        migrate::target_path(Path::new("pm.yml")),
        Path::new("pm.package")
    );
    assert_eq!(
        migrate::target_path(Path::new("recipe")),
        Path::new("recipe.package")
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
    let root = dir.path().join("build.yaml");
    write(
        &root,
        format!(
            "name: root\nversion: ['1']\ndependencies:\n- {}\n- /x/y.cpkg\nsteps: []\n",
            leaf.display()
        ),
    )
    .expect("write");

    let converted = migrate::convert_file(&root, true).expect("converts");
    assert_eq!(converted.len(), 2);
    assert_eq!(converted[0].source, root, "the named file comes first");
    assert!(converted[0].text.contains("lib/build.package"));
    assert!(converted[0].text.contains("/x/y.cpkg"));

    for item in &converted {
        migrate::write_converted(item, None, false).expect("writes");
    }
    assert!(sub.join("build.package").exists());
    let again = migrate::write_converted(&converted[0], None, false);
    assert!(again.is_err(), "refuses to overwrite without --force");
    migrate::write_converted(&converted[0], None, true).expect("--force overwrites");

    // Non-recursive migration leaves dependency paths alone.
    let shallow = migrate::convert_file(&root, false).expect("converts");
    assert_eq!(shallow.len(), 1);
    assert!(shallow[0].text.contains("build.yaml"));
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
    assert_eq!(converted[1].target, dir.path().join("leaf.package"));
    assert!(converted[0].text.contains("leaf.package"));
}

#[test]
fn recursive_migration_rejects_duplicate_targets() {
    let dir = tempdir().expect("tempdir");
    let yaml = "name: leaf\nversion: ['1']\ndependencies: []\nsteps: []\n";
    let first = dir.path().join("leaf.yaml");
    let second = dir.path().join("leaf.yml");
    write(&first, yaml).expect("write");
    write(&second, yaml).expect("write");
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
    assert!(format!("{error}").contains("leaf.package"), "{error}");
}

#[test]
fn migrating_a_starlark_file_is_an_error() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("build.package");
    write(&path, r#"package("p", "1")"#).expect("write");
    assert!(migrate::convert_file(&path, false).is_err());
}

#[test]
fn load_unverified_reads_package_files() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("build.package");
    write(&path, r#"package(name = "disk", version = "3.1")"#).expect("write");
    let build = BuildFile::load_unverified(&path).expect("loads");
    assert_eq!(build.name(), "disk");

    write(&path, "package(").expect("write");
    assert!(BuildFile::load_unverified(&path).is_err());
}

#[test]
fn the_cli_migrates_and_generates() {
    let dir = tempdir().expect("tempdir");
    let yaml = dir.path().join("build.yaml");
    write(&yaml, YAML).expect("write");
    let pm = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pm"));
        command.current_dir(dir.path()).stdin(Stdio::null());
        command
    };

    let stdout = pm()
        .args(["migrate", "--stdout", "build.yaml"])
        .output()
        .expect("run");
    assert!(stdout.status.success());
    assert!(String::from_utf8_lossy(&stdout.stdout).contains("package("));
    assert!(
        !dir.path().join("build.package").exists(),
        "--stdout writes nothing"
    );

    let wrote = pm().args(["migrate", "build.yaml"]).output().expect("run");
    assert!(wrote.status.success(), "{wrote:?}");
    let text = read_to_string(dir.path().join("build.package")).expect("written");
    assert!(eval(&text).is_ok());

    let again = pm().args(["migrate", "build.yaml"]).output().expect("run");
    assert!(!again.status.success(), "must not clobber without --force");
    let forced = pm()
        .args(["migrate", "build.yaml", "--force"])
        .output()
        .expect("run");
    assert!(forced.status.success());

    let generated = pm()
        .args(["generate", "new.package"])
        .output()
        .expect("run");
    assert!(generated.status.success(), "{generated:?}");
    let text = read_to_string(dir.path().join("new.package")).expect("generated");
    assert!(eval(&text).is_ok(), "the generated skeleton must evaluate");
}
