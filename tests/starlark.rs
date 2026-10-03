//! Behavioural tests for deprecated Starlark (`.package`) build files, which
//! still load until support for them is removed. Converting them to Rhai is
//! covered in `tests/rhai.rs`.

use std::{fs::write, path::Path};

use pm::{bf::BuildFile, star};
use tempfile::tempdir;

fn eval(text: &str) -> miette::Result<BuildFile> {
    star::parse("test.package", text.to_owned())
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
fn a_kernel_is_still_declared_with_kernel() {
    let build = eval(
        r#"package(name = "k", version = "1", kernel = kernel(image = "boot/vmlinuz", cmdline = "quiet"))"#,
    )
    .expect("evaluates");
    let kernel = build.kernel().expect("a kernel was declared");
    assert_eq!(kernel.image, Path::new("boot/vmlinuz"));
    assert_eq!(kernel.cmdline.as_deref(), Some("quiet"));
    assert!(
        eval(r#"package(name = "k", version = "1", kernel = {"imgae": "vmlinuz"})"#).is_err(),
        "a misspelt key must not be ignored"
    );
}
