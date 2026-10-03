//! Plugins as Rhai packages: what a recipe can reach through an installed plugin, and
//! what pm refuses to hand it.
//!
//! Uses the `systemd` example plugin and the `recipes` fixture, both built from
//! `plugins/` by `build.rs`.

use std::{
    fs::{copy, create_dir_all},
    path::Path,
};

use pm::{
    plugin::{Loader, RecipeValue, Registry},
    recipe,
};
use tempfile::{TempDir, tempdir};

fn registry(names: &[&str]) -> (TempDir, Registry) {
    let root = tempdir().expect("a temporary directory");
    let dir = root.path().join("plugins");
    create_dir_all(&dir).expect("create the plugin directory");
    for name in names {
        copy(
            Path::new(env!("PM_TEST_PLUGIN_DIR")).join(format!("{name}.wasm")),
            dir.join(format!("{name}.wasm")),
        )
        .unwrap_or_else(|error| panic!("stage the {name} fixture: {error}"));
    }
    let registry = Loader::new(dir)
        .allow_unsigned(true)
        .load()
        .expect("the fixtures must load");
    (root, registry)
}

fn error(text: &str, plugins: &Registry) -> String {
    match recipe::evaluate_with(text, plugins) {
        Ok(_) => panic!("{text} must not evaluate"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn systemd_adds_steps_and_constants() {
    let (_root, plugins) = registry(&["systemd"]);
    let build = recipe::evaluate_with(
        r#"
let p = Package("units", "1");
p += systemd::install_unit("units/foo.service");
p.add_steps(systemd::install_units(["a.socket", "b.timer"]));
p += step(Test, "unitdir", [`test -d /dest${systemd::unitdir}`]);
package(p);
"#,
        &plugins,
    )
    .expect("evaluates");
    let steps = build.steps();
    assert_eq!(steps.len(), 4);
    assert_eq!(steps[0].name, "install foo.service");
    assert_eq!(
        steps[0].run,
        ["install -Dm644 units/foo.service /dest/usr/lib/systemd/system/foo.service"]
    );
    assert_eq!(steps[2].name, "install b.timer");
    assert_eq!(steps[3].run, ["test -d /dest/usr/lib/systemd/system"]);
}

#[test]
fn a_plugin_s_refusal_is_a_recipe_error_at_the_call() {
    let (_root, plugins) = registry(&["systemd"]);
    let message = error(
        "let s = 1;\npackage(#{ name: \"p\", version: \"1\", steps: [systemd::install_unit(\"notes.txt\")] });",
        &plugins,
    );
    assert!(message.contains("systemd::install_unit"), "{message}");
    assert!(message.contains("not a unit file"), "{message}");
    assert!(message.contains("line 2"), "{message}");
}

#[test]
fn without_the_plugin_its_module_does_not_exist() {
    let message = error(
        "package(#{ name: \"p\", version: \"1\", steps: [systemd::install_unit(\"a.service\")] });",
        Registry::none(),
    );
    assert!(message.contains("systemd"), "{message}");
}

#[test]
fn the_fixture_s_functions_are_listed_and_the_unusable_ones_dropped() {
    let (_root, plugins) = registry(&["recipes"]);
    let manifest = plugins.plugins()[0].manifest();
    let names: Vec<_> = manifest
        .recipe_functions
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        names,
        [
            "build_step",
            "echo",
            "fraction",
            "kernel_for",
            "misspelt",
            "refuse",
            "skeleton",
            "spin"
        ]
    );
    assert_eq!(
        manifest.recipe_functions["skeleton"].returns,
        RecipeValue::Package
    );
    let modules = plugins.recipe_modules();
    assert_eq!(modules[0].namespace(), "recipe_fixture");
}

#[test]
fn values_cross_as_json_and_come_back_typed() {
    let (_root, plugins) = registry(&["recipes"]);
    let build = recipe::evaluate_with(
        r#"
let echoed = recipe_fixture::echo(#{ list: [1, "two", true, ()], step: step(Build, "s", ["x"]) });
if echoed.list != [1, "two", true, ()] { throw `list came back as ${echoed.list}`; }
if echoed.step.run != ["x"] { throw "a Step crosses as its map"; }
let p = recipe_fixture::skeleton("skel");
if type_of(p) != "Package" { throw type_of(p); }
p += recipe_fixture::build_step("extra");
p.with_kernel(recipe_fixture::kernel_for("boot/vmlinuz"));
p += step(Test, recipe_fixture::prefix, []);
package(p);
"#,
        &plugins,
    )
    .expect("evaluates");
    assert_eq!(build.name(), "skel");
    let names: Vec<_> = build.steps().iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["compile", "extra", "/opt/fixture"]);
    assert_eq!(
        build.kernel().expect("a kernel").cmdline.as_deref(),
        Some("quiet")
    );
}

#[test]
fn malformed_answers_are_refused() {
    let (_root, plugins) = registry(&["recipes"]);
    let message = error("recipe_fixture::misspelt();", &plugins);
    assert!(message.contains("nmae"), "{message}");
    let message = error("recipe_fixture::fraction();", &plugins);
    assert!(message.contains("floating-point"), "{message}");
    assert!(message.contains("1.5"), "{message}");
    let message = error("recipe_fixture::refuse();", &plugins);
    assert!(message.contains("this fixture refuses"), "{message}");
    let message = error("recipe_fixture::echo(1, 2);", &plugins);
    assert!(message.contains("echo"), "{message}");
}

#[test]
fn a_runaway_recipe_function_is_stopped() {
    let (_root, plugins) = registry(&["recipes"]);
    let message = error("recipe_fixture::spin();", &plugins);
    assert!(message.contains("fuel"), "{message}");
}

#[test]
fn definitions_include_plugin_modules() {
    let (_root, plugins) = registry(&["systemd"]);
    let definitions = recipe::definitions(&plugins);
    assert!(definitions.contains("install_unit"), "{definitions}");
}
