//! A fixture that adds recipe functions, some of them badly behaved.
//!
//! `tests/recipe_plugins.rs` calls each from a Rhai recipe:
//!
//! * `echo(value)` hands its argument back unchanged, as plain data, so a test can see
//!   exactly what crossed the boundary;
//! * `build_step(name)` and `kernel_for(image)` return a well-formed `Step` and
//!   `Kernel`, and `skeleton(name)` a whole `Package`;
//! * `misspelt()` returns a step with a misspelt key, `fraction()` a number recipes
//!   cannot hold, and `refuse()` an error - each of which pm must turn into a recipe
//!   error rather than a value;
//! * `spin()` never returns, and must be stopped by the fuel meter;
//! * `fn` and `too_many` are not functions a recipe could call, and must be dropped at
//!   load.
//!
//! `odd_params` has a parameter name that is not an identifier, which pm renames.
//!
//! It also publishes symbols, which a recipe sees as constants, two of them spelt
//! `same-name` and `same_name`: only the first is reachable from a recipe.

wit_bindgen::generate!({ path: "../../../wit", world: "recipe-plugin" });

use pm::plugin::types::{RecipeValue, Symbol};

struct Recipes;

fn function(name: &str, params: &[&str], returns: RecipeValue) -> RecipeFunction {
    RecipeFunction {
        name: name.into(),
        params: params.iter().map(|&param| param.into()).collect(),
        returns,
        doc: format!("The `{name}` fixture."),
    }
}

impl Guest for Recipes {
    fn describe() -> Manifest {
        Manifest {
            name: "recipe-fixture".into(),
            version: "0.1.0".into(),
            summary: "Adds recipe functions, some of them badly behaved".into(),
            hooks: Vec::new(),
            grants_at_most: Vec::new(),
            source_extensions: Vec::new(),
            symbols: vec![
                Symbol {
                    name: "prefix".into(),
                    value: "/opt/fixture".into(),
                    summary: "a constant".into(),
                },
                // The same recipe constant, `same_name`, twice over.
                Symbol {
                    name: "same-name".into(),
                    value: "/first".into(),
                    summary: "kept".into(),
                },
                Symbol {
                    name: "same_name".into(),
                    value: "/second".into(),
                    summary: "dropped from recipes".into(),
                },
            ],
        }
    }

    fn classify_command(_command: String) -> Option<Verdict> {
        None
    }

    fn scan_source(_file: SourceFile) -> Vec<Grant> {
        Vec::new()
    }

    fn recipe_functions() -> Vec<RecipeFunction> {
        vec![
            function("echo", &["value"], RecipeValue::Any),
            function("build_step", &["name"], RecipeValue::Step),
            function("kernel_for", &["image"], RecipeValue::Kernel),
            function("skeleton", &["name"], RecipeValue::Package),
            function("misspelt", &[], RecipeValue::Step),
            function("fraction", &[], RecipeValue::Any),
            function("refuse", &[], RecipeValue::Any),
            function("spin", &[], RecipeValue::Any),
            function("fn", &[], RecipeValue::Any),
            function("odd_params", &["fine", "not fine"], RecipeValue::Any),
            function(
                "too_many",
                &["a", "b", "c", "d", "e", "f", "g"],
                RecipeValue::Any,
            ),
        ]
    }

    fn call_recipe_function(name: String, args: Vec<String>) -> Result<String, String> {
        // Arguments arrive as JSON text; these fixtures only ever take a string, so
        // pass it through as the JSON it already is.
        let arg = args.first().cloned().unwrap_or_default();
        match name.as_str() {
            "echo" => Ok(arg),
            "build_step" => Ok(format!(
                r#"{{"stage":"Build","name":{arg},"run":["make"]}}"#
            )),
            "kernel_for" => Ok(format!(r#"{{"image":{arg},"cmdline":"quiet"}}"#)),
            "skeleton" => Ok(format!(
                r#"{{"name":{arg},"version":"0.1","steps":[{{"stage":"Build","name":"compile","run":["make"]}}]}}"#
            )),
            "misspelt" => Ok(r#"{"stage":"Build","nmae":"x","run":[]}"#.into()),
            "fraction" => Ok("1.5".into()),
            "refuse" => Err("this fixture refuses".into()),
            "spin" => {
                let mut n: u64 = 0;
                loop {
                    n = std::hint::black_box(n.wrapping_add(1));
                }
            }
            _ => Err(format!("no recipe function {name}")),
        }
    }
}

export!(Recipes);
