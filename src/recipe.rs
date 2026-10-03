//! Recipes (build files) written in [Rhai](https://rhai.rs).
//!
//! A `.rhai` recipe is a small, deterministic script that calls `package(...)`
//! exactly once. Evaluating it yields the same [`BuildFile`] a YAML or Starlark
//! file describes, so everything downstream - signature checks, policy
//! derivation, the dependency graph, the sandbox - is unchanged. What a script
//! adds over plain data is loops, functions and conditionals for generating steps
//! and commands.
//!
//! Rhai replaced Starlark as the recipe language. Starlark `.package` files still
//! load, with a deprecation warning, and `pm migrate` converts them (see
//! [`crate::migrate`]).
//!
//! # What a recipe can do
//!
//! Evaluation is hermetic. The only things in scope are Rhai's core language and
//! standard library and the pm builtins below; there is no file or network
//! access, no environment and no clock. **`import` and `eval` are disabled**: a
//! signature covers one file, so a recipe that pulled code in from elsewhere
//! would be vouching for text nobody signed. Unlike Starlark, Rhai has unbounded
//! loops and recursion, so evaluation runs under operation, call-depth and size
//! limits, and a recipe that exceeds them is an error rather than a hang.
//! Variables must be declared before use, so a misspelt name is caught when the
//! file is compiled. `print` and `debug` go to pm's log, never to stdout.
//!
//! | name | meaning |
//! |---|---|
//! | `package(#{ name, version, dependencies, steps, kernel })` | declares the package; call it exactly once |
//! | `step(stage, name, run)`, `step(stage, name, run, dl_urls)`, `step(#{ ... })` | one build step |
//! | `kernel(image)`, `kernel(image, cmdline)`, `kernel(#{ ... })` | a kernel the package ships, see [`crate::vm`] |
//! | `Prepare`, `Build`, `Install`, `Test` | the stage names, as strings |
//!
//! Rhai has no keyword arguments, so `package` takes an object map. `version` is
//! a string (`"1.2.3"`, split on `.`) or an array of strings; `dependencies`,
//! `steps` and `kernel` may be left out. `dl_urls` is an object map from URL to
//! SHA-256, with the URLs written as quoted keys.
//!
//! ```rhai
//! package(#{
//!     name: "hello",
//!     version: "1.0.0",
//!     steps: [
//!         step(Install, "stage", ["install -Dm755 /usr/bin/echo /dest/usr/bin/hello"]),
//!     ],
//! });
//! ```

use std::{cell::RefCell, fmt::Write as _, path::Path, rc::Rc};

use miette::{LabeledSpan, MietteDiagnostic, NamedSource, Report, miette};
use rhai::{
    AST, Array, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Position, Scope,
    serde::from_dynamic,
};
use serde_json::Value as Json;

use crate::{bf::BuildFile, step::Stage};

/// File extension of a Rhai recipe, without the dot.
pub const EXTENSION: &str = "rhai";

/// Whether `path` names a Rhai recipe.
#[must_use]
pub fn is_rhai(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == EXTENSION)
}

/// The stage constants a recipe can name.
pub const STAGES: [&str; 4] = ["Prepare", "Build", "Install", "Test"];

/// Most operations one evaluation may perform before it is stopped. Generous
/// for any recipe that terminates; it exists to turn `loop {}` into an error.
pub const MAX_OPERATIONS: u64 = 10_000_000;
/// Deepest function call nesting a recipe may reach.
const MAX_CALL_LEVELS: usize = 64;
/// Longest string a recipe may build, in bytes.
const MAX_STRING_SIZE: usize = 1 << 20;
/// Most elements in one array, or entries in one object map.
const MAX_COLLECTION_SIZE: usize = 100_000;

/// One pm builtin, as editors and `pm-lsp` describe it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Builtin {
    /// The name a recipe calls or refers to it by.
    pub name: &'static str,
    /// How it is called, or for a constant, its value.
    pub signature: &'static str,
    /// What it means, in Markdown.
    pub doc: &'static str,
}

/// Every pm builtin a recipe can see, beyond Rhai's own standard library.
pub const BUILTINS: [Builtin; 7] = [
    Builtin {
        name: "package",
        signature: "package(#{ name: string, version: string | [string], dependencies: [string], steps: [step], kernel: kernel })",
        doc: "Declare the package this file builds. Call it exactly once.\n\n\
              `version` is a string such as `\"1.2.3\"` or an array of strings. `dependencies` \
              are paths to recipes or `.cpkg` archives. `steps` is an array of `step(...)`. \
              `dependencies`, `steps` and `kernel` may be left out.",
    },
    Builtin {
        name: "step",
        signature: "step(stage, name, run) | step(stage, name, run, dl_urls) | step(#{ stage, name, run, dl_urls })",
        doc: "One build step: optional downloads, then commands run in order.\n\n\
              `stage` is one of `Prepare`, `Build`, `Install`, `Test`. `run` is an array of \
              command strings - no shell is involved. `dl_urls` is an object map from a URL \
              (a quoted key) to the SHA-256 of what it must download.",
    },
    Builtin {
        name: "kernel",
        signature: "kernel(image) | kernel(image, cmdline) | kernel(#{ image, cmdline })",
        doc: "A kernel the package ships: `pm run` boots it in a virtual machine and runs \
              the entrypoint under it, instead of on the host's kernel.\n\n\
              `image` is the kernel image the steps install, relative to `DESTDIR`, such as \
              `\"boot/vmlinuz\"`. `cmdline` is appended to the kernel command line pm boots it with.",
    },
    Builtin {
        name: "Prepare",
        signature: "const Prepare = \"Prepare\"",
        doc: "The first stage: fetch and unpack sources, apply patches.",
    },
    Builtin {
        name: "Build",
        signature: "const Build = \"Build\"",
        doc: "Compile.",
    },
    Builtin {
        name: "Install",
        signature: "const Install = \"Install\"",
        doc: "Stage the built files under `DESTDIR`.",
    },
    Builtin {
        name: "Test",
        signature: "const Test = \"Test\"",
        doc: "Run the package's test suite.",
    },
];

const PACKAGE_KEYS: [&str; 5] = ["name", "version", "dependencies", "steps", "kernel"];
pub(crate) const STEP_KEYS: [&str; 4] = ["stage", "name", "run", "dl_urls"];
const KERNEL_KEYS: [&str; 2] = ["image", "cmdline"];

type RhaiResult<T> = Result<T, Box<EvalAltResult>>;

/// Why a recipe did not evaluate to a package, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeError {
    /// What went wrong, without the position.
    pub message: String,
    /// 1-based line and column (in characters) of the offending code, when known.
    pub position: Option<(usize, usize)>,
    /// A hint at the fix, when there is an obvious one.
    pub help: Option<String>,
}

impl RecipeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            position: None,
            help: None,
        }
    }

    fn at(mut self, position: Position) -> Self {
        self.position = position
            .line()
            .map(|line| (line, position.position().unwrap_or(1)));
        self
    }

    fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    fn from_eval(mut error: EvalAltResult) -> Self {
        let position = error.take_position();
        let message = match &error {
            // A message a builtin raised reads better without Rhai's prefix.
            EvalAltResult::ErrorRuntime(value, _) if value.is_string() => value.to_string(),
            _ => error.to_string(),
        };
        Self::new(message).at(position)
    }
}

impl std::fmt::Display for RecipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        if let Some((line, column)) = self.position {
            write!(f, " (line {line}, column {column})")?;
        }
        Ok(())
    }
}

impl std::error::Error for RecipeError {}

/// The engine recipes are evaluated with. `collected` receives what `package()`
/// is called with.
fn engine(collected: Rc<RefCell<Option<(Map, Position)>>>) -> Engine {
    let mut engine = Engine::new();
    engine
        .set_strict_variables(true)
        .set_max_operations(MAX_OPERATIONS)
        .set_max_call_levels(MAX_CALL_LEVELS)
        .set_max_string_size(MAX_STRING_SIZE)
        .set_max_array_size(MAX_COLLECTION_SIZE)
        .set_max_map_size(MAX_COLLECTION_SIZE)
        .disable_symbol("eval")
        .on_print(|text| tracing::info!(target: "pm::recipe", "{text}"))
        .on_debug(|text, source, position| {
            tracing::debug!(target: "pm::recipe", ?source, %position, "{text}");
        });

    // Functions do not see the caller's scope, so the stage constants are
    // resolved here rather than pushed into it: they work inside a `fn` too.
    #[allow(deprecated)] // `on_var` is marked volatile, not deprecated.
    engine.on_var(|name, _, _| {
        Ok(STAGES
            .contains(&name)
            .then(|| Dynamic::from(ImmutableString::from(name))))
    });

    // `package` is a reserved word in Rhai, so it cannot be an ordinary function.
    // Custom syntax may claim a reserved word, and `package(...)` reads the same.
    engine
        .register_custom_syntax(["package", "(", "$expr$", ")"], false, {
            move |context, inputs| {
                let position = inputs[0].position();
                let at = |message: String| EvalAltResult::ErrorRuntime(message.into(), position);
                let spec = context.eval_expression_tree(&inputs[0])?;
                let Some(spec) = spec.try_cast::<Map>() else {
                    return Err(at("package() takes one object map: \
                                   package(#{ name: \"...\", version: \"...\" })"
                        .to_owned())
                    .into());
                };
                check_keys("package()", &spec, &PACKAGE_KEYS, &["name", "version"]).map_err(at)?;
                if collected.borrow_mut().replace((spec, position)).is_some() {
                    return Err(at("package() was called more than once".to_owned()).into());
                }
                Ok(Dynamic::UNIT)
            }
        })
        .expect("`package(...)` is valid custom syntax");

    engine
        .register_fn("step", |stage: &str, name: &str, run: Array| {
            step(stage, name, run, None)
        })
        .register_fn(
            "step",
            |stage: &str, name: &str, run: Array, dl_urls: Map| {
                step(stage, name, run, Some(dl_urls))
            },
        )
        .register_fn("step", |spec: Map| -> RhaiResult<Map> {
            check_keys("step()", &spec, &STEP_KEYS, &["stage", "name", "run"])?;
            let stage = spec["stage"]
                .read_lock::<ImmutableString>()
                .map(|s| s.to_string());
            check_stage(stage.as_deref().unwrap_or_default())?;
            Ok(spec)
        });

    engine
        .register_fn("kernel", |image: &str| kernel(image, None))
        .register_fn("kernel", |image: &str, cmdline: &str| {
            kernel(image, Some(cmdline))
        })
        .register_fn("kernel", |spec: Map| -> RhaiResult<Map> {
            check_keys("kernel()", &spec, &KERNEL_KEYS, &["image"])?;
            Ok(spec)
        });

    engine
}

fn step(stage: &str, name: &str, run: Array, dl_urls: Option<Map>) -> RhaiResult<Map> {
    check_stage(stage)?;
    let mut map = Map::new();
    map.insert("stage".into(), stage.into());
    map.insert("name".into(), name.into());
    map.insert("run".into(), run.into());
    if let Some(dl_urls) = dl_urls {
        map.insert("dl_urls".into(), dl_urls.into());
    }
    Ok(map)
}

fn kernel(image: &str, cmdline: Option<&str>) -> RhaiResult<Map> {
    let mut map = Map::new();
    map.insert("image".into(), image.into());
    if let Some(cmdline) = cmdline {
        map.insert("cmdline".into(), cmdline.into());
    }
    Ok(map)
}

fn check_stage(stage: &str) -> RhaiResult<()> {
    if STAGES.contains(&stage) {
        Ok(())
    } else {
        Err(format!("unknown stage {stage:?}; use Prepare, Build, Install or Test").into())
    }
}

fn check_keys(what: &str, map: &Map, allowed: &[&str], required: &[&str]) -> Result<(), String> {
    if let Some(unknown) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!(
            "{what} has an unknown key `{unknown}`; it takes {}",
            allowed.join(", ")
        ));
    }
    if let Some(missing) = required.iter().find(|key| !map.contains_key(**key)) {
        return Err(format!("{what} is missing `{missing}`"));
    }
    Ok(())
}

/// Compile `text` with pm's dialect: strict variables, the stage constants known.
fn compile(engine: &Engine, text: &str) -> Result<AST, RecipeError> {
    let mut constants = Scope::new();
    for stage in STAGES {
        constants.push_constant(stage, ImmutableString::from(stage));
    }
    engine.compile_with_scope(&constants, text).map_err(|error| {
        let position = error.position();
        let message = error.err_type().to_string();
        let error = RecipeError::new(message.clone()).at(position);
        if message.contains("'import'") {
            error.help("`import` is not supported in recipes: a signature covers one file.")
        } else if message.contains("'package'") {
            error.help("package() takes one object map: package(#{ name: \"...\", version: \"...\" });")
        } else {
            error
        }
    })
}

/// Evaluate a recipe and return the package it declares.
///
/// This is [`parse`] without the diagnostic dressing, for callers such as
/// `pm-lsp` that place the error themselves.
///
/// # Errors
///
/// Fails on a syntax or evaluation error, when a limit is exceeded, when
/// `package()` is never called or is called twice, or when what it declares is
/// not a valid build file (an unknown stage, a malformed download URL, a misspelt
/// key).
pub fn evaluate(text: &str) -> Result<BuildFile, RecipeError> {
    let collected = Rc::new(RefCell::new(None));
    let engine = engine(Rc::clone(&collected));
    let ast = compile(&engine, text)?;
    engine
        .run_ast(&ast)
        .map_err(|error| RecipeError::from_eval(*error))?;
    drop(engine);
    let (spec, position) = Rc::into_inner(collected)
        .and_then(RefCell::into_inner)
        .ok_or_else(|| {
            RecipeError::new("the recipe never calls package()").help(
                "Declare the package with package(#{ name: ..., version: ..., steps: [...] });",
            )
        })?;
    to_build_file(spec).map_err(|error| error.at(position))
}

/// Turn what `package()` was given into a [`BuildFile`].
fn to_build_file(mut spec: Map) -> Result<BuildFile, RecipeError> {
    let version = spec.remove("version").unwrap_or_default();
    let version = version_components(&version)?;
    // A recipe may leave these out, or write `()` for "none".
    for optional in ["dependencies", "steps"] {
        if spec.get(optional).is_none_or(Dynamic::is_unit) {
            spec.insert(optional.into(), Array::new().into());
        }
    }
    if spec.get("kernel").is_some_and(Dynamic::is_unit) {
        spec.remove("kernel");
    }
    let mut package: Json =
        from_dynamic(&Dynamic::from_map(spec)).map_err(|error| RecipeError::from_eval(*error))?;
    package["version"] = Json::from(version);
    check_step_keys(&package).map_err(|error| RecipeError::new(error.to_string()))?;
    serde_json::from_value(package)
        .map_err(|error| RecipeError::new(format!("not a valid build file: {error}")))
}

/// `version: "1.2.3"` or `version: ["1", "2", "3"]` to its components.
fn version_components(version: &Dynamic) -> Result<Vec<String>, RecipeError> {
    if let Some(text) = version.read_lock::<ImmutableString>() {
        return Ok(text.split('.').map(str::to_owned).collect());
    }
    let wrong = || {
        RecipeError::new(format!(
            "version must be a string like \"1.2.3\" or an array of strings, not {}",
            version.type_name()
        ))
    };
    let array = version.read_lock::<Array>().ok_or_else(wrong)?;
    array
        .iter()
        .map(|part| {
            part.read_lock::<ImmutableString>()
                .map(|part| part.to_string())
                .ok_or_else(wrong)
        })
        .collect()
}

/// Reject a step with a missing or unrecognised key.
///
/// `step()` always produces a well-formed map, but a plain map or dict literal in
/// `steps` is allowed too, and serde would silently ignore a misspelt key.
///
/// # Errors
///
/// Names the first step that is not a map, has an unknown key or lacks a
/// required one.
pub(crate) fn check_step_keys(package: &Json) -> miette::Result<()> {
    let steps = package["steps"].as_array().into_iter().flatten();
    for (index, step) in steps.enumerate() {
        let Some(map) = step.as_object() else {
            return Err(miette!(
                "steps[{index}] is not a step; build it with step(...)"
            ));
        };
        if let Some(unknown) = map.keys().find(|key| !STEP_KEYS.contains(&key.as_str())) {
            return Err(miette!(
                "steps[{index}] has an unknown key `{unknown}`; a step has {}",
                STEP_KEYS.join(", ")
            ));
        }
        for required in ["stage", "name", "run"] {
            if !map.contains_key(required) {
                return Err(miette!("steps[{index}] is missing `{required}`"));
            }
        }
        if serde_json::from_value::<Stage>(map["stage"].clone()).is_err() {
            return Err(miette!(
                "steps[{index}] has an unknown stage {}; use Prepare, Build, Install or Test",
                map["stage"]
            ));
        }
    }
    Ok(())
}

/// Evaluate a Rhai recipe and return the package it declares.
///
/// `file` is only the name shown in diagnostics.
///
/// # Errors
///
/// As [`evaluate`], as a diagnostic that points into the source.
pub fn parse(file: &str, text: String) -> miette::Result<BuildFile> {
    evaluate(&text).map_err(|error| {
        let mut diagnostic = MietteDiagnostic::new(error.message.clone());
        if let Some(help) = &error.help {
            diagnostic = diagnostic.with_help(help.clone());
        }
        if let Some((line, column)) = error.position {
            let offset = offset_of(&text, line, column);
            diagnostic = diagnostic.with_label(LabeledSpan::at_offset(offset, "here"));
        }
        Report::new(diagnostic).with_source_code(NamedSource::new(file, text))
    })
}

/// Byte offset of 1-based `line` and character `column` in `text`, clamped to its end.
fn offset_of(text: &str, line: usize, column: usize) -> usize {
    let line_start = text
        .split_inclusive('\n')
        .take(line.saturating_sub(1))
        .map(str::len)
        .sum::<usize>();
    let rest = &text[line_start.min(text.len())..];
    let within = rest
        .char_indices()
        .nth(column.saturating_sub(1))
        .map_or(rest.len(), |(offset, _)| offset);
    line_start + within
}

/// Render `build` as a Rhai recipe that evaluates back to the same package.
///
/// Output is deterministic: download maps are sorted by URL, and every value is
/// written as a literal, so a migrated file reads like one written by hand.
///
/// # Errors
///
/// Fails if a dependency path or the kernel image is not valid UTF-8, which a
/// Rhai string cannot represent.
pub fn render(build: &BuildFile) -> miette::Result<String> {
    let mut out = String::new();
    out.push_str("package(#{\n");
    let _ = writeln!(out, "    name: {},", quote(build.name()));
    let version = build.version();
    if version
        .iter()
        .all(|part| !part.is_empty() && !part.contains('.'))
    {
        let _ = writeln!(out, "    version: {},", quote(&version.join(".")));
    } else {
        let _ = writeln!(out, "    version: {},", list(version, 1));
    }
    let dependencies = build
        .dependencies()
        .map(|path| {
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| miette!("the dependency {} is not valid UTF-8", path.display()))
        })
        .collect::<miette::Result<Vec<_>>>()?;
    let _ = writeln!(out, "    dependencies: {},", list(&dependencies, 1));
    if build.steps().is_empty() {
        out.push_str("    steps: [],\n");
    } else {
        out.push_str("    steps: [\n");
        for step in build.steps() {
            out.push_str("        step(#{\n");
            let _ = writeln!(out, "            stage: {:?},", step.stage);
            let _ = writeln!(out, "            name: {},", quote(&step.name));
            let _ = writeln!(out, "            run: {},", list(&step.run, 3));
            if let Some(downloads) = &step.dl_urls {
                let mut sorted = downloads.iter().collect::<Vec<_>>();
                sorted.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
                if sorted.is_empty() {
                    out.push_str("            dl_urls: #{},\n");
                } else {
                    out.push_str("            dl_urls: #{\n");
                    for (url, sha) in sorted {
                        let _ = writeln!(
                            out,
                            "                {}: {},",
                            quote(url.as_str()),
                            quote(sha)
                        );
                    }
                    out.push_str("            },\n");
                }
            }
            out.push_str("        }),\n");
        }
        out.push_str("    ],\n");
    }
    if let Some(kernel) = build.kernel() {
        let image = kernel.image.to_str().ok_or_else(|| {
            miette!(
                "the kernel image {} is not valid UTF-8",
                kernel.image.display()
            )
        })?;
        let _ = write!(out, "    kernel: kernel({}", quote(image));
        if let Some(cmdline) = &kernel.cmdline {
            let _ = write!(out, ", {}", quote(cmdline));
        }
        out.push_str("),\n");
    }
    out.push_str("});\n");
    Ok(out)
}

/// A Rhai array literal; empty and single-line when there is nothing in it.
fn list<S: AsRef<str>>(items: &[S], depth: usize) -> String {
    if items.is_empty() {
        return "[]".to_owned();
    }
    let indent = "    ".repeat(depth);
    let mut out = String::from("[\n");
    for item in items {
        let _ = writeln!(out, "{indent}    {},", quote(item.as_ref()));
    }
    let _ = write!(out, "{indent}]");
    out
}

/// A double-quoted Rhai string literal for `text`.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
