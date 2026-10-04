//! Recipes (build files) written in [Rhai](https://rhai.rs).
//!
//! A `.rhai` recipe is a small, deterministic script that calls `package(...)`
//! exactly once. Evaluating it yields the same [`BuildFile`] a YAML or Starlark
//! file describes, so everything downstream - signature checks, policy
//! derivation, the dependency graph, the sandbox - is unchanged. What a script
//! adds over plain data is loops, functions, closures, objects and conditionals
//! for generating steps and commands.
//!
//! Rhai replaced Starlark as the recipe language. Starlark `.package` files still
//! load, with a deprecation warning, and `pm migrate` converts them (see
//! [`crate::migrate`]).
//!
//! # What a recipe can do
//!
//! Evaluation is hermetic. The only things in scope are Rhai's core language and
//! standard library, the pm builtins below and what installed plugins add; there
//! is no file or network access, no environment and no clock. **`import` and
//! `eval` are disabled**: a signature covers one file, so a recipe that pulled
//! code in from elsewhere would be vouching for text nobody signed. Unlike
//! Starlark, Rhai has unbounded loops and recursion, so evaluation runs under
//! operation, call-depth and size limits, and a recipe that exceeds them is an
//! error rather than a hang. Variables must be declared before use, so a misspelt
//! name is caught when the file is compiled, and so is reading a property an
//! object map does not have. `print` and `debug` go to pm's log, never to stdout.
//!
//! | name | meaning |
//! |---|---|
//! | `package(#{ name, version, dependencies, steps, kernel })`, `package(p)` | declares the package; call it exactly once |
//! | `Package(name, version)`, `Package(#{ ... })` | a package to build up before declaring it |
//! | `step(stage, name, run)`, `step(stage, name, run, dl_urls)`, `step(#{ ... })` | one build step, a `Step` |
//! | `kernel(image)`, `kernel(image, cmdline)`, `kernel(#{ ... })` | a kernel the package ships, a `Kernel`; see [`crate::vm`] |
//! | `Prepare`, `Build`, `Install`, `Test` | the stage names, as strings |
//! | `<plugin>::<name>` | a symbol or recipe function an installed plugin adds |
//!
//! Rhai has no keyword arguments, so `package` takes an object map, or a
//! `Package` built up beforehand. `version` is a string (`"1.2.3"`, split on `.`)
//! or an array of strings; `dependencies`, `steps` and `kernel` may be left out.
//! `dl_urls` is an object map from URL to SHA-256, with the URLs written as quoted
//! keys.
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
//!
//! # Objects
//!
//! `Step`, `Kernel` and `Package` are objects with properties and methods (see
//! [`types`]), and a recipe can define its own with object maps and closures,
//! where `this` is the map the closure was called on:
//!
//! ```rhai
//! let tool = #{
//!     prefix: "/usr",
//!     configure: |name| step(Build, name, [`./configure --prefix=${this.prefix}`, "make"]),
//! };
//! let p = Package("hello", "1.0.0");
//! p += tool.configure("compile");
//! p += step(Install, "stage", []).push("make install DESTDIR=/dest");
//! package(p);
//! ```
//!
//! # Plugins
//!
//! An installed plugin is a Rhai package of its own, under its name: its symbols
//! are constants and its recipe functions are functions, so `systemd::unitdir` and
//! `systemd::install_unit("foo.service")` work as written. A recipe function hands
//! back a `Step`, `Kernel`, `Package` or plain data, as the plugin declared. See
//! [`plugins`] and [`crate::plugin::RecipeFunction`].
//!
//! # How a recipe runs
//!
//! The engine is built once per thread (and again only when the plugin set
//! changes) with Rhai's full optimiser, which folds constants and pure calls at
//! compile time, and its fast built-in operators. The compiled script is then
//! lowered to bytecode and run on Rhai's Grain VM, which hands anything it cannot
//! lower back to the tree walker so the result is always the same; a script that
//! reads `global::` constants from inside a function, which Grain does not yet run
//! correctly, is walked instead.

mod plugins;
pub mod types;

use std::{cell::RefCell, fmt::Write as _, path::Path, rc::Rc};

use miette::{LabeledSpan, MietteDiagnostic, NamedSource, Report, miette};
use rhai::{
    AST, ASTNode, Array, Dynamic, Engine, EvalAltResult, Expr, FuncRegistration, ImmutableString,
    Map, NativeCallContext, OptimizationLevel, Position, Scope, Token,
    grain::{Compiler, Vm},
    module_resolvers::DummyModuleResolver,
    serde::from_dynamic,
};
use serde_json::Value as Json;

use crate::{bf::BuildFile, plugin::Registry, step::Stage};

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
/// Deepest expression nesting a recipe may be written with, at top level and
/// inside functions.
const MAX_EXPR_DEPTH: usize = 128;
/// Longest string a recipe may build, in bytes.
const MAX_STRING_SIZE: usize = 1 << 20;
/// Most elements in one array, or entries in one object map.
const MAX_COLLECTION_SIZE: usize = 100_000;
/// Most variables a recipe may have in scope at once.
const MAX_VARIABLES: usize = 10_000;
/// Most functions a recipe may define.
const MAX_FUNCTIONS: usize = 1_000;

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
pub const BUILTINS: &[Builtin] = &[
    Builtin {
        name: "package",
        signature: "package(#{ name: string, version: string | [string], dependencies: [string], steps: [Step], kernel: Kernel }) | package(p: Package)",
        doc: "Declare the package this file builds. Call it exactly once.\n\n\
              `version` is a string such as `\"1.2.3\"` or an array of strings. `dependencies` \
              are paths to recipes or `.cpkg` archives. `steps` is an array of `step(...)`. \
              `dependencies`, `steps` and `kernel` may be left out.",
    },
    Builtin {
        name: "Package",
        signature: "Package(name, version) -> Package | Package(#{ ... }) -> Package",
        doc: "Start a package to build up with methods and `+=`, then declare with `package(p)`.\n\n\
              Properties: `name`, `version`, `dependencies`, `steps`, `kernel`. Methods: \
              `depends_on(path)`, `add_step(step)`, `add_steps([step])`, `with_kernel(kernel)`, \
              `len()`, `to_map()`. `p += step` appends a step; `for s in p` visits the steps.",
    },
    Builtin {
        name: "step",
        signature: "step(stage, name, run) -> Step | step(stage, name, run, dl_urls) -> Step | step(#{ stage, name, run, dl_urls }) -> Step",
        doc: "One build step: optional downloads, then commands run in order.\n\n\
              `stage` is one of `Prepare`, `Build`, `Install`, `Test`. `run` is an array of \
              command strings - no shell is involved. `dl_urls` is an object map from a URL \
              (a quoted key) to the SHA-256 of what it must download.\n\n\
              Properties: `stage`, `name`, `run`, `dl_urls`. Methods: `push(command)`, \
              `download(url, sha256)`, `to_map()`. `s += command` appends a command.",
    },
    Builtin {
        name: "kernel",
        signature: "kernel(image) -> Kernel | kernel(image, cmdline) -> Kernel | kernel(#{ image, cmdline }) -> Kernel",
        doc: "A kernel the package ships: `pm run` boots it in a virtual machine and runs \
              the entrypoint under it, instead of on the host's kernel.\n\n\
              `image` is the kernel image the steps install, relative to `DESTDIR`, such as \
              `\"boot/vmlinuz\"`. `cmdline` is appended to the kernel command line pm boots it with.",
    },
    Builtin {
        name: "push",
        signature: "step.push(command) -> Step",
        doc: "Append a command to a step's `run`, and return the step.",
    },
    Builtin {
        name: "download",
        signature: "step.download(url, sha256) -> Step",
        doc: "Add a download to a step, by URL and the SHA-256 of what it must fetch, and \
              return the step.",
    },
    Builtin {
        name: "depends_on",
        signature: "package.depends_on(path) -> Package",
        doc: "Add a dependency (a path to a recipe or a `.cpkg`) and return the package.",
    },
    Builtin {
        name: "add_step",
        signature: "package.add_step(step) -> Package",
        doc: "Append a step (a `Step` or a step map) and return the package.",
    },
    Builtin {
        name: "add_steps",
        signature: "package.add_steps([step]) -> Package",
        doc: "Append an array of steps and return the package.",
    },
    Builtin {
        name: "with_kernel",
        signature: "package.with_kernel(kernel) -> Package",
        doc: "Set the package's kernel (a `Kernel`, a kernel map or `()`) and return the package.",
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

    fn from_eval(error: EvalAltResult) -> Self {
        let mut error = match error {
            // Point at the code inside the function the recipe defined, and say
            // which function it was.
            EvalAltResult::ErrorInFunctionCall(name, _, inner, _) => {
                let inner = Self::from_eval(*inner);
                return Self {
                    message: format!("{} (in {name}())", inner.message),
                    ..inner
                };
            }
            error => error,
        };
        let position = error.take_position();
        let message = match &error {
            // A message a builtin raised reads better without Rhai's prefix.
            EvalAltResult::ErrorRuntime(value, _) if value.is_string() => value.to_string(),
            _ => error.to_string(),
        };
        let error = Self::new(message).at(position);
        if error.message.contains("Function not found: package (") {
            error.help(PACKAGE_HELP)
        } else {
            error
        }
    }
}

const PACKAGE_HELP: &str =
    "package() takes one object map or a Package: package(#{ name: \"...\", version: \"...\" });";

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

thread_local! {
    /// This thread's engine, and the digest of the plugin set it was built for.
    ///
    /// Building an engine registers Rhai's standard library, pm's types and every
    /// plugin's module, which costs far more than evaluating a typical recipe; a
    /// dependency graph evaluates many recipes with the same plugins.
    static ENGINE: RefCell<Option<(String, Rc<Engine>)>> = const { RefCell::new(None) };

    /// What `package()` was called with during the evaluation running on this
    /// thread, and where.
    static DECLARED: RefCell<Option<(Map, Position)>> = const { RefCell::new(None) };
}

/// The engine for `plugins`, built on first use on this thread.
fn engine_for(plugins: &Registry) -> Rc<Engine> {
    ENGINE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((digest, engine)) = cache.as_ref()
            && digest == plugins.digest()
        {
            return Rc::clone(engine);
        }
        let engine = Rc::new(engine(plugins));
        *cache = Some((plugins.digest().to_owned(), Rc::clone(&engine)));
        engine
    })
}

/// A new engine with pm's dialect, builtins and `plugins`' modules.
fn engine(plugins: &Registry) -> Engine {
    let mut engine = Engine::new();
    engine
        // Fold constants and pure calls at compile time, and run arithmetic and
        // comparisons on built-in types without looking for overloads.
        .set_optimization_level(OptimizationLevel::Full)
        .set_fast_operators(true)
        // Catch misspellings before anything runs, and reading a property a map
        // does not have, instead of quietly getting `()`.
        .set_strict_variables(true)
        .set_fail_on_invalid_map_property(true)
        .set_max_operations(MAX_OPERATIONS)
        .set_max_call_levels(MAX_CALL_LEVELS)
        .set_max_expr_depths(MAX_EXPR_DEPTH, MAX_EXPR_DEPTH)
        .set_max_string_size(MAX_STRING_SIZE)
        .set_max_array_size(MAX_COLLECTION_SIZE)
        .set_max_map_size(MAX_COLLECTION_SIZE)
        .set_max_variables(MAX_VARIABLES)
        .set_max_functions(MAX_FUNCTIONS)
        // No modules from files: a signature covers one file.
        .set_max_modules(0)
        .set_module_resolver(DummyModuleResolver::new())
        .disable_symbol("import")
        .disable_symbol("eval")
        .on_print(|text| tracing::info!(target: "pm::recipe", "{text}"))
        .on_debug(|text, source, position| {
            tracing::debug!(target: "pm::recipe", ?source, %position, "{text}");
        });

    // `package` is a reserved word in Rhai. pm's recipes have called it that since
    // Starlark, so the tokenizer hands it on as an ordinary name.
    #[allow(deprecated)] // `on_parse_token` is marked volatile, not deprecated.
    engine.on_parse_token(|token, _, _| match token {
        Token::Reserved(word) if word.as_str() == "package" => Token::Identifier(word),
        token => token,
    });

    // Functions do not see the caller's scope, so the stage constants are
    // resolved here rather than pushed into it: they work inside a `fn` too.
    #[allow(deprecated)] // `on_var` is marked volatile, not deprecated.
    engine.on_var(|name, _, _| {
        Ok(STAGES
            .contains(&name)
            .then(|| Dynamic::from(ImmutableString::from(name))))
    });

    types::register(&mut engine);

    // Declaring the package is the one side effect a recipe has, so `package` is
    // volatile: the optimiser must leave every call where it is.
    FuncRegistration::new("package")
        .with_volatility(true)
        .with_params_info(["spec: Map", "()"])
        .with_comments(["/// Declare the package this file builds. Call it exactly once."])
        .register_into_engine(&mut engine, |context: NativeCallContext, spec: Map| {
            declare(&context, types::Package::from_map(spec)?)
        });
    FuncRegistration::new("package")
        .with_volatility(true)
        .with_params_info(["package: Package", "()"])
        .with_comments([
            "/// Declare a package built up with `Package(...)`. Call it exactly once.",
        ])
        .register_into_engine(
            &mut engine,
            |context: NativeCallContext, package: types::Package| declare(&context, package),
        );
    FuncRegistration::new("package")
        .with_volatility(true)
        .register_into_engine(&mut engine, |value: Dynamic| -> RhaiResult<()> {
            Err(format!("{PACKAGE_HELP} It was given {}.", value.type_name()).into())
        });

    for module in plugins.recipe_modules() {
        let namespace = module.namespace();
        if namespace == "global" || !rhai::is_valid_identifier(&namespace) {
            tracing::warn!(
                plugin = module.plugin(),
                "the plugin's name is not usable as a Rhai module name; recipes cannot reach it"
            );
            continue;
        }
        engine.register_static_module(namespace, plugins::module(&module).into());
    }

    engine
}

/// Record the package a recipe declares.
fn declare(context: &NativeCallContext, package: types::Package) -> RhaiResult<()> {
    let position = context.call_position();
    DECLARED.with(|declared| {
        let mut declared = declared.borrow_mut();
        if declared.is_some() {
            return Err(EvalAltResult::ErrorRuntime(
                "package() was called more than once".into(),
                position,
            )
            .into());
        }
        *declared = Some((package.to_map(), position));
        Ok(())
    })
}

/// Compile `text` with pm's dialect: strict variables, the stage constants known.
fn compile(engine: &Engine, text: &str) -> Result<AST, RecipeError> {
    let mut constants = Scope::new();
    for stage in STAGES {
        constants.push_constant(stage, ImmutableString::from(stage));
    }
    engine
        .compile_with_scope(&constants, text)
        .map_err(|error| {
            let position = error.position();
            let message = error.err_type().to_string();
            let error = RecipeError::new(message.clone()).at(position);
            if message.contains("'import'") {
                error.help("`import` is not supported in recipes: a signature covers one file.")
            } else if message.contains("'eval'") {
                error.help(
                    "`eval` is not supported in recipes: a signature covers the text as written.",
                )
            } else {
                error
            }
        })
}

/// Run a compiled recipe on the Grain bytecode VM, or on the tree walker when it
/// uses something Grain does not run faithfully yet.
fn run(engine: &Engine, ast: &AST) -> RhaiResult<()> {
    if reads_global_namespace(ast) {
        return engine.run_ast(ast);
    }
    let program = Compiler::new().compile(ast);
    Vm::new(engine).run(&program)
}

/// Whether `ast` names a `global::` variable, which Grain cannot yet resolve from
/// inside a function.
fn reads_global_namespace(ast: &AST) -> bool {
    !ast.walk(&mut |path: &[ASTNode]| {
        !matches!(
            path.last(),
            Some(ASTNode::Expr(Expr::Variable(variable, ..)))
                if !variable.2.is_empty() && variable.2.root() == "global"
        )
    })
}

/// Evaluate a recipe and return the package it declares, with no plugins.
///
/// This is [`parse`] without the diagnostic dressing, for callers such as
/// `pm-lsp` that place the error themselves.
///
/// # Errors
///
/// As [`evaluate_with`].
pub fn evaluate(text: &str) -> Result<BuildFile, RecipeError> {
    evaluate_with(text, Registry::none())
}

/// Evaluate a recipe with the modules `plugins` add and return the package it declares.
///
/// # Errors
///
/// Fails on a syntax or evaluation error, when a limit is exceeded, when
/// `package()` is never called or is called twice, or when what it declares is
/// not a valid build file (an unknown stage, a malformed download URL, a misspelt
/// key).
pub fn evaluate_with(text: &str, plugins: &Registry) -> Result<BuildFile, RecipeError> {
    let engine = engine_for(plugins);
    let ast = compile(&engine, text)?;
    DECLARED.with(|declared| declared.borrow_mut().take());
    let outcome = run(&engine, &ast);
    let declared = DECLARED.with(|declared| declared.borrow_mut().take());
    outcome.map_err(|error| RecipeError::from_eval(*error))?;
    let (spec, position) = declared.ok_or_else(|| {
        RecipeError::new("the recipe never calls package()")
            .help("Declare the package with package(#{ name: ..., version: ..., steps: [...] });")
    })?;
    to_build_file(spec).map_err(|error| error.at(position))
}

/// A Rhai definitions file (`.d.rhai`) describing everything a recipe can call
/// beyond Rhai's standard library: pm's builtins and types, and what `plugins`
/// add. Editors with a Rhai language server use it for completion and checking.
#[must_use]
pub fn definitions(plugins: &Registry) -> String {
    let engine = engine(plugins);
    let mut constants = Scope::new();
    for stage in STAGES {
        constants.push_constant(stage, ImmutableString::from(stage));
    }
    engine
        .definitions_with_scope(&constants)
        .include_standard_packages(false)
        .single_file()
}

/// Turn what `package()` was given into a [`BuildFile`].
fn to_build_file(spec: Map) -> Result<BuildFile, RecipeError> {
    // `plain` keeps a map a map; it only rewrites the pm objects inside it.
    let mut spec = types::plain(Dynamic::from_map(spec))
        .map_err(|error| RecipeError::from_eval(*error))?
        .cast::<Map>();
    let version = spec.remove("version").unwrap_or_default();
    let version = version_components(&version)?;
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

/// Evaluate a Rhai recipe, with no plugins, and return the package it declares.
///
/// `file` is only the name shown in diagnostics.
///
/// # Errors
///
/// As [`evaluate`], as a diagnostic that points into the source.
pub fn parse(file: &str, text: String) -> miette::Result<BuildFile> {
    parse_with(file, text, Registry::none())
}

/// [`parse`] with the modules `plugins` add.
///
/// # Errors
///
/// As [`evaluate_with`], as a diagnostic that points into the source.
pub fn parse_with(file: &str, text: String, plugins: &Registry) -> miette::Result<BuildFile> {
    evaluate_with(&text, plugins).map_err(|error| {
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
