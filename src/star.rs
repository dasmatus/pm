//! Build files written in [Starlark](https://github.com/bazelbuild/starlark).
//!
//! A `.package` build file is a small, deterministic program that calls
//! `package(...)` exactly once. Evaluating it yields the same [`BuildFile`] a
//! YAML file describes, so everything downstream - signature checks, policy
//! derivation, the dependency graph, the sandbox - is unchanged. What Starlark
//! adds is the part YAML cannot express: loops, functions, conditionals and
//! comprehensions for generating steps and commands.
//!
//! # What a build file can do
//!
//! Evaluation is hermetic. The only things in scope are the Starlark core
//! library and the pm builtins below; there is no file or network access, no
//! environment, no clock, and **`load()` is disabled** - a signature covers one
//! file, so a build file that pulled code in from another would be vouching for
//! text nobody signed. Evaluation happens before the policy is derived and
//! before anything runs, so it needs no confinement of its own.
//!
//! | name | meaning |
//! |---|---|
//! | `package(name, version, dependencies = [], steps = [], kernel = None)` | declares the package; call it exactly once |
//! | `step(stage, name, run, dl_urls = None)` | one build step |
//! | `kernel(image, cmdline = None)` | a kernel the package ships, see [`crate::vm`] |
//! | `Prepare`, `Build`, `Install`, `Test` | the stage names, as strings |
//!
//! `version` is either a string (`"1.2.3"`, split on `.`) or a list of strings.
//! `dl_urls` is a dict mapping URL to SHA-256. `kernel(image = ...)` names a
//! kernel image the steps install, relative to `DESTDIR`; `pm run` boots it and
//! runs the package's entrypoint under it instead of the host's kernel.

use std::{cell::RefCell, fmt::Write as _, path::Path};

use miette::{IntoDiagnostic, WrapErr, miette};
use serde_json::{Value as Json, json};
use starlark::{
    any::ProvidesStaticType,
    environment::{Globals, GlobalsBuilder, Module},
    eval::Evaluator,
    starlark_module,
    syntax::{AstModule, Dialect},
    values::{
        Heap, UnpackValue, Value,
        dict::{AllocDict, UnpackDictEntries},
        list::UnpackList,
        none::{NoneOr, NoneType},
    },
};

use crate::{bf::BuildFile, step::Stage};

/// File extension of a Starlark build file, without the dot.
pub const EXTENSION: &str = "package";

/// Whether `path` names a Starlark build file; anything else is read as YAML.
#[must_use]
pub fn is_starlark(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == EXTENSION)
}

/// The Starlark dialect build files are written in.
///
/// Core Starlark plus top-level `for`/`if` (so steps can be generated without
/// wrapping everything in a function), keyword-only arguments and f-strings.
/// `load()` is switched off, see the module documentation.
#[must_use]
pub fn dialect() -> Dialect {
    Dialect {
        enable_load: false,
        enable_keyword_only_arguments: true,
        enable_top_level_stmt: true,
        enable_f_strings: true,
        ..Dialect::Standard
    }
}

/// Everything a build file can see: the Starlark core library plus the pm
/// builtins.
#[must_use]
pub fn globals() -> Globals {
    GlobalsBuilder::standard().with(pm_builtins).build()
}

/// What `package()` recorded, shared with the builtins through `Evaluator::extra`.
#[derive(Default, ProvidesStaticType)]
struct Collected {
    package: RefCell<Option<Json>>,
}

const STEP_KEYS: [&str; 4] = ["stage", "name", "run", "dl_urls"];

#[starlark_module]
#[allow(non_snake_case)]
fn pm_builtins(builder: &mut GlobalsBuilder) {
    /// The first stage: fetch and unpack sources, apply patches.
    const Prepare: &str = "Prepare";
    /// Compile.
    const Build: &str = "Build";
    /// Stage the built files under `DESTDIR`.
    const Install: &str = "Install";
    /// Run the package's test suite.
    const Test: &str = "Test";

    /// Declare the package this file builds. Call it exactly once.
    ///
    /// `version` is a string such as `"1.2.3"` or a list of strings. `dependencies`
    /// are paths to build files or `.cpkg` archives. `steps` is a list of `step(...)`.
    fn package<'v>(
        name: &str,
        version: Value<'v>,
        #[starlark(default = UnpackList::default())] dependencies: UnpackList<String>,
        #[starlark(default = UnpackList::default())] steps: UnpackList<Value<'v>>,
        #[starlark(default = NoneOr::None)] kernel: NoneOr<Value<'v>>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<NoneType> {
        let version = version_components(version)?;
        let mut rendered = Vec::with_capacity(steps.items.len());
        for step in &steps.items {
            rendered.push(step.to_json_value()?);
        }
        let mut package = json!({
            "name": name,
            "version": version,
            "dependencies": dependencies.items,
            "steps": rendered,
        });
        if let NoneOr::Other(kernel) = kernel {
            package["kernel"] = kernel.to_json_value()?;
        }
        let collected = eval
            .extra
            .and_then(|extra| extra.downcast_ref::<Collected>())
            .ok_or_else(|| anyhow::anyhow!("package() is not available in this context"))?;
        if collected.package.borrow_mut().replace(package).is_some() {
            return Err(anyhow::anyhow!("package() was called more than once").into());
        }
        Ok(NoneType)
    }

    /// One build step: optional downloads, then commands run in order.
    ///
    /// `stage` is one of `Prepare`, `Build`, `Install`, `Test`. `run` is a list of
    /// command strings - no shell is involved. `dl_urls` maps a URL to the SHA-256
    /// of what it must download.
    fn step<'v>(
        stage: &str,
        name: &str,
        run: UnpackList<String>,
        #[starlark(default = NoneOr::None)] dl_urls: NoneOr<UnpackDictEntries<String, String>>,
        heap: Heap<'v>,
    ) -> starlark::Result<Value<'v>> {
        if serde_json::from_value::<Stage>(Json::String(stage.to_owned())).is_err() {
            return Err(anyhow::anyhow!(
                "unknown stage {stage:?}; use Prepare, Build, Install or Test"
            )
            .into());
        }
        let mut entries: Vec<(&str, Value<'v>)> = vec![
            ("stage", heap.alloc(stage)),
            ("name", heap.alloc(name)),
            ("run", heap.alloc(run.items)),
        ];
        if let NoneOr::Other(downloads) = dl_urls {
            let map = downloads.entries.into_iter().collect::<Vec<_>>();
            entries.push(("dl_urls", heap.alloc(AllocDict(map))));
        }
        Ok(heap.alloc(AllocDict(entries)))
    }

    /// A kernel the package ships: `pm run` boots it in a virtual machine and runs
    /// the entrypoint under it, instead of on the host's kernel.
    ///
    /// `image` is the kernel image the steps install, relative to `DESTDIR`, such
    /// as `"boot/vmlinuz"`. `cmdline` is appended to the kernel command line pm
    /// boots it with.
    fn kernel<'v>(
        image: &str,
        #[starlark(default = NoneOr::None)] cmdline: NoneOr<&str>,
        heap: Heap<'v>,
    ) -> starlark::Result<Value<'v>> {
        let mut entries: Vec<(&str, Value<'v>)> = vec![("image", heap.alloc(image))];
        if let NoneOr::Other(cmdline) = cmdline {
            entries.push(("cmdline", heap.alloc(cmdline)));
        }
        Ok(heap.alloc(AllocDict(entries)))
    }
}

/// `version = "1.2.3"` or `version = ["1", "2", "3"]` to its components.
fn version_components(version: Value<'_>) -> starlark::Result<Vec<String>> {
    if let Some(text) = version.unpack_str() {
        return Ok(text.split('.').map(str::to_owned).collect());
    }
    match UnpackList::<String>::unpack_value(version)? {
        Some(list) => Ok(list.items),
        None => Err(anyhow::anyhow!(
            "version must be a string like \"1.2.3\" or a list of strings, not {}",
            version.get_type()
        )
        .into()),
    }
}

/// Evaluate a Starlark build file and return the package it declares.
///
/// `file` is only the name shown in diagnostics.
///
/// # Errors
///
/// Fails on a syntax or evaluation error, when `package()` is never called or
/// is called twice, or when what it declares is not a valid build file (an
/// unknown stage, a malformed download URL, a misspelt step key).
pub fn parse(file: &str, text: String) -> miette::Result<BuildFile> {
    let ast = AstModule::parse(file, text, &dialect()).map_err(|error| miette!("{error}"))?;
    let collected = Collected::default();
    Module::with_temp_heap(|module| {
        let mut eval = Evaluator::new(&module);
        eval.extra = Some(&collected);
        eval.eval_module(ast, &globals()).map(|_| ())
    })
    .map_err(|error| miette!("{error}"))?;

    let package = collected.package.into_inner().ok_or_else(|| {
        miette!(
            help = "Declare the package with package(name = ..., version = ..., steps = [...]).",
            "{file} never calls package()"
        )
    })?;
    check_step_keys(&package)?;
    serde_json::from_value(package)
        .into_diagnostic()
        .wrap_err_with(|| format!("{file} does not describe a valid build file"))
}

/// Reject a step dict with a missing or unrecognised key.
///
/// `step()` always produces a well-formed dict, but a plain `{...}` literal in
/// `steps` is allowed too, and serde would silently ignore a misspelt key.
fn check_step_keys(package: &Json) -> miette::Result<()> {
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
    }
    Ok(())
}

/// Render `build` as a Starlark build file that evaluates back to the same package.
///
/// Output is deterministic: download maps are sorted by URL, and every value is
/// written as a literal, so a migrated file reads like one written by hand.
///
/// # Errors
///
/// Fails if a dependency path or the kernel image is not valid UTF-8, which a Starlark string
/// cannot represent.
pub fn render(build: &BuildFile) -> miette::Result<String> {
    let mut out = String::new();
    out.push_str("package(\n");
    let _ = writeln!(out, "    name = {},", quote(build.name()));
    let version = build.version();
    if version
        .iter()
        .all(|part| !part.is_empty() && !part.contains('.'))
    {
        let _ = writeln!(out, "    version = {},", quote(&version.join(".")));
    } else {
        let _ = writeln!(out, "    version = {},", list(version, 1));
    }
    let dependencies = build
        .dependencies()
        .map(|path| {
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| miette!("the dependency {} is not valid UTF-8", path.display()))
        })
        .collect::<miette::Result<Vec<_>>>()?;
    let _ = writeln!(out, "    dependencies = {},", list(&dependencies, 1));
    if build.steps().is_empty() {
        out.push_str("    steps = [],\n");
    } else {
        out.push_str("    steps = [\n");
        for step in build.steps() {
            out.push_str("        step(\n");
            let _ = writeln!(out, "            stage = {:?},", step.stage);
            let _ = writeln!(out, "            name = {},", quote(&step.name));
            let _ = writeln!(out, "            run = {},", list(&step.run, 3));
            if let Some(downloads) = &step.dl_urls {
                let mut sorted = downloads.iter().collect::<Vec<_>>();
                sorted.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
                if sorted.is_empty() {
                    out.push_str("            dl_urls = {},\n");
                } else {
                    out.push_str("            dl_urls = {\n");
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
            out.push_str("        ),\n");
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
        let _ = write!(out, "    kernel = kernel(image = {}", quote(image));
        if let Some(cmdline) = &kernel.cmdline {
            let _ = write!(out, ", cmdline = {}", quote(cmdline));
        }
        out.push_str("),\n");
    }
    out.push_str(")\n");
    Ok(out)
}

/// A Starlark list literal; empty and single-line when there is nothing in it.
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

/// A double-quoted Starlark string literal for `text`.
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
            c if c.is_ascii_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
