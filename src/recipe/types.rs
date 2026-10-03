//! The types a recipe builds its package out of: `Step`, `Kernel` and `Package`.
//!
//! Each is a Rhai custom type with properties and methods, so a recipe can build a
//! package the object-oriented way:
//!
//! ```rhai
//! let p = Package("hello", "1.0.0");
//! p += step(Build, "compile", []).push("make").push("make check");
//! p.depends_on("../libc/build.rhai");
//! package(p);
//! ```
//!
//! Each also has a plain object-map spelling - `step(#{ ... })`, `kernel(#{ ... })`,
//! `package(#{ ... })` - and the two mix freely: a map is checked and converted the
//! moment it is handed to a constructor, and [`plain`] turns the typed values back into
//! maps once evaluation is over, so the rest of pm only ever sees one shape.
//!
//! A method that changes the value it is called on also returns the changed value, so
//! calls chain on a freshly built one (`step(...).push("a").push("b")`). Rhai passes the
//! returned value on, not the variable, so on a variable call them one at a time, or use
//! `+=`.

use rhai::{
    Array, CustomType, Dynamic, Engine, EvalAltResult, FuncRegistration, ImmutableString, Map,
    TypeBuilder,
};
use serde_json::Value as Json;

use super::{KERNEL_KEYS, PACKAGE_KEYS, RhaiResult, STAGES, STEP_KEYS};
use crate::plugin::RecipeValue;

/// One build step: optional downloads, then commands run in order.
#[derive(Debug, Clone)]
pub(super) struct Step {
    stage: ImmutableString,
    name: ImmutableString,
    run: Array,
    dl_urls: Option<Map>,
}

/// A kernel the package ships.
#[derive(Debug, Clone)]
pub(super) struct Kernel {
    image: ImmutableString,
    cmdline: Option<ImmutableString>,
}

/// A package being built up, before `package()` declares it.
#[derive(Debug, Clone)]
pub(super) struct Package {
    name: ImmutableString,
    /// A string or an array of strings, as a recipe wrote it.
    version: Dynamic,
    dependencies: Array,
    steps: Array,
    kernel: Option<Kernel>,
}

impl Step {
    fn new(
        stage: &str,
        name: ImmutableString,
        run: Array,
        dl_urls: Option<Map>,
    ) -> RhaiResult<Self> {
        Ok(Self {
            stage: check_stage(stage)?,
            name,
            run,
            dl_urls,
        })
    }

    fn from_map(spec: Map) -> RhaiResult<Self> {
        check_keys("step()", &spec, &STEP_KEYS, &["stage", "name", "run"])?;
        let stage = string("step()", "stage", &spec["stage"])?;
        let name = string("step()", "name", &spec["name"])?;
        let run = array("step()", "run", &spec["run"])?;
        let dl_urls = match spec.get("dl_urls") {
            None => None,
            Some(value) => optional_map("step()", "dl_urls", value)?,
        };
        Self::new(&stage, name, run, dl_urls)
    }

    fn to_map(&self) -> Map {
        let mut map = Map::new();
        map.insert("stage".into(), self.stage.clone().into());
        map.insert("name".into(), self.name.clone().into());
        map.insert("run".into(), self.run.clone().into());
        if let Some(dl_urls) = &self.dl_urls {
            map.insert("dl_urls".into(), dl_urls.clone().into());
        }
        map
    }

    fn push(&mut self, command: ImmutableString) -> Self {
        self.run.push(command.into());
        self.clone()
    }

    fn download(&mut self, url: ImmutableString, sha256: ImmutableString) -> Self {
        self.dl_urls
            .get_or_insert_with(Map::new)
            .insert(url.as_str().into(), sha256.into());
        self.clone()
    }
}

impl CustomType for Step {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_name("Step")
            .with_comments(&[
                "/// One build step: optional downloads, then commands run in order.",
                "///",
                "/// Built with `step(stage, name, run)`, `step(stage, name, run, dl_urls)` or",
                "/// `step(#{ stage, name, run, dl_urls })`.",
            ])
            .with_get_set(
                "stage",
                |step: &mut Self| step.stage.clone(),
                |step: &mut Self, stage: ImmutableString| -> RhaiResult<()> {
                    step.stage = check_stage(&stage)?;
                    Ok(())
                },
            )
            .with_get_set(
                "name",
                |step: &mut Self| step.name.clone(),
                |step: &mut Self, name: ImmutableString| step.name = name,
            )
            .with_get_set(
                "run",
                |step: &mut Self| step.run.clone(),
                |step: &mut Self, run: Array| step.run = run,
            )
            .with_get_set(
                "dl_urls",
                |step: &mut Self| {
                    step.dl_urls
                        .clone()
                        .map_or(Dynamic::UNIT, Dynamic::from_map)
                },
                |step: &mut Self, value: Dynamic| -> RhaiResult<()> {
                    step.dl_urls = optional_map("Step", "dl_urls", &value)?;
                    Ok(())
                },
            )
            .with_fn("push", Self::push)
            .and_comments(&["/// Append a command to `run`, and return the step."])
            .with_fn("download", Self::download)
            .and_comments(&[
                "/// Add a download, by URL and the SHA-256 of what it must fetch, and return",
                "/// the step.",
            ])
            .with_fn("+=", |step: &mut Self, command: ImmutableString| {
                step.run.push(command.into());
            })
            .with_fn("+", |mut step: Self, command: ImmutableString| {
                step.run.push(command.into());
                step
            })
            .with_fn("to_map", |step: &mut Self| step.to_map())
            .and_comments(&["/// The step as an object map, as `step(#{ ... })` takes it."])
            .on_print(|step| format!("step {:?} ({})", step.name.as_str(), step.stage))
            .on_debug(|step| format!("{:?}", Dynamic::from_map(step.to_map())));
    }
}

impl Kernel {
    fn from_map(spec: Map) -> RhaiResult<Self> {
        check_keys("kernel()", &spec, &KERNEL_KEYS, &["image"])?;
        let image = string("kernel()", "image", &spec["image"])?;
        let cmdline = match spec.get("cmdline") {
            None => None,
            Some(value) if value.is_unit() => None,
            Some(value) => Some(string("kernel()", "cmdline", value)?),
        };
        Ok(Self { image, cmdline })
    }

    fn to_map(&self) -> Map {
        let mut map = Map::new();
        map.insert("image".into(), self.image.clone().into());
        if let Some(cmdline) = &self.cmdline {
            map.insert("cmdline".into(), cmdline.clone().into());
        }
        map
    }
}

impl CustomType for Kernel {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_name("Kernel")
            .with_comments(&[
                "/// A kernel the package ships, which `pm run` boots the entrypoint under.",
                "///",
                "/// Built with `kernel(image)`, `kernel(image, cmdline)` or",
                "/// `kernel(#{ image, cmdline })`.",
            ])
            .with_get_set(
                "image",
                |kernel: &mut Self| kernel.image.clone(),
                |kernel: &mut Self, image: ImmutableString| kernel.image = image,
            )
            .with_get_set(
                "cmdline",
                |kernel: &mut Self| kernel.cmdline.clone().map_or(Dynamic::UNIT, Dynamic::from),
                |kernel: &mut Self, value: Dynamic| -> RhaiResult<()> {
                    kernel.cmdline = if value.is_unit() {
                        None
                    } else {
                        Some(string("Kernel", "cmdline", &value)?)
                    };
                    Ok(())
                },
            )
            .with_fn("to_map", |kernel: &mut Self| kernel.to_map())
            .and_comments(&["/// The kernel as an object map, as `kernel(#{ ... })` takes it."])
            .on_print(|kernel| format!("kernel {:?}", kernel.image.as_str()))
            .on_debug(|kernel| format!("{:?}", Dynamic::from_map(kernel.to_map())));
    }
}

impl Package {
    fn new(name: ImmutableString, version: Dynamic) -> RhaiResult<Self> {
        Ok(Self {
            name,
            version: check_version(version)?,
            dependencies: Array::new(),
            steps: Array::new(),
            kernel: None,
        })
    }

    pub(super) fn from_map(spec: Map) -> RhaiResult<Self> {
        check_keys("package()", &spec, &PACKAGE_KEYS, &["name", "version"])?;
        let mut package = Self::new(
            string("package()", "name", &spec["name"])?,
            spec["version"].clone(),
        )?;
        if let Some(dependencies) = spec.get("dependencies").filter(|value| !value.is_unit()) {
            package.dependencies = array("package()", "dependencies", dependencies)?;
        }
        if let Some(steps) = spec.get("steps").filter(|value| !value.is_unit()) {
            package.set_steps(array("package()", "steps", steps)?)?;
        }
        if let Some(kernel) = spec.get("kernel") {
            package.kernel = to_kernel(kernel.clone())?;
        }
        Ok(package)
    }

    pub(super) fn to_map(&self) -> Map {
        let mut map = Map::new();
        map.insert("name".into(), self.name.clone().into());
        map.insert("version".into(), self.version.clone());
        map.insert("dependencies".into(), self.dependencies.clone().into());
        map.insert("steps".into(), self.steps.clone().into());
        if let Some(kernel) = &self.kernel {
            map.insert("kernel".into(), Dynamic::from(kernel.clone()));
        }
        map
    }

    fn set_steps(&mut self, steps: Array) -> RhaiResult<()> {
        self.steps = steps.into_iter().map(to_step).collect::<RhaiResult<_>>()?;
        Ok(())
    }

    fn add_step(&mut self, step: Dynamic) -> RhaiResult<Self> {
        self.steps.push(to_step(step)?);
        Ok(self.clone())
    }

    fn add_steps(&mut self, steps: Array) -> RhaiResult<Self> {
        for step in steps {
            self.steps.push(to_step(step)?);
        }
        Ok(self.clone())
    }

    fn depends_on(&mut self, dependency: ImmutableString) -> Self {
        self.dependencies.push(dependency.into());
        self.clone()
    }

    fn with_kernel(&mut self, kernel: Dynamic) -> RhaiResult<Self> {
        self.kernel = to_kernel(kernel)?;
        Ok(self.clone())
    }
}

impl IntoIterator for Package {
    type Item = Dynamic;
    type IntoIter = std::vec::IntoIter<Dynamic>;

    /// A package iterates over its steps.
    fn into_iter(self) -> Self::IntoIter {
        self.steps.into_iter()
    }
}

impl CustomType for Package {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_name("Package")
            .with_comments(&[
                "/// A package being built up. Declare it with `package(p)` once it is done.",
                "///",
                "/// Built with `Package(name, version)` or `Package(#{ ... })`. Iterating over",
                "/// a package visits its steps.",
            ])
            .with_get_set(
                "name",
                |package: &mut Self| package.name.clone(),
                |package: &mut Self, name: ImmutableString| package.name = name,
            )
            .with_get_set(
                "version",
                |package: &mut Self| package.version.clone(),
                |package: &mut Self, version: Dynamic| -> RhaiResult<()> {
                    package.version = check_version(version)?;
                    Ok(())
                },
            )
            .with_get_set(
                "dependencies",
                |package: &mut Self| package.dependencies.clone(),
                |package: &mut Self, dependencies: Array| package.dependencies = dependencies,
            )
            .with_get_set(
                "steps",
                |package: &mut Self| package.steps.clone(),
                |package: &mut Self, steps: Array| package.set_steps(steps),
            )
            .with_get_set(
                "kernel",
                |package: &mut Self| package.kernel.clone().map_or(Dynamic::UNIT, Dynamic::from),
                |package: &mut Self, kernel: Dynamic| -> RhaiResult<()> {
                    package.kernel = to_kernel(kernel)?;
                    Ok(())
                },
            )
            .with_fn("depends_on", Self::depends_on)
            .and_comments(&[
                "/// Add a dependency: a path to a recipe or a `.cpkg`. Returns the package.",
            ])
            .with_fn("add_step", Self::add_step)
            .and_comments(&["/// Append a step (a `Step` or a step map). Returns the package."])
            .with_fn("add_steps", Self::add_steps)
            .and_comments(&["/// Append an array of steps. Returns the package."])
            .with_fn("with_kernel", Self::with_kernel)
            .and_comments(&[
                "/// Set the kernel (a `Kernel`, a kernel map or `()`). Returns the package.",
            ])
            .with_fn("+=", |package: &mut Self, step: Step| {
                package.steps.push(Dynamic::from(step));
            })
            .with_fn("+=", |package: &mut Self, steps: Array| -> RhaiResult<()> {
                package.add_steps(steps).map(drop)
            })
            .with_fn("+", |mut package: Self, step: Step| {
                package.steps.push(Dynamic::from(step));
                package
            })
            .with_fn("len", |package: &mut Self| {
                i64::try_from(package.steps.len()).unwrap_or(i64::MAX)
            })
            .and_comments(&["/// How many steps the package has."])
            .with_fn("to_map", |package: &mut Self| package.to_map())
            .and_comments(&["/// The package as an object map, as `package(#{ ... })` takes it."])
            .on_print(|package| format!("package {:?} {}", package.name.as_str(), package.version))
            .on_debug(|package| format!("{:?}", Dynamic::from_map(package.to_map())))
            .is_iterable();
    }
}

/// Register the types and their constructors.
pub(super) fn register(engine: &mut Engine) {
    engine
        .build_type::<Step>()
        .build_type::<Kernel>()
        .build_type::<Package>();

    FuncRegistration::new("step")
        .with_params_info(["stage: &str", "name: &str", "run: Array", "Step"])
        .with_comments(["/// One build step: `stage` is `Prepare`, `Build`, `Install` or `Test`,\n/// `run` an array of commands - no shell is involved."])
        .register_into_engine(engine, |stage: &str, name: ImmutableString, run: Array| {
            Step::new(stage, name, run, None)
        });
    FuncRegistration::new("step")
        .with_params_info(["stage: &str", "name: &str", "run: Array", "dl_urls: Map", "Step"])
        .with_comments(["/// One build step that first downloads `dl_urls`: an object map from a\n/// URL (a quoted key) to the SHA-256 of what it must fetch."])
        .register_into_engine(
            engine,
            |stage: &str, name: ImmutableString, run: Array, dl_urls: Map| {
                Step::new(stage, name, run, Some(dl_urls))
            },
        );
    FuncRegistration::new("step")
        .with_params_info(["spec: Map", "Step"])
        .with_comments(["/// One build step, from an object map with `stage`, `name`, `run` and\n/// optionally `dl_urls`."])
        .register_into_engine(engine, Step::from_map);

    FuncRegistration::new("kernel")
        .with_params_info(["image: &str", "Kernel"])
        .with_comments(["/// A kernel the package ships: `image` is relative to `DESTDIR`."])
        .register_into_engine(engine, |image: ImmutableString| Kernel {
            image,
            cmdline: None,
        });
    FuncRegistration::new("kernel")
        .with_params_info(["image: &str", "cmdline: &str", "Kernel"])
        .with_comments(["/// A kernel the package ships, booted with `cmdline` appended to the\n/// kernel command line."])
        .register_into_engine(engine, |image: ImmutableString, cmdline: ImmutableString| {
            Kernel {
                image,
                cmdline: Some(cmdline),
            }
        });
    FuncRegistration::new("kernel")
        .with_params_info(["spec: Map", "Kernel"])
        .with_comments(["/// A kernel, from an object map with `image` and optionally `cmdline`."])
        .register_into_engine(engine, Kernel::from_map);

    FuncRegistration::new("Package")
        .with_params_info(["name: &str", "version: Dynamic", "Package"])
        .with_comments(["/// Start a package. `version` is a string such as `\"1.2.3\"` or an array\n/// of strings. Declare it with `package(p)` when it is complete."])
        .register_into_engine(engine, |name: ImmutableString, version: Dynamic| {
            Package::new(name, version)
        });
    FuncRegistration::new("Package")
        .with_params_info(["spec: Map", "Package"])
        .with_comments(["/// Start a package from an object map, as `package(#{ ... })` takes it."])
        .register_into_engine(engine, Package::from_map);
}

/// `value` with every `Step`, `Kernel` and `Package` in it turned into the object map
/// it stands for, for serde.
pub(super) fn plain(value: Dynamic) -> Dynamic {
    if value.is::<Step>() {
        return Dynamic::from_map(value.cast::<Step>().to_map());
    }
    if value.is::<Kernel>() {
        return Dynamic::from_map(value.cast::<Kernel>().to_map());
    }
    if value.is::<Package>() {
        return plain(Dynamic::from_map(value.cast::<Package>().to_map()));
    }
    if value.is_array() {
        return value
            .cast::<Array>()
            .into_iter()
            .map(plain)
            .collect::<Array>()
            .into();
    }
    if value.is_map() {
        return Dynamic::from_map(
            value
                .cast::<Map>()
                .into_iter()
                .map(|(key, value)| (key, plain(value)))
                .collect(),
        );
    }
    value
}

/// What a plugin's recipe function answered, as the recipe sees it.
///
/// # Errors
///
/// When the answer is not of the kind the function declared, or holds a number with
/// a fraction (recipes have no floating point).
pub(super) fn from_json(value: Json, kind: RecipeValue) -> RhaiResult<Dynamic> {
    let value = json_to_dynamic(value)?;
    let map = |what: &str| {
        value
            .clone()
            .try_cast::<Map>()
            .ok_or_else(|| -> Box<EvalAltResult> {
                format!("expected {what} as an object, not {}", value.type_name()).into()
            })
    };
    Ok(match kind {
        RecipeValue::Any => value,
        RecipeValue::Step => Dynamic::from(Step::from_map(map("a step")?)?),
        RecipeValue::Kernel => Dynamic::from(Kernel::from_map(map("a kernel")?)?),
        RecipeValue::Package => Dynamic::from(Package::from_map(map("a package")?)?),
        RecipeValue::Steps => {
            let steps =
                value
                    .clone()
                    .try_cast::<Array>()
                    .ok_or_else(|| -> Box<EvalAltResult> {
                        format!("expected an array of steps, not {}", value.type_name()).into()
                    })?;
            steps
                .into_iter()
                .map(to_step)
                .collect::<RhaiResult<Array>>()?
                .into()
        }
    })
}

/// A JSON value as the Rhai value it stands for. Written out rather than left to
/// serde, which hands back a map in place of a number when `serde_json` is built with
/// arbitrary precision.
fn json_to_dynamic(value: Json) -> RhaiResult<Dynamic> {
    Ok(match value {
        Json::Null => Dynamic::UNIT,
        Json::Bool(value) => value.into(),
        Json::Number(number) => number
            .as_i64()
            .ok_or_else(|| -> Box<EvalAltResult> {
                format!("{number} is not an integer, and a recipe has no floating-point numbers")
                    .into()
            })?
            .into(),
        Json::String(text) => text.into(),
        Json::Array(items) => items
            .into_iter()
            .map(json_to_dynamic)
            .collect::<RhaiResult<Array>>()?
            .into(),
        Json::Object(entries) => Dynamic::from_map(
            entries
                .into_iter()
                .map(|(key, value)| Ok((key.into(), json_to_dynamic(value)?)))
                .collect::<RhaiResult<Map>>()?,
        ),
    })
}

/// A `Step`, or a step map checked and converted to one.
fn to_step(value: Dynamic) -> RhaiResult<Dynamic> {
    if value.is::<Step>() {
        return Ok(value);
    }
    let type_name = value.type_name();
    match value.try_cast::<Map>() {
        Some(map) => Ok(Dynamic::from(Step::from_map(map)?)),
        None => Err(format!("a step must be a Step or an object map, not {type_name}").into()),
    }
}

/// A `Kernel`, a kernel map checked and converted to one, or `()` for none.
fn to_kernel(value: Dynamic) -> RhaiResult<Option<Kernel>> {
    if value.is_unit() {
        return Ok(None);
    }
    if value.is::<Kernel>() {
        return Ok(Some(value.cast()));
    }
    let type_name = value.type_name();
    match value.try_cast::<Map>() {
        Some(map) => Ok(Some(Kernel::from_map(map)?)),
        None => {
            Err(format!("a kernel must be a Kernel, an object map or (), not {type_name}").into())
        }
    }
}

fn check_stage(stage: &str) -> RhaiResult<ImmutableString> {
    if STAGES.contains(&stage) {
        Ok(stage.into())
    } else {
        Err(format!("unknown stage {stage:?}; use Prepare, Build, Install or Test").into())
    }
}

/// A version is a string such as `"1.2.3"` or an array of strings.
fn check_version(version: Dynamic) -> RhaiResult<Dynamic> {
    let ok = version.is_string()
        || version
            .read_lock::<Array>()
            .is_some_and(|parts| parts.iter().all(Dynamic::is_string));
    if ok {
        Ok(version)
    } else {
        Err(format!(
            "version must be a string like \"1.2.3\" or an array of strings, not {}",
            version.type_name()
        )
        .into())
    }
}

pub(super) fn check_keys(
    what: &str,
    map: &Map,
    allowed: &[&str],
    required: &[&str],
) -> RhaiResult<()> {
    if let Some(unknown) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!(
            "{what} has an unknown key `{unknown}`; it takes {}",
            allowed.join(", ")
        )
        .into());
    }
    if let Some(missing) = required.iter().find(|key| !map.contains_key(**key)) {
        return Err(format!("{what} is missing `{missing}`").into());
    }
    Ok(())
}

fn string(what: &str, key: &str, value: &Dynamic) -> RhaiResult<ImmutableString> {
    value
        .read_lock::<ImmutableString>()
        .map(|text| text.clone())
        .ok_or_else(|| {
            format!(
                "{what}: `{key}` must be a string, not {}",
                value.type_name()
            )
            .into()
        })
}

fn array(what: &str, key: &str, value: &Dynamic) -> RhaiResult<Array> {
    value
        .read_lock::<Array>()
        .map(|items| items.clone())
        .ok_or_else(|| {
            format!(
                "{what}: `{key}` must be an array, not {}",
                value.type_name()
            )
            .into()
        })
}

fn optional_map(what: &str, key: &str, value: &Dynamic) -> RhaiResult<Option<Map>> {
    if value.is_unit() {
        return Ok(None);
    }
    value
        .read_lock::<Map>()
        .map(|map| Some(map.clone()))
        .ok_or_else(|| {
            format!(
                "{what}: `{key}` must be an object map or (), not {}",
                value.type_name()
            )
            .into()
        })
}
