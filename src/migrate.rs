//! Converting YAML build files to Starlark (`pm migrate`).
//!
//! The conversion is mechanical: the YAML is parsed exactly as `pm build` would
//! parse it and the resulting package is written back out as a `package(...)`
//! call by [`crate::star::render`]. The new file evaluates to the same package,
//! but three things do not carry over and are the caller's to handle:
//!
//! * **Signatures.** A signature covers one file's bytes, so the `.package` file has
//!   to be signed afresh with `pm sign`.
//! * **Comments.** They are not part of the parsed data and are dropped.
//! * **Dependency paths.** They are copied verbatim unless `recursive` is set, in
//!   which case YAML dependencies are converted too and their paths renamed.
//!   Relative paths are resolved against the current directory, as `pm build`
//!   resolves them.

use std::{
    collections::HashSet,
    fs::{OpenOptions, read_to_string, write},
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
};

use miette::{IntoDiagnostic, WrapErr, miette};

use crate::{bf::BuildFile, star};

/// One converted build file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    /// The YAML file that was read.
    pub source: PathBuf,
    /// Where the Starlark file belongs.
    pub target: PathBuf,
    /// The Starlark text.
    pub text: String,
}

/// Whether `path` names a YAML build file.
fn is_yaml(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
}

fn is_convertible_dependency(path: &Path) -> bool {
    !star::is_starlark(path) && !path.extension().is_some_and(|ext| ext == "cpkg")
}

/// The path of the Starlark file `source` converts to: `.yaml` and `.yml` become
/// `.package`, and anything else gets `.package` appended.
#[must_use]
pub fn target_path(source: &Path) -> PathBuf {
    if is_yaml(source) {
        source.with_extension(star::EXTENSION)
    } else {
        let mut name = source.as_os_str().to_owned();
        name.push(".");
        name.push(star::EXTENSION);
        PathBuf::from(name)
    }
}

/// Convert YAML build-file text to Starlark.
///
/// # Errors
///
/// Fails if `yaml` is not a valid build file, or a dependency path is not UTF-8.
pub fn convert_text(yaml: &str) -> miette::Result<String> {
    star::render(&BuildFile::from_yaml(yaml)?)
}

/// Convert the YAML build file at `source`, and with `recursive` every YAML
/// build file in its dependency closure, rewriting those dependency paths to
/// their `.package` counterparts. The first element is `source` itself.
///
/// Nothing is written; see [`write_converted`].
///
/// # Errors
///
/// Fails if a file cannot be read or is not a valid YAML build file. A
/// dependency that is already Starlark, or a `.cpkg`, is left alone.
pub fn convert_file(source: &Path, recursive: bool) -> miette::Result<Vec<Converted>> {
    let mut done = Vec::new();
    let mut seen = HashSet::new();
    convert_into(source, recursive, &mut seen, &mut done)?;
    // Dependencies are pushed ahead of their dependents, so the file the user
    // named is last; put it first.
    done.rotate_right(1);
    let mut targets = HashSet::new();
    for converted in &done {
        let parent = converted
            .target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let target = parent
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot resolve target directory {}", parent.display()))?
            .join(
                converted
                    .target
                    .file_name()
                    .ok_or_else(|| miette!("{} has no file name", converted.target.display()))?,
            );
        if !targets.insert(target.clone()) {
            return Err(miette!(
                "multiple source files map to the same target {}",
                target.display()
            ));
        }
    }
    Ok(done)
}

fn convert_into(
    source: &Path,
    recursive: bool,
    seen: &mut HashSet<PathBuf>,
    done: &mut Vec<Converted>,
) -> miette::Result<()> {
    let key = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    if !seen.insert(key) {
        return Ok(());
    }
    if star::is_starlark(source) {
        return Err(miette!(
            "{} is already a Starlark build file",
            source.display()
        ));
    }
    let text = read_to_string(source)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot read {}", source.display()))?;
    let mut build = BuildFile::from_yaml(&text)
        .wrap_err_with(|| format!("cannot convert {}", source.display()))?;

    if recursive {
        let dependencies = build
            .dependencies()
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        for dependency in dependencies
            .iter()
            .filter(|path| is_convertible_dependency(path))
        {
            convert_into(dependency, recursive, seen, done)?;
        }
        build.map_dependencies(|path| {
            if is_convertible_dependency(path) {
                target_path(path)
            } else {
                path.to_path_buf()
            }
        });
    }

    let rendered = star::render(&build)?;
    done.push(Converted {
        source: source.to_path_buf(),
        target: target_path(source),
        text: format!(
            "# Converted from {} by `pm migrate`. Comments were not carried over.\n\
             # Sign this file with `pm sign`; the old signature does not apply to it.\n\n{rendered}",
source.file_name().map_or_else(
                || {
                    source
                        .display()
                        .to_string()
                        .replace('\n', "\\n")
                        .replace('\r', "\\r")
                },
                |name| {
                    name.to_string_lossy()
                        .replace('\n', "\\n")
                        .replace('\r', "\\r")
                },
            ),
        ),
    });
    Ok(())
}

/// Write `converted` to `target` (its own target path when `None`).
///
/// # Errors
///
/// Fails if the file exists and `force` is not set, or cannot be written.
pub fn write_converted(
    converted: &Converted,
    target: Option<&Path>,
    force: bool,
) -> miette::Result<()> {
    let target = target.unwrap_or(&converted.target);
    if force {
        return write(target, &converted.text)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot write {}", target.display()));
    }
    // `create_new` makes "does it exist" and "create it" one syscall, so a file
    // that appears in between is refused rather than truncated.
    match OpenOptions::new().write(true).create_new(true).open(target) {
        Ok(mut file) => file
            .write_all(converted.text.as_bytes())
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot write {}", target.display())),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(miette!(
            help = "Pass --force to overwrite it.",
            "{} already exists.",
            target.display()
        )),
        Err(error) => Err(error)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot create {}", target.display())),
    }
}
