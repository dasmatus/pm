//! Measures the entrypoint classification in `ConfigFile::run`, before and
//! after the walk was made lazy.
//!
//! This is the O(files-in-the-package-tree) path, so it is the one where the
//! shape of the iterator can actually move the wall clock. Both variants end
//! up with the same `HashMap` — that collect is unavoidable, the map is a
//! serialized field — so what the timer isolates is the per-entry work: the
//! old shape paid an extra `stat` through `Path::metadata` for every entry,
//! and inserted directories into the map as if they were binaries.
//!
//! Harness scaffolding: `classify_old` reproduces deleted code verbatim,
//! unwraps included, and the fixture helper panics on setup failure. Neither
//! is a shipped path.

use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{File, create_dir_all},
    path::PathBuf,
};

use divan::{Bencher, black_box};
use tempfile::TempDir;
use walkdir::WalkDir;

fn main() {
    divan::main();
}

/// Stand-in for `metadata::Type`, which is crate-private.
#[derive(PartialEq, Eq)]
enum Type {
    Binary,
    Library(bool),
}

/// A package tree shaped like a real `make install` output: nested directories
/// with a mix of extensionless binaries, shared objects and static archives.
fn fixture(files: usize) -> TempDir {
    let dir = TempDir::new().unwrap();
    for index in 0..files {
        let sub = dir.path().join(format!("usr/lib/pkg{}", index % 16));
        create_dir_all(&sub).unwrap();
        let name = match index % 4 {
            0 => format!("bin{index}"),
            1 => format!("lib{index}.so"),
            2 => format!("lib{index}.a"),
            _ => format!("share{index}.txt"),
        };
        File::create(sub.join(name)).unwrap();
    }
    dir
}

/// The old shape: eager `map` into a `collect`, an extra `stat` per entry via
/// `Path::metadata`, and a panic waiting on any extensionless file.
#[divan::bench(args = [256, 2048])]
fn classify_old(bencher: Bencher, files: usize) {
    let tree = fixture(files);
    bencher.bench_local(|| {
        let map: HashMap<PathBuf, Type> = WalkDir::new(black_box(tree.path()))
            .into_iter()
            .map(|item| {
                let path = item.unwrap().into_path();
                let mut r#type = Type::Binary;
                // The original also unwrapped `extension()` here, which panics
                // on any extensionless file; relaxed so the bench can run.
                if path.metadata().unwrap().is_file()
                    && let Some(fext) = path.extension()
                {
                    if fext.eq("so") {
                        r#type = Type::Library(true);
                    } else if fext.eq("a") {
                        r#type = Type::Library(false);
                    }
                }
                (path, r#type)
            })
            .collect();
        black_box(map)
    });
}

/// The new shape: a lazy `filter_map` that reuses the file type readdir
/// already reported and skips directories entirely.
#[divan::bench(args = [256, 2048])]
fn classify_lazy(bencher: Bencher, files: usize) {
    let tree = fixture(files);
    bencher.bench_local(|| {
        let map: HashMap<PathBuf, Type> = WalkDir::new(black_box(tree.path()))
            .into_iter()
            .filter_map(|item| {
                let entry = item.ok()?;
                if !entry.file_type().is_file() {
                    return None;
                }
                let path = entry.into_path();
                let r#type = match path.extension().and_then(OsStr::to_str) {
                    Some("so") => Type::Library(true),
                    Some("a") => Type::Library(false),
                    _ => Type::Binary,
                };
                Some((path, r#type))
            })
            .collect();
        black_box(map)
    });
}
