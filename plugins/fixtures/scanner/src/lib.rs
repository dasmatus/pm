//! A fixture that contributes run-time permissions from a file type pm has no grammar
//! for.
//!
//! Reads `.toy` files, whose whole syntax is one directive per line:
//!
//! ```text
//! read /etc/toy.conf
//! write /var/log/toy.log
//! exec /usr/bin/toybox
//! network
//! spawn
//! ```
//!
//! Trivial on purpose: `tests/plugins.rs` is asserting what pm does with the grants -
//! that they arrive, that they carry `plugin` provenance, that the evidence names the
//! plugin and the file - not that a scanner is clever.

wit_bindgen::generate!({ path: "../../../wit", world: "plugin" });

use pm::plugin::{
    host::{Level, log},
    types::{Hook, Permission},
};

struct Scanner;

impl Guest for Scanner {
    fn describe() -> Manifest {
        Manifest {
            name: "toy".into(),
            version: "0.1.0".into(),
            summary: "Reads .toy directive files".into(),
            hooks: vec![Hook::ScanSource],
            grants_at_most: Vec::new(),
            source_extensions: vec!["toy".into()],
            symbols: Vec::new(),
        }
    }

    fn classify_command(_command: String) -> Option<Verdict> {
        None
    }

    fn scan_source(file: SourceFile) -> Vec<Grant> {
        log(Level::Debug, &format!("scanning {}", file.path));
        file.contents
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let mut words = line.split_whitespace();
                let permission = match (words.next()?, words.next()) {
                    ("read", Some(path)) => Permission::ReadPath(path.into()),
                    ("write", Some(path)) => Permission::WritePath(path.into()),
                    ("exec", Some(path)) => Permission::ExecPath(path.into()),
                    ("network", None) => Permission::Network,
                    ("spawn", None) => Permission::Spawn,
                    _ => return None,
                };
                Some(Grant {
                    permission,
                    evidence: format!("{}: directive", index + 1),
                })
            })
            .collect()
    }
}

export!(Scanner);
