//! A pm plugin that teaches pm about `systemd-sysupdate`.
//!
//! `systemd-sysupdate` updates a host from transfer definitions - small unit-file-syntax
//! documents under `sysupdate.d/` saying where an image comes from and where it goes. A
//! package that ships one is shipping a run-time behaviour: after it is installed,
//! something on that machine will fetch a URL and write a partition or a file.
//!
//! * [`classify_command`] recognises `systemd-sysupdate` and `updatectl`, which pm's
//!   built-in table does not.
//! * [`scan_source`] reads transfer definitions and records that fetch and that write.
//!
//! # Claiming `.conf` honestly
//!
//! Transfer definitions are `*.conf` (and, since systemd 257, `*.transfer`). `.conf`
//! names nothing in particular - a source tree is full of them - so pm would hand this
//! plugin every one it finds. The plugin therefore **gates on content**: no `[Transfer]`
//! section, no grants at all, not even a plausible-looking guess. That is the pattern
//! for any plugin claiming a generic extension, and it is why `sysext` and this plugin
//! can both claim `.conf` without either one inventing facts about the other's files.

wit_bindgen::generate!({ path: "../../wit", world: "plugin" });

use pm::plugin::{
    host::{Level, log},
    types::{Capability, Hook, Permission},
};
use unitfile::{Directive, absolute_path, has_section, parse};

struct SysUpdate;

/// The section that identifies a transfer definition.
const GATE: &str = "Transfer";

/// `[Source] Type=` values that name a URL rather than a path.
const REMOTE_TYPES: &[&str] = &["url-file", "url-tar"];

/// Subcommands that only touch what is already on disk.
///
/// Everything else `systemd-sysupdate` does starts by asking the source where the newest
/// version is, which is a fetch even when nothing is downloaded in the end.
const LOCAL_SUBCOMMANDS: &[&str] = &["vacuum", "components"];

impl Guest for SysUpdate {
    fn describe() -> Manifest {
        Manifest {
            name: "sysupdate".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            summary: "Classifies systemd-sysupdate and reads its transfer definitions".into(),
            hooks: vec![Hook::ClassifyCommand, Hook::ScanSource],
            grants_at_most: vec![
                Capability::Coreutils,
                Capability::Network,
                Capability::Archive,
            ],
            source_extensions: vec!["conf".into(), "transfer".into()],
        }
    }

    /// Classify a `systemd-sysupdate` or `updatectl` invocation.
    ///
    /// The two are not the same thing from a jail's point of view, and the difference is
    /// worth getting right. `systemd-sysupdate` does the fetching itself, in the process
    /// pm launched. `updatectl` asks `systemd-sysupdated` over D-Bus to do it, so the
    /// command pm runs opens no socket of its own - granting it the network would be
    /// granting something that is not used.
    fn classify_command(command: String) -> Option<Verdict> {
        let mut words = command.split_whitespace();
        let program = program_name(words.next()?)?;

        let capabilities = match program {
            "updatectl" => vec![Capability::Coreutils],
            "systemd-sysupdate" | "sysupdate" => {
                let subcommand = words.find(|word| !word.starts_with('-'));
                if subcommand.is_some_and(|name| LOCAL_SUBCOMMANDS.contains(&name)) {
                    vec![Capability::Coreutils]
                } else {
                    vec![
                        Capability::Coreutils,
                        Capability::Network,
                        // `Type=url-tar` unpacks what it downloaded.
                        Capability::Archive,
                    ]
                }
            }
            _ => return None,
        };

        Some(Verdict {
            fingerprint: if program == "updatectl" {
                "updatectl".into()
            } else {
                "sysupdate".into()
            },
            capabilities,
        })
    }

    fn scan_source(file: SourceFile) -> Vec<Grant> {
        if !has_section(&file.contents, GATE) {
            return Vec::new();
        }
        log(
            Level::Debug,
            &format!("{} is a sysupdate transfer definition", file.path),
        );

        let directives = parse(&file.contents);
        let remote = is_remote(&directives);
        let mut grants = Vec::new();

        if remote {
            // The `[Source] Type=` directive is the evidence: it is the line that says
            // this definition reaches off the machine.
            if let Some(directive) = directives.iter().find(|d| d.is("Source", "Type")) {
                grants.push(grant(Permission::Network, directive));
            }
        }

        for directive in &directives {
            // A remote source's `Path=` is a URL, and a URL is not a path. Recording it
            // as one would put `https:/example.com` in the profile.
            if directive.is("Source", "Path") && !remote {
                grants.extend(path_grant(directive, false));
            }
            // A target `Path=` is where the update lands, whether that is a directory,
            // a regular file or the block device holding a partition.
            if directive.is("Target", "Path") {
                grants.extend(path_grant(directive, true));
            }
        }
        grants
    }
}

/// Whether the definition's source is a URL.
fn is_remote(directives: &[Directive]) -> bool {
    directives.iter().any(|directive| {
        directive.is("Source", "Type")
            && REMOTE_TYPES
                .iter()
                .any(|kind| directive.value.eq_ignore_ascii_case(kind))
    })
}

/// The absolute path a `Path=` directive names, as a read or a write.
fn path_grant(directive: &Directive, writes: bool) -> Vec<Grant> {
    absolute_path(&directive.value)
        .map(|path| {
            let permission = if writes {
                Permission::WritePath(path.into())
            } else {
                Permission::ReadPath(path.into())
            };
            grant(permission, directive)
        })
        .into_iter()
        .collect()
}

/// One grant, with the evidence line pm prefixes with the file and the plugin name.
fn grant(permission: Permission, directive: &Directive) -> Grant {
    Grant {
        permission,
        evidence: format!(
            "{}: [{}] {}=",
            directive.line, directive.section, directive.key
        ),
    }
}

/// The program name of a command's first word: the last path component.
fn program_name(word: &str) -> Option<&str> {
    let name = word.rsplit('/').next()?;
    (!name.is_empty()).then_some(name)
}

export!(SysUpdate);
