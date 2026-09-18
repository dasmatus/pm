//! A pm plugin that teaches pm about building systemd system extension images.
//!
//! A sysext is a filesystem image that is merged over `/usr` at run time. Building one
//! means assembling a tree, writing an `extension-release` marker into it and packing it
//! with `systemd-repart`, `mksquashfs` or `mkfs.erofs`. pm's built-in fingerprint table
//! knows `tar`, `zip` and `xz` but none of the image packers, so a build file that makes
//! a sysext stops before it starts.
//!
//! # This plugin implements one hook, on purpose
//!
//! `scan-source` asks what the **built package will need at run time**. A
//! `systemd-repart` definition does not answer that question: `CopyFiles=` and
//! `MakeDirectories=` describe how an image is assembled at build time, and the paths in
//! them exist inside the image being made rather than on the machine that will run it.
//! Recording them as run-time grants would put the right paths in the wrong profile.
//!
//! So this plugin declares only [`Hook::ClassifyCommand`] and its `scan-source` export
//! returns nothing. pm calls a hook only when the manifest lists it, so the export is
//! never reached - the component model has no optional export, which is the only reason
//! it is written out at all.
//!
//! The systemd units and sysupdate transfer definitions a sysext ships *are* run-time
//! declarations, and the `systemd` and `sysupdate` plugins in this workspace read them.

wit_bindgen::generate!({ path: "../../wit", world: "plugin" });

use pm::plugin::{
    host::{Level, log},
    types::{Capability, Hook, Symbol},
};

struct SysExt;

/// The image tooling this plugin classifies, and what each needs from the build jail.
///
/// Two capabilities between them. The packers are doing what `tar` does in pm's own
/// table - walking a tree and compressing it - so they get [`Capability::Archive`]
/// alongside the file access everything here needs.
const TOOLS: &[(&[&str], &str, &[Capability])] = &[
    (
        &["systemd-repart"],
        "repart",
        &[Capability::Coreutils, Capability::Archive],
    ),
    (
        &[
            "mkfs.btrfs",
            "mkfs.erofs",
            "mkfs.ext4",
            "mkfs.squashfs",
            "mkfs.vfat",
            "mkfs.xfs",
            "mksquashfs",
        ],
        "mkfs",
        &[Capability::Coreutils, Capability::Archive],
    ),
    (
        &["systemd-confext", "systemd-sysext"],
        "sysext",
        &[Capability::Coreutils],
    ),
    (&["systemd-dissect"], "dissect", &[Capability::Coreutils]),
    (
        &["systemd-measure", "veritysetup"],
        "verity",
        &[Capability::Coreutils],
    ),
];

/// The directories a system extension is assembled from and installed into.
///
/// `extensionreleasedir` is the one worth having: every sysext image must carry an
/// `extension-release.<name>` file at exactly that path or systemd refuses to merge it,
/// and it is the single most common thing to get wrong when building one by hand.
const SYMBOLS: &[(&str, &str, &str)] = &[
    (
        "extensionreleasedir",
        "/usr/lib/extension-release.d",
        "where an image's extension-release marker must live",
    ),
    ("imagedir", "/var/lib/extensions", "system extension images"),
    (
        "confextdir",
        "/var/lib/confexts",
        "configuration extension images",
    ),
    (
        "repartdir",
        "/usr/lib/repart.d",
        "systemd-repart partition definitions",
    ),
];

/// Tools that fetch and assemble a whole distribution, and are therefore refused.
///
/// `mkosi` genuinely needs a compiler, a shell, an archiver and the network, so a
/// verdict for it would publish a ceiling wide enough to make reading `pm plugins`
/// pointless for this plugin. It is left unclassified for the same reason the `systemd`
/// plugin leaves `systemd-nspawn` alone: what it will run is not something anybody has
/// looked at, and pm's diagnostic naming the command is the better outcome.
const REFUSED: &[&str] = &["debootstrap", "mkosi", "pacstrap", "rpm-ostree"];

impl Guest for SysExt {
    fn describe() -> Manifest {
        Manifest {
            name: "sysext".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            summary: "Classifies the systemd system-extension image toolchain".into(),
            // One hook. See the module documentation for why there is no scanner here.
            hooks: vec![Hook::ClassifyCommand],
            grants_at_most: vec![Capability::Coreutils, Capability::Archive],
            source_extensions: Vec::new(),
            symbols: SYMBOLS
                .iter()
                .map(|(name, value, summary)| Symbol {
                    name: (*name).into(),
                    value: (*value).into(),
                    summary: (*summary).into(),
                })
                .collect(),
        }
    }

    fn classify_command(command: String) -> Option<Verdict> {
        let program = program_name(command.split_whitespace().next()?)?;

        if REFUSED.contains(&program) {
            log(
                Level::Info,
                &format!(
                    "`{program}` resolves and downloads a whole distribution; leaving it \
                     unclassified rather than publishing a ceiling wide enough to cover it"
                ),
            );
            return None;
        }

        let (_, fingerprint, capabilities) = TOOLS
            .iter()
            .find(|(names, _, _)| names.contains(&program))?;
        Some(Verdict {
            fingerprint: (*fingerprint).into(),
            capabilities: capabilities.to_vec(),
        })
    }

    /// Never called: [`Hook::ScanSource`] is not in the manifest.
    fn scan_source(_file: SourceFile) -> Vec<Grant> {
        Vec::new()
    }
}

/// The program name of a command's first word: the last path component.
fn program_name(word: &str) -> Option<&str> {
    let name = word.rsplit('/').next()?;
    (!name.is_empty()).then_some(name)
}

export!(SysExt);
