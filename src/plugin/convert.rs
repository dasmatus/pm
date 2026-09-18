//! Turning what a plugin said into something pm is willing to act on.
//!
//! Everything crossing back from a plugin passes through here, and nothing reaches the
//! rest of the crate as the generated type it arrived as. That is deliberate: a plugin
//! is code somebody else wrote, and the component model only guarantees that its
//! answers have the right *shape*. It says nothing about whether the shape is filled
//! with a usable name, a path that is not empty, or a capability the plugin said it
//! would never ask for.
//!
//! The rules are all of the "reject or trim, never fail the build" kind. A plugin that
//! returns nonsense loses the nonsense and gets a `warn` line naming it; it does not get
//! to stop a package from building, because a plugin that can fail a build at will is a
//! plugin that can hold a build hostage.

use std::{collections::BTreeSet, path::PathBuf};

use tracing::warn;

use super::{
    Hook, Manifest,
    wit::{WitCapability, WitGrant, WitHook, WitManifest, WitPermission, WitVerdict},
};
use crate::{
    perms::{Grant, Permission, Provenance},
    policy::Capability,
};

/// Longest a plugin name or a fingerprint name may be.
///
/// Both end up in a column of `pm explain` or `pm plugins`, and both are meant to be
/// read at a glance.
const NAME_MAX: usize = 32;

/// Longest a version string may be. Shown, never parsed.
const VERSION_MAX: usize = 32;

/// Longest a one-line summary may be.
const SUMMARY_MAX: usize = 200;

/// Longest a file extension may be, without the dot.
const EXTENSION_MAX: usize = 16;

/// Longest an evidence line from a plugin may be.
///
/// The house format is one locator plus one reason; anything longer is a plugin
/// printing its own debugging into the permission report.
const EVIDENCE_MAX: usize = 200;

/// Longest a path in a plugin's grant may be.
const PATH_MAX: usize = 4096;

/// How many grants one `scan-source` call may contribute.
///
/// A file yielding more than this is a plugin with a runaway query, not a file with
/// sixty-five genuinely distinct permissions in it.
pub(super) const MAX_GRANTS_PER_FILE: usize = 64;

/// Read the manifest a plugin describes itself with, rejecting the parts pm cannot use.
///
/// The name is the one hard requirement: it prefixes every fingerprint the plugin
/// contributes and tags every log line and evidence line it causes, so a plugin without
/// a usable one has no way to be attributed and is refused outright. Everything else is
/// trimmed to size or dropped with a warning.
///
/// # Errors
///
/// Returns the reason as a string when the name is missing or malformed. That is the
/// only way this fails, and it fails at load time, where refusing a plugin is a
/// configuration error the user can see and fix.
pub(super) fn manifest(from: WitManifest, file: &str) -> Result<Manifest, String> {
    let name = name(&from.name).ok_or_else(|| {
        format!(
            "the plugin in {file} calls itself {:?}, which is not a usable name: \
             1 to {NAME_MAX} characters of a-z, 0-9 and `-`, at least one of them not `-`",
            from.name
        )
    })?;

    let hooks: BTreeSet<Hook> = from.hooks.into_iter().map(hook).collect();
    if hooks.is_empty() {
        warn!(
            plugin = %name,
            "declares no hooks, so it will never be called; it is loaded only to be listed"
        );
    }

    let grants_at_most: Vec<Capability> = {
        let mut set: BTreeSet<Capability> =
            from.grants_at_most.into_iter().map(capability).collect();
        // A ceiling nobody will ever be measured against is noise in `pm plugins`.
        if !hooks.contains(&Hook::ClassifyCommand) {
            set.clear();
        }
        set.into_iter().collect()
    };

    let source_extensions = if hooks.contains(&Hook::ScanSource) {
        from.source_extensions
            .into_iter()
            .filter_map(|raw| {
                extension(&raw).or_else(|| {
                    warn!(plugin = %name, extension = %raw, "not a usable file extension; ignored");
                    None
                })
            })
            .collect()
    } else {
        BTreeSet::new()
    };

    Ok(Manifest {
        name,
        version: clip(from.version, VERSION_MAX),
        summary: clip(from.summary, SUMMARY_MAX),
        hooks,
        grants_at_most,
        source_extensions,
    })
}

/// Read a classification verdict, holding the plugin to the ceiling it declared.
///
/// Two things can happen to a verdict here:
///
/// * **the fingerprint name is unusable** - the verdict is dropped whole, because a
///   grant pm cannot name is a grant pm cannot explain, and `pm explain` exists
///   precisely so that nothing in a policy is anonymous;
/// * **it asks for a capability outside [`Manifest::grants_at_most`]** - that capability
///   is dropped and the rest of the verdict stands. The ceiling is the plugin's own
///   published claim about itself, and holding it to that claim is what makes reading
///   `pm plugins` a substitute for reading the plugin.
///
/// Both are logged at `warn` against the plugin's name.
///
/// The name comes back prefixed with the plugin's own, so a plugin's fingerprint reads
/// `zig:zig-build` in `pm explain` and can never be mistaken for a built-in.
pub(super) fn verdict(from: WitVerdict, manifest: &Manifest) -> Option<(String, Vec<Capability>)> {
    let Some(fingerprint) = name(&from.fingerprint) else {
        warn!(
            plugin = %manifest.name,
            fingerprint = %from.fingerprint,
            "returned a verdict whose fingerprint name is not usable; ignoring the verdict"
        );
        return None;
    };

    let capabilities = from
        .capabilities
        .into_iter()
        .map(capability)
        .filter(|wanted| {
            let allowed = manifest.grants_at_most.contains(wanted);
            if !allowed {
                warn!(
                    plugin = %manifest.name,
                    capability = ?wanted,
                    ceiling = ?manifest.grants_at_most,
                    "asked for a capability outside the ceiling it published; dropping it"
                );
            }
            allowed
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    Some((format!("{}:{fingerprint}", manifest.name), capabilities))
}

/// Read the grants a `scan-source` call produced, dropping the unusable ones.
///
/// Each surviving grant is stamped [`Provenance::Plugin`] and its evidence line is
/// rewritten to lead with the file and name the plugin, so the permission report answers
/// "who asked for this, and about what?" without anyone having to correlate two columns.
/// At most [`MAX_GRANTS_PER_FILE`] survive one call.
pub(super) fn grants(from: Vec<WitGrant>, manifest: &Manifest, relative: &str) -> Vec<Grant> {
    let produced = from.len();
    let kept: Vec<Grant> = from
        .into_iter()
        .filter_map(|raw| {
            let permission = permission(raw.permission, manifest)?;
            let reason = clip(raw.evidence.replace(['\n', '\r'], " "), EVIDENCE_MAX);
            Some(Grant::new(
                permission,
                Provenance::Plugin,
                [format!("{relative}: {}: {reason}", manifest.name)],
            ))
        })
        .take(MAX_GRANTS_PER_FILE)
        .collect();

    // Only when the cap is what stopped it. A plugin returning ninety unusable grants
    // and ten good ones was not truncated, it was filtered, and saying otherwise sends
    // the reader looking for grants that were never there.
    if kept.len() == MAX_GRANTS_PER_FILE && produced > MAX_GRANTS_PER_FILE {
        warn!(
            plugin = %manifest.name,
            file = %relative,
            produced,
            kept = kept.len(),
            "returned more grants for one file than pm records; the rest were dropped"
        );
    }
    kept
}

/// Read one permission, or `None` when its path is not one pm can record.
///
/// An empty path would normalise to the current directory and quietly grant the whole
/// build tree; an over-long one and one holding a NUL are both things that cannot come
/// from a real source file and can only make trouble further down.
fn permission(from: WitPermission, manifest: &Manifest) -> Option<Permission> {
    let with_path = |raw: String, build: fn(PathBuf) -> Permission| {
        if raw.is_empty() || raw.len() > PATH_MAX || raw.contains('\0') {
            warn!(
                plugin = %manifest.name,
                bytes = raw.len(),
                "asked for a path that is empty, over-long or holds a NUL; dropping the grant"
            );
            return None;
        }
        Some(build(PathBuf::from(raw)))
    };

    match from {
        WitPermission::ReadPath(path) => with_path(path, Permission::ReadPath),
        WitPermission::WritePath(path) => with_path(path, Permission::WritePath),
        WitPermission::ExecPath(path) => with_path(path, Permission::ExecPath),
        WitPermission::Network => Some(Permission::Network),
        WitPermission::Spawn => Some(Permission::Spawn),
    }
}

/// Map a capability across the boundary. Total in both directions by construction: the
/// WIT enum is the Rust one, written out again.
fn capability(from: WitCapability) -> Capability {
    match from {
        WitCapability::Toolchain => Capability::Toolchain,
        WitCapability::Coreutils => Capability::Coreutils,
        WitCapability::Shell => Capability::Shell,
        WitCapability::Archive => Capability::Archive,
        WitCapability::Network => Capability::Network,
        WitCapability::VersionControl => Capability::VersionControl,
    }
}

/// Map a hook across the boundary.
fn hook(from: WitHook) -> Hook {
    match from {
        WitHook::ClassifyCommand => Hook::ClassifyCommand,
        WitHook::ScanSource => Hook::ScanSource,
    }
}

/// A plugin or fingerprint name, if `raw` is one.
///
/// The charset is narrow on purpose. These names are printed in aligned tables,
/// interpolated into evidence lines and used as a prefix separated by `:`, so anything
/// holding whitespace, a colon, a control character or a right-to-left override would
/// either break the layout or make one plugin's output look like another's.
fn name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let usable = !trimmed.is_empty()
        && trimmed.len() <= NAME_MAX
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && trimmed.bytes().any(|byte| byte != b'-');
    usable.then(|| trimmed.to_owned())
}

/// A file extension, without the dot, if `raw` is one.
fn extension(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('.').to_ascii_lowercase();
    let usable = !trimmed.is_empty()
        && trimmed.len() <= EXTENSION_MAX
        && trimmed.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || byte == b'+'
                || byte == b'-'
        });
    usable.then_some(trimmed)
}

/// Cut `text` to `max` characters on a character boundary, marking the cut.
fn clip(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        return text;
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}
