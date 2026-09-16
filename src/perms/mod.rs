//! The permission model: what a package is allowed to do at run time, and why.
//!
//! Every package used to get the *same* run sandbox. This module replaces that with a
//! per-package permission set, derived from three independent signals that each live in
//! a sibling module:
//!
//! - [`source`] reads the package's sources with tree-sitter,
//! - [`monitor`] watches one real execution with `ptrace`,
//! - [`elf`] inspects the built binaries.
//!
//! Each signal produces a [`Permissions`] set of [`Grant`]s, and [`Permissions::merge`]
//! folds them into one. A grant carries its [`Provenance`] and its evidence strings, so
//! `pm explain` can answer "why does this package get to read `/etc/ssl`?" with a file
//! and a line rather than a shrug.
//!
//! # Derived permissions are incomplete by construction
//!
//! The runtime monitor sees only the paths that *one* execution took, and source
//! analysis sees only what its queries look for. A package that worked perfectly while
//! traced will still hit an untraced path in production. Every profile generator in
//! existence runs into this - AppArmor's `aa-genprof` and SELinux's `audit2allow` both
//! ship the same warning - so a freshly derived profile is [`Enforcement::Audit`]: it
//! logs what it *would* have denied and denies nothing. Promotion to
//! [`Enforcement::Enforce`] is a human decision and never happens silently.
//!
//! # Shape of a merged set
//!
//! Merging is not concatenation. Two signals that ask for the same permission produce
//! **one** grant carrying both provenances and both evidence strings - that agreement is
//! the most interesting thing a reviewer can see. Redundant sub-paths are collapsed into
//! the ancestor that already covers them (see [`Permissions::merge`]), because an
//! eight-line profile gets audited and a four-hundred-line one does not. Ordering is
//! total and deterministic, so a recorded permission set diffs cleanly between builds.

/// Permissions derived from the ELF objects a build produced.
pub mod elf;
/// Permissions derived by tracing one real execution.
pub mod monitor;
/// Permissions derived from the package's source code.
pub mod source;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write as _},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tracing::debug;

/// One thing a package is allowed to do inside its run sandbox.
///
/// The path variants always hold a *normalised* path once the value has been through
/// [`Permissions`]: no trailing slash, no `.` components. Paths are deliberately **not**
/// canonicalised - they routinely name files that do not exist on the machine doing the
/// building, and resolving symlinks there would record the wrong answer.
///
/// The declaration order of the variants is also the sort and report order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Permission {
    /// Read the path, and everything under it if it is a directory.
    ReadPath(PathBuf),
    /// Write the path, and everything under it if it is a directory.
    WritePath(PathBuf),
    /// Execute the path, or anything under it if it is a directory.
    ExecPath(PathBuf),
    /// Reach the network: keep the host network namespace instead of unsharing it.
    Network,
    /// Fork or exec child processes at all.
    Spawn,
}

impl Permission {
    /// The path this permission is about, or `None` for [`Permission::Network`] and
    /// [`Permission::Spawn`].
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::ReadPath(path) | Self::WritePath(path) | Self::ExecPath(path) => {
                Some(path.as_path())
            }
            Self::Network | Self::Spawn => None,
        }
    }

    /// A short, stable label: `read`, `write`, `exec`, `network` or `spawn`.
    ///
    /// Used as the group heading in [`Permissions::report`] and safe to match on.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ReadPath(_) => "read",
            Self::WritePath(_) => "write",
            Self::ExecPath(_) => "exec",
            Self::Network => "network",
            Self::Spawn => "spawn",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.path() {
            Some(path) => write!(f, "{} {}", self.label(), path.display()),
            None => f.write_str(self.label()),
        }
    }
}

/// Where a permission came from, so a user can audit WHY it was granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Provenance {
    /// A tree-sitter query matched the package's own source code.
    SourceAnalysis,
    /// A traced execution actually performed the operation.
    RuntimeMonitor,
    /// The built ELF objects imply it - a `DT_NEEDED`, an interpreter, an imported
    /// symbol.
    ElfAnalysis,
}

impl Provenance {
    /// A short, stable label: `source`, `runtime` or `elf`.
    pub fn label(self) -> &'static str {
        match self {
            Self::SourceAnalysis => "source",
            Self::RuntimeMonitor => "runtime",
            Self::ElfAnalysis => "elf",
        }
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One permission, everything that asked for it, and the justification.
///
/// Construct one with [`Grant::new`] - a single analyser speaks with a single
/// provenance. Grants that name the same permission are unified by
/// [`Permissions::merge`], which is the only way a grant ends up with more than one
/// provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    permission: Permission,
    provenance: Vec<Provenance>,
    evidence: Vec<String>,
}

impl Grant {
    /// Record that `provenance` asked for `permission`, justified by `evidence`.
    ///
    /// Evidence is free text meant for a human reading [`Permissions::report`]; keep it
    /// to one locator-plus-reason line each, e.g. `"src/net.c:42: call to socket"`.
    /// Duplicates are dropped and the order is normalised, so callers need not
    /// de-duplicate.
    ///
    /// The path inside `permission` is normalised here (trailing slashes and `.`
    /// components removed); it is *not* canonicalised.
    pub fn new(
        permission: Permission,
        provenance: Provenance,
        evidence: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            permission: normalise_permission(permission),
            provenance: vec![provenance],
            evidence: evidence
                .into_iter()
                .map(Into::into)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }

    /// What is being allowed.
    pub fn permission(&self) -> &Permission {
        &self.permission
    }

    /// Every signal that asked for this permission, sorted and de-duplicated.
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }

    /// Justification, e.g. "src/net.c:42: call to socket".
    ///
    /// When a redundant sub-path was collapsed into this grant, its evidence is kept
    /// here alongside a `covers <path>` line naming the path that disappeared.
    pub fn evidence(&self) -> &[String] {
        &self.evidence
    }
}

/// A merged, normalised set of grants: the run-time profile of one package.
///
/// Build one with [`Permissions::merge`] (or by collecting [`Grant`]s). The invariants
/// every constructed set holds:
///
/// - grants are sorted by [`Permission`], so two builds of the same package produce
///   byte-identical output,
/// - no two grants name the same permission,
/// - no path grant is a sub-path of another grant of the same kind.
///
/// A set says what a package *wants*. Whether those wants are enforced or merely logged
/// is [`Enforcement`], which is tracked separately precisely so that deriving a fresh
/// set can never turn denial on by itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    grants: Vec<Grant>,
}

impl Permissions {
    /// Fold any number of permission sets into one.
    ///
    /// This is where the model earns its keep:
    ///
    /// - **Unification.** Grants naming the same permission become one grant whose
    ///   provenance and evidence are the union of the inputs. If source analysis and the
    ///   runtime monitor both ask for `ReadPath("/etc/ssl")`, the result is a single
    ///   grant with two provenances and both evidence strings - two independent signals
    ///   agreeing is exactly what a reviewer wants to see.
    /// - **Collapsing.** A grant covered by an ancestor grant of the same kind is
    ///   dropped, and its provenance and evidence move to the ancestor together with a
    ///   `covers <path>` note. `ReadPath("/usr")` plus `ReadPath("/usr/lib/foo")` is
    ///   just `ReadPath("/usr")`.
    /// - **Ordering.** The result is sorted, so recorded permissions are reproducible
    ///   and diffable between builds.
    ///
    /// Merging widens: the result grants everything any input granted. It is not a
    /// review step and performs no promotion - see [`Enforcement`].
    pub fn merge(sets: impl IntoIterator<Item = Self>) -> Self {
        let grants = sets.into_iter().flat_map(|set| set.grants);
        Self::from_grants(grants)
    }

    /// Normalise a pile of grants into a set, with the same unification, collapsing and
    /// ordering [`Permissions::merge`] performs.
    pub fn from_grants(grants: impl IntoIterator<Item = Grant>) -> Self {
        let mut merged: BTreeMap<Permission, Entry> = BTreeMap::new();
        let mut seen = 0usize;
        for grant in grants {
            seen += 1;
            let permission = normalise_permission(grant.permission);
            let entry = merged.entry(permission).or_default();
            entry.provenance.extend(grant.provenance);
            entry.evidence.extend(grant.evidence);
        }
        let unified = merged.len();

        collapse(&mut merged);

        let grants: Vec<Grant> = merged
            .into_iter()
            .map(|(permission, entry)| Grant {
                permission,
                provenance: entry.provenance.into_iter().collect(),
                evidence: entry.evidence.into_iter().collect(),
            })
            .collect();

        debug!(
            seen,
            unified,
            collapsed = unified - grants.len(),
            kept = grants.len(),
            "normalised permission grants"
        );
        Self { grants }
    }

    /// Every grant in the set, sorted by permission.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// How many grants the set holds.
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether the set grants nothing at all.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Whether the package asked to reach the network.
    pub fn wants_network(&self) -> bool {
        self.holds(&Permission::Network)
    }

    /// Whether the package asked to start child processes.
    pub fn wants_spawn(&self) -> bool {
        self.holds(&Permission::Spawn)
    }

    /// The paths the package may read, in sorted order.
    pub fn read_paths(&self) -> impl Iterator<Item = &Path> {
        self.paths_of("read")
    }

    /// The paths the package may write, in sorted order.
    pub fn write_paths(&self) -> impl Iterator<Item = &Path> {
        self.paths_of("write")
    }

    /// The paths the package may execute, in sorted order.
    pub fn exec_paths(&self) -> impl Iterator<Item = &Path> {
        self.paths_of("exec")
    }

    /// Aligned, human-readable report for `pm explain`.
    ///
    /// Grants are grouped by kind in a fixed order and laid out in three columns -
    /// permission, provenance, evidence - with extra evidence lines hanging under the
    /// evidence column. Empty groups are printed as `(none)` rather than omitted, so the
    /// absence of, say, network access is visible instead of merely unstated.
    ///
    /// The report always leads with the incompleteness caveat: a derived profile
    /// describes what was *observed*, not what the package can need.
    pub fn report(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "permissions: {} grant(s)", self.grants.len());
        let _ = writeln!(
            out,
            "derived by observation, so necessarily incomplete - a fresh profile stays in \
             audit mode until a human promotes it"
        );

        for (label, belongs) in GROUPS {
            let rows: Vec<Row<'_>> = self
                .grants
                .iter()
                .filter(|grant| belongs(&grant.permission))
                .map(Row::of)
                .collect();

            let _ = writeln!(out);
            let _ = writeln!(out, "{label}");
            if rows.is_empty() {
                let _ = writeln!(out, "  (none)");
                continue;
            }

            let subject_width = rows.iter().map(|row| width(&row.subject)).max().unwrap_or(0);
            let provenance_width = rows
                .iter()
                .map(|row| width(&row.provenance))
                .max()
                .unwrap_or(0);

            for row in &rows {
                let mut evidence = row.evidence.iter();
                let first = evidence.next().map_or("", String::as_str);
                let _ = writeln!(
                    out,
                    "  {subject:<subject_width$}  {provenance:<provenance_width$}  {first}",
                    subject = pad(&row.subject, subject_width),
                    provenance = pad(&row.provenance, provenance_width),
                );
                let indent = 2 + subject_width + 2 + provenance_width + 2;
                for line in evidence {
                    let _ = writeln!(out, "{:indent$}{line}", "");
                }
            }
        }
        out
    }

    /// Whether an exact permission is present. Sub-path coverage is already folded away
    /// by [`Permissions::from_grants`], so an exact lookup is the right question.
    fn holds(&self, permission: &Permission) -> bool {
        self.grants
            .iter()
            .any(|grant| &grant.permission == permission)
    }

    /// The paths of every grant whose kind matches `label`.
    fn paths_of(&self, label: &'static str) -> impl Iterator<Item = &Path> {
        self.grants.iter().filter_map(move |grant| {
            (grant.permission.label() == label).then(|| grant.permission.path())?
        })
    }
}

impl FromIterator<Grant> for Permissions {
    fn from_iter<I: IntoIterator<Item = Grant>>(iter: I) -> Self {
        Self::from_grants(iter)
    }
}

/// Whether a derived profile is actually enforced.
///
/// A permission set derived by observation is incomplete by construction: the runtime
/// monitor saw one execution's paths, and source analysis saw what its queries asked
/// about. Enforcing such a set breaks the package the first time it takes a path nobody
/// watched. So a newly derived profile is [`Enforcement::Audit`], and **nothing in this
/// crate ever promotes it to [`Enforcement::Enforce`]** - that is a human decision, made
/// after reading [`Permissions::report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Enforcement {
    /// Log what WOULD have been denied; deny nothing. Default for a new profile.
    #[default]
    Audit,
    /// Actually deny. Only after a human promotes the profile.
    Enforce,
}

impl Enforcement {
    /// Whether denial is live. `false` means violations are only logged.
    pub fn denies(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

impl fmt::Display for Enforcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Audit => "audit",
            Self::Enforce => "enforce",
        })
    }
}

/// The report's groups, in print order, each with the test for membership.
const GROUPS: [(&str, fn(&Permission) -> bool); 5] = [
    ("read", |p| matches!(p, Permission::ReadPath(_))),
    ("write", |p| matches!(p, Permission::WritePath(_))),
    ("exec", |p| matches!(p, Permission::ExecPath(_))),
    ("network", |p| matches!(p, Permission::Network)),
    ("spawn", |p| matches!(p, Permission::Spawn)),
];

/// Accumulator for one permission while grants are being unified. `BTreeSet` gives the
/// de-duplication and the deterministic order for free.
#[derive(Default)]
struct Entry {
    provenance: BTreeSet<Provenance>,
    evidence: BTreeSet<String>,
}

/// One laid-out line of [`Permissions::report`].
struct Row<'a> {
    subject: String,
    provenance: String,
    evidence: &'a [String],
}

impl<'a> Row<'a> {
    fn of(grant: &'a Grant) -> Self {
        let subject = grant
            .permission
            .path()
            .map_or_else(|| "(granted)".to_owned(), |path| path.display().to_string());
        let provenance = grant
            .provenance
            .iter()
            .map(|provenance| provenance.label())
            .collect::<Vec<_>>()
            .join(", ");
        Self {
            subject,
            provenance,
            evidence: &grant.evidence,
        }
    }
}

/// Normalise the path inside a permission, leaving the pathless variants alone.
fn normalise_permission(permission: Permission) -> Permission {
    match permission {
        Permission::ReadPath(path) => Permission::ReadPath(normalise_path(&path)),
        Permission::WritePath(path) => Permission::WritePath(normalise_path(&path)),
        Permission::ExecPath(path) => Permission::ExecPath(normalise_path(&path)),
        other @ (Permission::Network | Permission::Spawn) => other,
    }
}

/// Lexical normalisation: drop `.` components, trailing slashes and repeated separators.
///
/// Deliberately **not** `canonicalize`: these paths are recorded on the machine doing the
/// building and used on a different machine at run time, where they may not exist and
/// may resolve differently. `..` components are preserved verbatim for the same reason -
/// resolving `a/../b` lexically is wrong the moment `a` is a symlink - and
/// [`covers`] refuses to reason about any path that still contains one.
///
/// A path that normalises to nothing (`""`, `"."`, `"./"`) becomes `.`, so a grant never
/// carries an empty path that would look like a prefix of everything.
fn normalise_path(path: &Path) -> PathBuf {
    let normalised: PathBuf = path
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect();
    if normalised.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalised
    }
}

/// Whether `parent` is a strict ancestor of `child`, making a grant on `child`
/// redundant.
///
/// **Compared by components, never by string prefix.** `"/usrlocal"` starts with the
/// string `"/usr"` but is not under it, and a `starts_with` on the raw text would grant
/// a package the whole of `/usr` because it asked for `/usrlocal` - silently widening
/// the sandbox in the exact direction that hurts. `Path::components` yields
/// `["/", "usr"]` versus `["/", "usrlocal"]`, which do not match. (`Path::starts_with`
/// is itself component-wise and would be correct; the hand-rolled loop is here because
/// it also has to reject the two cases below.)
///
/// Two paths are never in an ancestor relationship when either still contains a `..`
/// component, since only the run-time filesystem knows what that resolves to; and a path
/// with no components at all covers nothing, so an empty path cannot swallow the set.
fn covers(parent: &Path, child: &Path) -> bool {
    if !is_lexically_plain(parent) || !is_lexically_plain(child) {
        return false;
    }
    let mut child_components = child.components();
    let mut parent_components = 0usize;
    let matched = parent.components().all(|component| {
        parent_components += 1;
        child_components.next() == Some(component)
    });
    matched && parent_components > 0 && child_components.next().is_some()
}

/// Whether a path can be reasoned about lexically, i.e. holds no `..` component.
fn is_lexically_plain(path: &Path) -> bool {
    !path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
}

/// Drop every path grant that an ancestor grant of the same kind already covers, moving
/// its provenance and evidence onto that ancestor.
///
/// Paths are visited shallowest first, so the survivor is always the widest ancestor:
/// with `/usr`, `/usr/lib` and `/usr/lib/foo` present, `/usr/lib` collapses into `/usr`
/// first, and `/usr/lib/foo` then finds `/usr` rather than the entry that just went
/// away. That also keeps the "kept" list free of any ancestor pairs, so at most one
/// candidate can ever match.
fn collapse(merged: &mut BTreeMap<Permission, Entry>) {
    for (_, belongs) in GROUPS {
        let mut paths: Vec<PathBuf> = merged
            .keys()
            .filter(|permission| belongs(permission))
            .filter_map(|permission| permission.path().map(Path::to_path_buf))
            .collect();
        // Shallowest first; ties broken by the path itself to stay deterministic.
        paths.sort_by(|a, b| {
            a.components()
                .count()
                .cmp(&b.components().count())
                .then_with(|| a.cmp(b))
        });

        let mut kept: Vec<PathBuf> = Vec::new();
        for path in paths {
            let Some(root) = kept.iter().find(|root| covers(root, &path)).cloned() else {
                kept.push(path);
                continue;
            };
            let Some(rebuilt) = rebuild(merged, &path, belongs) else {
                continue;
            };
            let Some(entry) = merged.remove(&rebuilt) else {
                continue;
            };
            let Some(root_key) = rebuild(merged, &root, belongs) else {
                continue;
            };
            let Some(target) = merged.get_mut(&root_key) else {
                continue;
            };
            debug!(
                collapsed = %path.display(),
                into = %root.display(),
                "dropping redundant sub-path grant"
            );
            target.provenance.extend(entry.provenance);
            target.evidence.extend(entry.evidence);
            target.evidence.insert(format!("covers {}", path.display()));
        }
    }
}

/// Rebuild the map key for `path` in the group `belongs` describes.
///
/// The group predicates are the only handle this function has on which variant it is
/// working with, so it tries each variant and keeps the one the predicate accepts.
fn rebuild(
    _merged: &BTreeMap<Permission, Entry>,
    path: &Path,
    belongs: fn(&Permission) -> bool,
) -> Option<Permission> {
    [
        Permission::ReadPath(path.to_path_buf()),
        Permission::WritePath(path.to_path_buf()),
        Permission::ExecPath(path.to_path_buf()),
    ]
    .into_iter()
    .find(|permission| belongs(permission))
}

/// Display width of a report cell, in characters.
fn width(cell: &str) -> usize {
    cell.chars().count()
}

/// Pad a cell to `to` characters. `{:<width$}` counts bytes, which misaligns any column
/// holding a non-ASCII path, so the padding is computed from the character count.
fn pad(cell: &str, to: usize) -> String {
    let mut padded = cell.to_owned();
    padded.extend(std::iter::repeat_n(' ', to.saturating_sub(width(cell))));
    padded
}
