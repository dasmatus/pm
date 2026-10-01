//! Reading a build file to decide what its steps are allowed to do.
//!
//! A build file is data supplied by whoever wrote the package, so the sandbox
//! it runs in must not be configured by that same file: a hostile build file
//! would simply ask for everything. Instead the policy is *derived* - every
//! command of every step is offered to pm's [bundled command
//! classifiers](crate::plugin::bundled), and the capabilities of the fingerprints that
//! matched are the only ones the jail in [`crate::sandbox`] hands out. A command that
//! matches nothing is an error rather than an unconstrained wildcard.
//!
//! # Where installed plugins fit
//!
//! The bundled classifiers are finite, so a build system pm has never heard of stops a
//! build before it starts. [`BuildPolicy::derive_with`] gives a
//! [`crate::plugin::Registry`] a say - but only about the commands no bundled classifier
//! matched. That ordering is the
//! guarantee: a plugin can name a command pm would have refused, and can never rename
//! one pm already knows, so no plugin can strip [`Capability::Network`] from `cargo` or
//! decide that `git` is not version control. A plugin's answer is recorded under its own
//! name (`zig:zig`), and the plugin set folds into the policy digest, so the same
//! build file under different plugins does not produce the same policy.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    sync::{LazyLock, Mutex, PoisonError},
};

use miette::{IntoDiagnostic, WrapErr, miette};
use serde::{Deserialize, Serialize};
use serde_yaml::{Value, from_value, to_value};
use tracing::{debug, warn};

use crate::{
    plugin::{Registry, bundled},
    step::Step,
};

/// One capability a build step may need from the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Capability {
    /// Compilers, linkers, headers and build systems.
    Toolchain,
    /// The basic file-manipulation utilities: `install`, `cp`, `mkdir`, ...
    Coreutils,
    /// A POSIX shell. `make`, `cmake` and `./configure` all spawn one.
    Shell,
    /// Archive and compression tools: `tar`, `unzip`, `xz`, ...
    Archive,
    /// Access to the network namespace of the host.
    Network,
    /// Version-control clients, currently `git`.
    VersionControl,
}

/// The fingerprint name recorded for a command that matched nothing.
///
/// Only ever reaches [`BuildPolicy::matches`] in permissive mode; a strict
/// derivation fails instead. It is not a program name, and the angle brackets
/// keep it from ever colliding with one.
pub const UNMATCHED: &str = "<unmatched>";

/// The sandbox policy derived from a whole build file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "PolicyWire", try_from = "PolicyWire")]
pub struct BuildPolicy {
    /// Sorted and deduplicated, so two build files needing the same things
    /// compare equal and digest identically.
    capabilities: Vec<Capability>,
    matches: Vec<(String, &'static str)>,
    fingerprint: String,
}

impl BuildPolicy {
    /// Derive the policy by reading every step command of `build` and matching
    /// it against the bundled fingerprint plugins.
    ///
    /// Every step of every stage is read, in the order the build file declares
    /// them. A step carrying a non-empty `dl_urls` map is granted
    /// [`Capability::Network`] whatever its commands turn out to be, since the
    /// downloads happen before the first one runs.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic naming the command if it matches no fingerprint and
    /// `permissive` is false. Also fails if `build` cannot be serialised for
    /// inspection, or if a bundled plugin fails to load or misbehaves - the latter is
    /// a bug in pm, not in the build file.
    pub fn derive(build: &crate::bf::BuildFile, permissive: bool) -> miette::Result<Self> {
        Self::derive_with(build, permissive, Registry::none())
    }

    /// As [`BuildPolicy::derive`], letting `plugins` classify what the bundled plugins
    /// could not.
    ///
    /// A plugin is consulted **only** for a command no built-in fingerprint matched, and
    /// only the capabilities it published a ceiling for survive - see
    /// [`crate::plugin`]. Passing [`Registry::none`], which is what [`BuildPolicy::derive`]
    /// does, makes this identical to the derivation pm performed before plugins existed,
    /// digest included.
    ///
    /// # Errors
    ///
    /// As [`BuildPolicy::derive`]: a command that neither a bundled nor an installed plugin
    /// recognises is still an error unless `permissive` is set.
    pub fn derive_with(
        build: &crate::bf::BuildFile,
        permissive: bool,
        plugins: &Registry,
    ) -> miette::Result<Self> {
        // `BuildFile` keeps its fields private, so the steps are read back
        // through serde. The same `Value` is what the digest is taken over,
        // which keeps the two views of the build file from drifting apart.
        let value = to_value(build)
            .into_diagnostic()
            .wrap_err("cannot inspect the build file")?;
        let view: BuildFileView = from_value(value.clone())
            .into_diagnostic()
            .wrap_err("cannot read the steps of the build file")?;

        let mut capabilities = BTreeSet::new();
        let mut matches = Vec::new();
        let mut unknown = Vec::new();

        for step in &view.steps {
            if step.dl_urls.as_ref().is_some_and(|urls| !urls.is_empty()) {
                debug!(step = %step.name, "downloads grant network access");
                capabilities.insert(Capability::Network);
            }
            for command in &step.run {
                match bundled::classify(command.trim())? {
                    Some((name, granted)) => {
                        debug!(
                            step = %step.name,
                            command = %command,
                            fingerprint = name,
                            "matched"
                        );
                        capabilities.extend(granted);
                        matches.push((command.clone(), name));
                    }
                    // The bundled plugins had nothing, so - and only so - the plugins
                    // get a say.
                    None => match plugins.classify(command.trim()) {
                        Some((fingerprint, granted)) => {
                            debug!(
                                step = %step.name,
                                command = %command,
                                fingerprint = %fingerprint,
                                capabilities = ?granted,
                                "matched by a plugin"
                            );
                            capabilities.extend(granted);
                            matches.push((command.clone(), intern(&fingerprint)));
                        }
                        None => {
                            unknown.push(format!("{} (step `{}`)", quoted(command), step.name));
                            matches.push((command.clone(), UNMATCHED));
                        }
                    },
                }
            }
        }

        if !unknown.is_empty() {
            let report = miette!(
                "{} matches {}: {}\nknown fingerprints: {}",
                if plugins.is_empty() {
                    "no built-in fingerprint"
                } else {
                    "no built-in fingerprint, and no installed plugin,"
                },
                if unknown.len() == 1 {
                    "this command"
                } else {
                    "these commands"
                },
                unknown.join(", "),
                bundled::fingerprint_names()?.join(", ")
            );
            if permissive {
                warn!("{report:?}");
                warn!("continuing without a policy for those commands: --permissive was given");
            } else {
                return Err(report);
            }
        }

        let capabilities: Vec<Capability> = capabilities.into_iter().collect();
        let fingerprint = digest(&value, &capabilities, plugins.digest());
        debug!(
            fingerprint = %fingerprint,
            capabilities = ?capabilities,
            "derived build policy"
        );
        Ok(Self {
            capabilities,
            matches,
            fingerprint,
        })
    }

    /// The capabilities the sandbox must grant, sorted and deduplicated.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Whether the policy grants `capability`.
    #[must_use]
    pub fn grants(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Which fingerprint matched each command, for logging and for
    /// `pm explain`.
    ///
    /// Commands appear in the order the build file declares them. A command
    /// that matched nothing is paired with [`UNMATCHED`], which can only
    /// happen when the policy was derived permissively.
    #[must_use]
    pub fn matches(&self) -> &[(String, &'static str)] {
        &self.matches
    }

    /// Stable hex digest over the build file and the resolved capability set.
    ///
    /// **Not cryptographic.** See [`digest`]: this is a change detector, and
    /// integrity comes from the Ed25519 signature in [`crate::signing`].
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// The parts of a build file this module reads.
///
/// `BuildFile`'s fields are private to its own module, so the steps come back
/// through serde rather than through a field access. Unknown keys are ignored,
/// which keeps this from breaking every time a field is added to `BuildFile`.
#[derive(Deserialize)]
struct BuildFileView {
    #[serde(default)]
    steps: Vec<Step>,
}

/// Render a command for a diagnostic, keeping an empty one visible.
fn quoted(command: &str) -> String {
    let command = command.trim();
    if command.is_empty() {
        "an empty command".to_string()
    } else {
        format!("`{command}`")
    }
}

/// A stable, **non-cryptographic** digest over the build file and the
/// capabilities derived from it.
///
/// It exists to answer "has anything about this build changed since last
/// time?", nothing more: it is a change detector, not a security boundary, and
/// forging a collision is not meant to be hard. Integrity and authorship come
/// from the Ed25519 detached signature in [`crate::signing`].
///
/// Stability is the actual requirement, so:
///
/// * the input is the canonical form produced by [`canonical`], which sorts
///   mappings and length-prefixes strings, because the `dl_urls` map is a
///   `HashMap` whose iteration order differs from process to process;
/// * the mixing is FNV-1a followed by two SplitMix64 finalisers, both written
///   out inline with fixed constants, rather than `DefaultHasher`, whose
///   output is explicitly not stable across releases or processes;
/// * the build file's own path is not part of it - `BuildFile::source` is
///   `#[serde(skip)]`, so the same file digests the same wherever it lives.
///
/// Any change to a command, to a step's stage or name, to the order of the
/// steps, to the downloads, or to the resolved capability set changes the
/// output - and so does installing, removing or upgrading a plugin, because
/// [`crate::plugin::Registry::digest`] is mixed in whenever it is non-empty. The
/// same build file can derive a different capability set under a different plugin
/// set, and two policies that differ must not print the same digest.
fn digest(build: &Value, capabilities: &[Capability], plugins: &str) -> String {
    const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;

    let mut canon = String::new();
    canonical(build, &mut canon);
    // The separator cannot occur in the canonical form of a value, so the
    // build file and the capability list cannot be confused for one another.
    let _ = write!(canon, "|capabilities:{capabilities:?}");
    // Appended only when there are plugins, so a pm with none installed digests a
    // build file to exactly what it digested to before plugins existed - which is what
    // makes this whole feature invisible to anyone not using it.
    if !plugins.is_empty() {
        let _ = write!(canon, "|plugins:{plugins}");
    }

    let seed = fnv1a(canon.as_bytes());
    format!("{:016x}{:016x}", splitmix(seed), splitmix(seed ^ GOLDEN))
}

/// Append a canonical, order-independent rendering of `value` to `out`.
///
/// Mappings are emitted with their entries sorted by the canonical form of the
/// key, so a `HashMap` digests the same however it happened to be laid out.
/// Strings are length-prefixed and every composite is delimited, so no two
/// distinct values can render to the same text.
fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push('~'),
        Value::Bool(flag) => {
            let _ = write!(out, "b{}", u8::from(*flag));
        }
        Value::Number(number) => {
            let _ = write!(out, "n{number}");
        }
        Value::String(text) => {
            let _ = write!(out, "s{}:{text}", text.len());
        }
        Value::Sequence(items) => {
            out.push('[');
            for item in items {
                canonical(item, out);
                out.push(';');
            }
            out.push(']');
        }
        Value::Mapping(mapping) => {
            let mut entries: Vec<(String, String)> = mapping
                .iter()
                .map(|(key, value)| {
                    let mut rendered_key = String::new();
                    canonical(key, &mut rendered_key);
                    let mut rendered_value = String::new();
                    canonical(value, &mut rendered_value);
                    (rendered_key, rendered_value)
                })
                .collect();
            entries.sort();
            out.push('{');
            for (key, value) in entries {
                let _ = write!(out, "{key}={value};");
            }
            out.push('}');
        }
        Value::Tagged(tagged) => {
            let _ = write!(out, "!{}:", tagged.tag);
            canonical(&tagged.value, out);
        }
    }
}

/// FNV-1a over `bytes`, written out inline with the standard 64-bit constants.
fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    bytes.iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

/// SplitMix64's finalising mix, used to spread the FNV-1a state over two
/// independent 64-bit halves of the printed digest.
fn splitmix(seed: u64) -> u64 {
    let mut state = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    state = (state ^ (state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    state = (state ^ (state >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    state ^ (state >> 31)
}

/// The serialised shape of a [`BuildPolicy`].
///
/// [`BuildPolicy::matches`] hands out `&'static str` fingerprint names, and
/// serde cannot deserialise a borrow that outlives its input. The wire form carries owned names instead, and
/// [`TryFrom`] maps each one back to the name it came from - which also
/// rejects a policy naming a fingerprint this build of pm does not have.
#[derive(Serialize, Deserialize)]
struct PolicyWire {
    capabilities: Vec<Capability>,
    matches: Vec<(String, String)>,
    fingerprint: String,
}

impl From<BuildPolicy> for PolicyWire {
    fn from(policy: BuildPolicy) -> Self {
        Self {
            capabilities: policy.capabilities,
            matches: policy
                .matches
                .into_iter()
                .map(|(command, name)| (command, name.to_string()))
                .collect(),
            fingerprint: policy.fingerprint,
        }
    }
}

impl TryFrom<PolicyWire> for BuildPolicy {
    type Error = String;

    fn try_from(wire: PolicyWire) -> Result<Self, Self::Error> {
        let matches = wire
            .matches
            .into_iter()
            .map(|(command, name)| {
                static_name(&name)
                    .map(|name| (command, name))
                    .ok_or_else(|| format!("unknown fingerprint `{name}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            capabilities: wire.capabilities,
            matches,
            fingerprint: wire.fingerprint,
        })
    }
}

/// Map a fingerprint name back to a `&'static str`.
///
/// [`UNMATCHED`] first, then the bundled plugins' names, then the interner - an
/// installed plugin's fingerprint has no bundled entry but is just as much a name this installation
/// produced, and a policy that was serialised with one has to deserialise again.
fn static_name(name: &str) -> Option<&'static str> {
    if name == UNMATCHED {
        return Some(UNMATCHED);
    }
    bundled::fingerprint_names()
        .ok()
        .and_then(|names| names.into_iter().find(|known| *known == name))
        .or_else(|| interned(name))
}

/// Fingerprint names contributed by plugins, kept alive for the rest of the process.
///
/// [`BuildPolicy::matches`] hands out `&'static str`, because the bundled names are
/// `'static` and nothing else needed a lifetime. A plugin's names arrive as owned
/// strings at run time, so they are leaked into `'static` once each and shared from
/// then on.
///
/// The honest accounting: this leaks at most one 32-byte name per *distinct* name a
/// plugin returns, which for an honest plugin is the handful of build systems it knows
/// and is allocated once for the whole process. A plugin that invented a fresh name for
/// every command it saw would leak one per classified command, which is bounded by the
/// build files pm reads in one run and is why the name length is capped at all. The
/// alternative - making the whole `matches` list owned - would spend an allocation per
/// command on every build, plugins or not, to bound something no honest plugin does.
static INTERNED: LazyLock<Mutex<BTreeSet<&'static str>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

/// The interned copy of `name`, interning it if this is the first time it is seen.
fn intern(name: &str) -> &'static str {
    let mut names = INTERNED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(existing) = names.get(name) {
        return existing;
    }
    let leaked: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.insert(leaked);
    leaked
}

/// The interned copy of `name`, or `None` if nothing in this process ever produced it.
fn interned(name: &str) -> Option<&'static str> {
    INTERNED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(name)
        .copied()
}
