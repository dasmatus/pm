//! A pm plugin that teaches pm about systemd.
//!
//! Three jobs, and the second is the interesting one:
//!
//! * [`classify_command`] recognises the systemd tools a build file actually invokes -
//!   `systemd-tmpfiles --create --root=$DESTDIR`, `systemd-sysusers`, `systemctl
//!   preset`, `systemd-analyze verify` as a unit lint - none of which pm's built-in
//!   fingerprint table knows.
//! * [`scan_source`] reads the unit files a package installs and records what they say
//!   the program will do at run time.
//! * It adds recipe functions to Rhai recipes: `systemd::install_unit("foo.service")`
//!   is the `Install` step that puts a unit file where systemd looks for it, and
//!   `systemd::install_units([...])` is one such step per file. Built against the
//!   `recipe-plugin` world for that; see [`RECIPE_FUNCTIONS`].
//!
//! # Why unit files are a better signal than source code
//!
//! pm's own source analysis is a careful heuristic: it reads a syntax tree looking for
//! calls that *imply* a permission, and its module documentation lists six things it
//! cannot see. A unit file needs none of that, because it is not a program - it is a
//! **declaration of what the program will be allowed to do**, written by the same person
//! who wrote the program, in a vocabulary that lines up almost one-for-one with pm's
//! [`Permission`]. `ReadWritePaths=/var/lib/foo` is not evidence that a write might
//! happen; it is the author saying where the writes go.
//!
//! That precision buys something source scanning cannot have: **negative** information.
//! `PrivateNetwork=yes` does not merely fail to suggest network access, it positively
//! denies it, so this plugin drops every network grant it would otherwise have derived
//! from the same file. A source scanner has no equivalent - not finding a `socket()`
//! call never means there is not one.
//!
//! # What this deliberately does not classify
//!
//! `systemd-nspawn`, `systemd-run`, `systemd-mount`, `machinectl` and `portablectl` are
//! recognised and then refused, with a line in the log saying why. Each of them runs
//! something else - a container, a transient unit, an arbitrary image - so a verdict
//! here would be a jail sized for a program nobody has looked at. pm's answer to an
//! unclassified command is a diagnostic naming it, and for these that is the better
//! outcome.

wit_bindgen::generate!({ path: "../../wit", world: "recipe-plugin" });

use pm::plugin::{
    host::{Level, log},
    types::{Capability, Hook, Permission, RecipeValue, Symbol},
};
use unitfile::{Directive, absolute_path, is_templated, parse, undecorate, words};

struct Systemd;

/// The tools this plugin classifies, and what each needs from the build jail.
///
/// All of them do the same thing from the jail's point of view: read and write files
/// under the staging root. None of them compiles anything, none needs a shell, and -
/// importantly - none needs the network, which is the one capability that actually
/// changes the jail pm builds.
const TOOLS: &[(&[&str], &str)] = &[
    (&["systemctl"], "systemctl"),
    (&["systemd-tmpfiles"], "tmpfiles"),
    (&["systemd-sysusers"], "sysusers"),
    (&["systemd-analyze"], "analyze"),
    (&["systemd-hwdb", "udevadm"], "udev"),
    (&["kernel-install", "bootctl"], "boot"),
    (
        &[
            "busctl",
            "hostnamectl",
            "journalctl",
            "localectl",
            "loginctl",
            "networkctl",
            "resolvectl",
            "systemd-cat",
            "systemd-detect-virt",
            "systemd-escape",
            "systemd-id128",
            "systemd-path",
            "timedatectl",
        ],
        "ctl",
    ),
];

/// The functions this plugin adds to Rhai recipes: name, parameters, what each
/// returns, and its documentation.
const RECIPE_FUNCTIONS: &[(&str, &[&str], RecipeValue, &str)] = &[
    (
        "install_unit",
        &["file"],
        RecipeValue::Step,
        "The `Install` step that installs the unit file `file` (a path in the build \
         tree) where systemd looks for system units, mode 0644.",
    ),
    (
        "install_units",
        &["files"],
        RecipeValue::Steps,
        "`install_unit` for each of an array of unit files.",
    ),
];

/// Unit file suffixes `install_unit` accepts.
const UNIT_SUFFIXES: &[&str] = &[
    ".automount",
    ".device",
    ".mount",
    ".path",
    ".scope",
    ".service",
    ".slice",
    ".socket",
    ".swap",
    ".target",
    ".timer",
];

/// The step installing one unit file, as JSON.
///
/// The destination is under `/dest`, pm's `DESTDIR` inside the build jail, at
/// `unitdir`: a recipe gets exactly the step it would have written by hand, so the
/// command is classified and signed-off like any other.
fn install_unit(file: &str) -> Result<String, String> {
    let unit = file.rsplit('/').next().unwrap_or(file);
    if unit.is_empty() || file.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{file:?} is not a usable unit file path"));
    }
    if !UNIT_SUFFIXES.iter().any(|suffix| unit.ends_with(suffix)) {
        return Err(format!(
            "{unit:?} is not a unit file; it must end in one of {}",
            UNIT_SUFFIXES.join(", ")
        ));
    }
    let unitdir = SYMBOLS
        .iter()
        .find(|(name, ..)| *name == "unitdir")
        .map_or("/usr/lib/systemd/system", |(_, value, _)| value);
    // `--`, so a path starting with `-` is still the file to install.
    let command = format!("install -Dm644 -- {file} /dest{unitdir}/{unit}");
    Ok(format!(
        r#"{{"stage":"Install","name":{},"run":[{}]}}"#,
        json::quote(&format!("install {unit}")),
        json::quote(&command)
    ))
}

/// Just enough JSON for recipe function arguments and answers: strings and arrays of
/// strings. A plugin is small and the component is compiled on every pm run, so this
/// is a few dozen lines rather than a JSON library.
mod json {
    /// `text` as a JSON string literal.
    pub fn quote(text: &str) -> String {
        let mut out = String::with_capacity(text.len() + 2);
        out.push('"');
        for c in text.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    /// The string a JSON string literal holds.
    pub fn string(text: &str) -> Option<String> {
        let (value, rest) = parse_string(text.trim())?;
        rest.trim().is_empty().then_some(value)
    }

    /// The strings a JSON array of string literals holds.
    pub fn strings(text: &str) -> Option<Vec<String>> {
        let mut rest = text.trim().strip_prefix('[')?.trim_start();
        let mut out = Vec::new();
        if let Some(after) = rest.strip_prefix(']') {
            return after.trim().is_empty().then_some(out);
        }
        loop {
            let (value, after) = parse_string(rest)?;
            out.push(value);
            let after = after.trim_start();
            if let Some(after) = after.strip_prefix(',') {
                rest = after.trim_start();
            } else {
                let after = after.strip_prefix(']')?;
                return after.trim().is_empty().then_some(out);
            }
        }
    }

    /// One string literal at the start of `text`, and what follows it.
    fn parse_string(text: &str) -> Option<(String, &str)> {
        let mut chars = text.strip_prefix('"')?.char_indices();
        let mut out = String::new();
        while let Some((index, c)) = chars.next() {
            match c {
                '"' => return Some((out, &text[index + 2..])),
                '\\' => match chars.next()?.1 {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'u' => {
                        let hex: String = (0..4)
                            .filter_map(|_| chars.next().map(|(_, c)| c))
                            .collect();
                        out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                    }
                    _ => return None,
                },
                c => out.push(c),
            }
        }
        None
    }
}

/// Tools that run something else, and are therefore refused rather than classified.
///
/// See the module documentation. Listed rather than ignored so the log can say *why*
/// there was no verdict, which is a good deal more useful than silence.
const REFUSED: &[&str] = &[
    "machinectl",
    "portablectl",
    "systemd-mount",
    "systemd-nspawn",
    "systemd-run",
];

/// The install directories a package shipping systemd integration has to write into.
///
/// Every one of these is a constant a build file would otherwise hardcode, or dig out
/// of `pkg-config --variable=systemdsystemunitdir systemd` - which needs pkg-config and
/// systemd's development files present inside the build jail to answer. A build file
/// can write `%{systemd:unitdir}` instead and get the same answer with neither.
///
/// They are upstream systemd's own defaults, under `/usr/lib` rather than `/lib`: a
/// package stages into `DESTDIR` and a distribution that disagrees is patching the
/// prefix anyway.
const SYMBOLS: &[(&str, &str, &str)] = &[
    ("unitdir", "/usr/lib/systemd/system", "system unit files"),
    ("userunitdir", "/usr/lib/systemd/user", "user unit files"),
    (
        "presetdir",
        "/usr/lib/systemd/system-preset",
        "system preset policy",
    ),
    (
        "userpresetdir",
        "/usr/lib/systemd/user-preset",
        "user preset policy",
    ),
    (
        "sysusersdir",
        "/usr/lib/sysusers.d",
        "systemd-sysusers definitions",
    ),
    (
        "tmpfilesdir",
        "/usr/lib/tmpfiles.d",
        "systemd-tmpfiles definitions",
    ),
    (
        "modulesloaddir",
        "/usr/lib/modules-load.d",
        "modules to load at boot",
    ),
    ("sysctldir", "/usr/lib/sysctl.d", "sysctl settings"),
    ("udevrulesdir", "/usr/lib/udev/rules.d", "udev rules"),
    (
        "udevhwdbdir",
        "/usr/lib/udev/hwdb.d",
        "udev hardware database entries",
    ),
    (
        "catalogdir",
        "/usr/lib/systemd/catalog",
        "journal message catalogs",
    ),
    (
        "generatordir",
        "/usr/lib/systemd/system-generators",
        "unit generators",
    ),
];

/// Unit types whose files this plugin reads, as file extensions.
const UNIT_EXTENSIONS: &[&str] = &[
    "automount",
    "mount",
    "path",
    "scope",
    "service",
    "slice",
    "socket",
    "swap",
    "target",
    "timer",
];

/// Sections whose `Exec*` directives name a program to run.
const EXEC_SECTIONS: &[&str] = &["Service", "Socket", "Mount", "Swap"];

/// `Exec*` directives whose first word is a program path.
const EXEC_KEYS: &[&str] = &[
    "ExecCondition",
    "ExecMount",
    "ExecReload",
    "ExecRemount",
    "ExecStart",
    "ExecStartPost",
    "ExecStartPre",
    "ExecStop",
    "ExecStopPost",
    "ExecUnmount",
];

/// `Exec*` directives whose presence means the unit runs more than one program.
const AUXILIARY_EXEC: &[&str] = &[
    "ExecCondition",
    "ExecReload",
    "ExecStartPost",
    "ExecStartPre",
    "ExecStopPost",
];

/// Directives naming paths the program reads.
const READ_KEYS: &[(&[&str], &str)] = &[
    (&["Service"], "BindReadOnlyPaths"),
    (&["Service"], "EnvironmentFile"),
    (&["Service"], "ReadOnlyPaths"),
    (&["Service"], "RootDirectory"),
    (&["Service"], "RootImage"),
    (&["Service"], "WorkingDirectory"),
    (&["Unit"], "AssertPathExists"),
    (&["Unit"], "ConditionFileNotEmpty"),
    (&["Unit"], "ConditionPathExists"),
    (&["Unit"], "ConditionPathIsDirectory"),
    (&["Path"], "DirectoryNotEmpty"),
    (&["Path"], "PathChanged"),
    (&["Path"], "PathExists"),
    (&["Path"], "PathExistsGlob"),
    (&["Path"], "PathModified"),
    (&["Mount", "Swap"], "What"),
];

/// Directives naming paths the program writes.
const WRITE_KEYS: &[(&[&str], &str)] = &[
    (&["Service"], "BindPaths"),
    (&["Service"], "PIDFile"),
    (&["Service"], "ReadWritePaths"),
    (&["Automount", "Mount"], "Where"),
];

/// `*Directory=` directives, whose value is a name under a fixed root rather than a
/// path, and whether the program writes there.
///
/// systemd creates these for the unit and hands them over owned by its user, so all but
/// the configuration one are writes.
const DIRECTORY_KEYS: &[(&str, &str, bool)] = &[
    ("CacheDirectory", "/var/cache", true),
    ("ConfigurationDirectory", "/etc", false),
    ("LogsDirectory", "/var/log", true),
    ("RuntimeDirectory", "/run", true),
    ("StateDirectory", "/var/lib", true),
];

/// `Listen*` directives that take either a socket address or a filesystem path.
const LISTEN_KEYS: &[&str] = &["ListenDatagram", "ListenSequentialPacket", "ListenStream"];

impl Guest for Systemd {
    fn describe() -> Manifest {
        Manifest {
            name: "systemd".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            summary: "Classifies systemd tooling and reads the unit files a package installs"
                .into(),
            hooks: vec![Hook::ClassifyCommand, Hook::ScanSource],
            // The tightest ceiling any plugin here publishes, and it is not modesty:
            // every tool in TOOLS manipulates files under the staging root and nothing
            // more. A verdict from this plugin can never grant the network.
            grants_at_most: vec![Capability::Coreutils],
            source_extensions: UNIT_EXTENSIONS.iter().map(|&e| e.into()).collect(),
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

    fn recipe_functions() -> Vec<RecipeFunction> {
        RECIPE_FUNCTIONS
            .iter()
            .map(|(name, params, returns, doc)| RecipeFunction {
                name: (*name).into(),
                params: params.iter().map(|&param| param.into()).collect(),
                returns: *returns,
                doc: (*doc).into(),
            })
            .collect()
    }

    fn call_recipe_function(name: String, args: Vec<String>) -> Result<String, String> {
        match (name.as_str(), args.as_slice()) {
            ("install_unit", [file]) => {
                let file = json::string(file).ok_or("the unit file must be a string")?;
                install_unit(&file)
            }
            ("install_units", [files]) => {
                let files =
                    json::strings(files).ok_or("the unit files must be an array of strings")?;
                let steps = files
                    .iter()
                    .map(|file| install_unit(file))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("[{}]", steps.join(",")))
            }
            _ => Err(format!(
                "no recipe function {name} taking {} arguments",
                args.len()
            )),
        }
    }

    fn classify_command(command: String) -> Option<Verdict> {
        let program = program_name(command.split_whitespace().next()?)?;

        if REFUSED.contains(&program) {
            log(
                Level::Info,
                &format!(
                    "`{program}` runs a program of its own choosing, so sizing a jail for it \
                     would size it for something nobody has read; leaving it unclassified"
                ),
            );
            return None;
        }

        let (_, fingerprint) = TOOLS.iter().find(|(names, _)| names.contains(&program))?;
        Some(Verdict {
            fingerprint: (*fingerprint).into(),
            capabilities: vec![Capability::Coreutils],
        })
    }

    fn scan_source(file: SourceFile) -> Vec<Grant> {
        let directives = parse(&file.contents);
        let mut grants = Vec::new();

        for directive in &directives {
            grants.extend(read_grants(directive));
            grants.extend(write_grants(directive));
            grants.extend(exec_grants(directive));
            grants.extend(listen_grants(directive));
            grants.extend(network_grants(directive));
            grants.extend(spawn_grants(directive));
        }

        // The whole point of reading a declaration rather than a program: the file can
        // say *no*, and when it does that answer beats every positive signal in it.
        if denies_network(&directives) {
            let before = grants.len();
            grants.retain(|grant| !matches!(grant.permission, Permission::Network));
            if grants.len() != before {
                log(
                    Level::Debug,
                    &format!(
                        "{}: PrivateNetwork=yes, so {} network grant(s) derived from this unit \
                         were dropped",
                        file.path,
                        before - grants.len()
                    ),
                );
            }
        }
        grants
    }
}

/// Paths a directive says the program reads.
fn read_grants(directive: &Directive) -> impl Iterator<Item = Grant> {
    let stream = directive.is("Service", "StandardInput");
    READ_KEYS
        .iter()
        .filter(move |(sections, key)| directive.is_any(sections, key))
        .flat_map(move |_| paths(directive, false))
        .chain(directories(directive, false))
        .chain(
            stream
                .then(|| stream_path(directive, false))
                .into_iter()
                .flatten(),
        )
}

/// Paths a directive says the program writes.
fn write_grants(directive: &Directive) -> impl Iterator<Item = Grant> {
    let stream =
        directive.is("Service", "StandardOutput") || directive.is("Service", "StandardError");
    WRITE_KEYS
        .iter()
        .filter(move |(sections, key)| directive.is_any(sections, key))
        .flat_map(move |_| paths(directive, true))
        .chain(directories(directive, true))
        .chain(
            stream
                .then(|| stream_path(directive, true))
                .into_iter()
                .flatten(),
        )
}

/// The program an `Exec*` directive runs.
fn exec_grants(directive: &Directive) -> impl Iterator<Item = Grant> {
    let execs = EXEC_KEYS
        .iter()
        .any(|key| directive.is_any(EXEC_SECTIONS, key));
    // The command line is the value; the program is its first word, once the `-@:+!`
    // decorations systemd allows in front of it are off.
    execs
        .then(|| words(&directive.value).into_iter().next())
        .flatten()
        .and_then(|first| {
            absolute_path(&first).map(|path| grant(Permission::ExecPath(path.into()), directive))
        })
        .into_iter()
}

/// What a `Listen*` directive asks for: a port is the network, a path is a socket file
/// the program creates.
///
/// This is the distinction that makes reading the declaration worthwhile.
/// `ListenStream=8080` and `ListenStream=/run/foo.sock` are the same directive and mean
/// entirely different things, and nothing about the program's source would tell them
/// apart.
fn listen_grants(directive: &Directive) -> impl Iterator<Item = Grant> {
    let permission = if directive.is("Socket", "ListenFIFO") {
        absolute_path(&directive.value).map(|path| Permission::WritePath(path.into()))
    } else if !LISTEN_KEYS.iter().any(|key| directive.is("Socket", key)) {
        None
    } else {
        match absolute_path(&directive.value) {
            Some(path) => Some(Permission::WritePath(path.into())),
            // An abstract namespace socket (`@name`) is not a file and not the network.
            None if directive.value.starts_with('@') => None,
            None => Some(Permission::Network),
        }
    };
    permission
        .map(|permission| grant(permission, directive))
        .into_iter()
}

/// Directives that say the program reaches the network.
fn network_grants(directive: &Directive) -> impl Iterator<Item = Grant> {
    let wanted = if directive.is("Service", "IPAddressAllow") {
        !directive.value.is_empty()
    } else if directive.is("Service", "RestrictAddressFamilies") {
        directive.value.contains("AF_INET")
    } else if ["After", "BindsTo", "Requires", "Requisite", "Wants"]
        .iter()
        .any(|key| directive.is("Unit", key))
    {
        // `After=network.target` says only "start me late" and is on half the units in
        // existence. `network-online.target` is the one that means the unit does not
        // work without a usable network.
        directive.value.contains("network-online.target")
    } else {
        false
    };
    wanted
        .then(|| grant(Permission::Network, directive))
        .into_iter()
}

/// Directives that say the unit runs more than one process.
fn spawn_grants(directive: &Directive) -> impl Iterator<Item = Grant> {
    let spawns = AUXILIARY_EXEC
        .iter()
        .any(|key| directive.is_any(EXEC_SECTIONS, key))
        || (directive.is("Service", "Type") && directive.value.eq_ignore_ascii_case("forking"));
    spawns
        .then(|| grant(Permission::Spawn, directive))
        .into_iter()
}

/// Whether the unit denies itself the network outright.
fn denies_network(directives: &[Directive]) -> bool {
    directives
        .iter()
        .any(|directive| directive.is("Service", "PrivateNetwork") && is_yes(&directive.value))
}

/// Every absolute path in a whitespace-separated directive value.
///
/// A `BindPaths=` entry is `source:destination:options`; the source is the host path and
/// the rest describes where it lands inside the unit's own namespace, so only the source
/// is recorded.
fn paths(directive: &Directive, writes: bool) -> impl Iterator<Item = Grant> {
    words(&directive.value).into_iter().filter_map(move |word| {
        let source = word.split(':').next().unwrap_or(&word);
        absolute_path(source).map(|path| {
            let permission = if writes {
                Permission::WritePath(path.into())
            } else {
                Permission::ReadPath(path.into())
            };
            grant(permission, directive)
        })
    })
}

/// A `*Directory=` value, which is a name (or several) under a fixed root.
fn directories(directive: &Directive, writes: bool) -> impl Iterator<Item = Grant> {
    DIRECTORY_KEYS
        .iter()
        .filter(move |(key, _, is_write)| *is_write == writes && directive.is("Service", key))
        .flat_map(move |(_, root, _)| {
            words(&directive.value).into_iter().filter_map(move |name| {
                let name = undecorate(&name);
                // `StateDirectory=foo/bar` is legal; a specifier is not a name.
                if name.is_empty() || name.starts_with('/') || is_templated(name) {
                    return None;
                }
                Some(format!("{root}/{name}"))
            })
        })
        .map(move |path| {
            let permission = if writes {
                Permission::WritePath(path)
            } else {
                Permission::ReadPath(path)
            };
            grant(permission, directive)
        })
}

/// The path in a `Standard{Input,Output,Error}=` directive, if it names one.
///
/// Only the `file:`, `append:` and `truncate:` forms name a path; `journal`, `null`,
/// `socket`, `inherit` and `fd:name` do not.
fn stream_path(directive: &Directive, writes: bool) -> impl Iterator<Item = Grant> {
    directive
        .value
        .split_once(':')
        .filter(|(kind, _)| ["file", "append", "truncate"].contains(kind))
        .and_then(|(_, rest)| absolute_path(rest))
        .map(|path| {
            let permission = if writes {
                Permission::WritePath(path.into())
            } else {
                Permission::ReadPath(path.into())
            };
            grant(permission, directive)
        })
        .into_iter()
}

/// One grant, with the evidence line pm prefixes with the file and the plugin name.
fn grant(permission: Permission, directive: &Directive) -> Grant {
    Grant {
        permission,
        evidence: format!("{}: {}=", directive.line, directive.key),
    }
}

/// Whether a boolean directive says yes, in any of the spellings systemd accepts.
fn is_yes(value: &str) -> bool {
    ["yes", "true", "on", "1"]
        .iter()
        .any(|spelling| value.eq_ignore_ascii_case(spelling))
}

/// The program name of a command's first word: the last path component.
fn program_name(word: &str) -> Option<&str> {
    let name = word.rsplit('/').next()?;
    (!name.is_empty()).then_some(name)
}

export!(Systemd);
