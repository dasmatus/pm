//! Python: pip, the interpreter, and the Python grammar.

use tree_sitter::Language;

use super::{Builtin, FETCHING_TOOLCHAIN, WANTS_NETWORK, WANTS_NOTHING, WANTS_SPAWN};
use crate::{
    perms::source::{LanguageRules, SourceQuery},
    policy::{Capability, Fingerprint},
};

pub(super) static PLUGIN: Builtin = Builtin {
    name: "python",
    summary: "pip and python; reads `.py` and `.pyi` sources",
    fingerprints: FINGERPRINTS,
    languages: &[LanguageRules {
        name: "python",
        extensions: &["py", "pyi"],
        grammar,
        queries: PYTHON_QUERIES,
    }],
};

static FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        name: "pip",
        pattern: program!(r"pip[23]?"),
        capabilities: &FETCHING_TOOLCHAIN,
    },
    Fingerprint {
        name: "python",
        // `python setup.py build` and friends. Deliberately NOT granted
        // Network: a setup.py that needs to download says so with `dl_urls`
        // or reaches for pip, and both of those grant it explicitly.
        pattern: program!(r"python[23]?(?:\.\d+)?"),
        capabilities: &[Capability::Toolchain, Capability::Coreutils],
    },
];

fn grammar() -> Language {
    tree_sitter_python::LANGUAGE.into()
}

/// Python: imports are nodes, and `open`'s mode is its second argument.
static PYTHON_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "python:net-import",
        query: r#"
            (import_statement
              name: [(dotted_name (identifier) @_m)
                     (aliased_import name: (dotted_name (identifier) @_m))]
              (#any-of? @_m
                "socket" "requests" "urllib" "urllib2" "urllib3" "http" "httplib"
                "httpx" "aiohttp" "ftplib" "smtplib" "telnetlib")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "python:net-import-from",
        query: r#"
            (import_from_statement
              module_name: (dotted_name (identifier) @_m)
              (#any-of? @_m
                "socket" "requests" "urllib" "urllib2" "urllib3" "http" "httplib"
                "httpx" "aiohttp" "ftplib" "smtplib" "telnetlib")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "python:net-call",
        query: r#"
            (call
              function: (attribute object: (identifier) @_obj)
              (#any-of? @_obj "socket" "requests" "urllib" "httpx" "aiohttp")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "python:spawn-import",
        query: r#"
            (import_statement
              name: [(dotted_name (identifier) @_m)
                     (aliased_import name: (dotted_name (identifier) @_m))]
              (#any-of? @_m "subprocess" "multiprocessing" "pty")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "python:spawn-import-from",
        query: r#"
            (import_from_statement
              module_name: (dotted_name (identifier) @_m)
              (#any-of? @_m "subprocess" "multiprocessing" "pty")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "python:spawn-call",
        query: r#"
            (call
              function: (attribute
                object: (identifier) @_obj
                attribute: (identifier) @_fn)
              (#any-of? @_obj "subprocess" "os")
              (#any-of? @_fn
                "run" "call" "check_call" "check_output" "Popen" "system" "popen"
                "fork" "execv" "execvp" "execl" "execlp" "spawnv" "spawnl" "posix_spawn")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "python:open-mode",
        query: r#"
            (call
              function: (identifier) @_fn
              arguments: (argument_list (string) @path . (string) @mode)
              (#any-of? @_fn "open" "fdopen")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "python:write-call",
        query: r#"
            (call
              function: (attribute object: (identifier) @_obj attribute: (identifier) @_fn)
              arguments: (argument_list . (string) @write.path)
              (#any-of? @_obj "os" "shutil" "pathlib")
              (#any-of? @_fn
                "remove" "unlink" "rename" "mkdir" "makedirs" "rmtree" "copy" "chmod")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "python:path-literal",
        query: r"(string) @path",
        implies: &WANTS_NOTHING,
    },
];
