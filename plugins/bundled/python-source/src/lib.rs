//! Reads Python sources (`.py`, `.pyi`) for what the built program will need at run
//! time. The query engine is `bundled-source`.

use bundled_source::{Implies, Language, Scanner, SourceQuery, tree_sitter};

static SCANNER: Scanner = Scanner::new(&[Language {
    name: "python",
    extensions: &["py", "pyi"],
    grammar,
    queries: PYTHON_QUERIES,
}]);

fn grammar() -> tree_sitter::Language {
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
        implies: Implies::Network,
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
        implies: Implies::Network,
    },
    SourceQuery {
        name: "python:net-call",
        query: r#"
            (call
              function: (attribute object: (identifier) @_obj)
              (#any-of? @_obj "socket" "requests" "urllib" "httpx" "aiohttp")) @call
        "#,
        implies: Implies::Network,
    },
    SourceQuery {
        name: "python:spawn-import",
        query: r#"
            (import_statement
              name: [(dotted_name (identifier) @_m)
                     (aliased_import name: (dotted_name (identifier) @_m))]
              (#any-of? @_m "subprocess" "multiprocessing" "pty")) @call
        "#,
        implies: Implies::Spawn,
    },
    SourceQuery {
        name: "python:spawn-import-from",
        query: r#"
            (import_from_statement
              module_name: (dotted_name (identifier) @_m)
              (#any-of? @_m "subprocess" "multiprocessing" "pty")) @call
        "#,
        implies: Implies::Spawn,
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
        implies: Implies::Spawn,
    },
    SourceQuery {
        name: "python:open-mode",
        query: r#"
            (call
              function: (identifier) @_fn
              arguments: (argument_list (string) @path . (string) @mode)
              (#any-of? @_fn "open" "fdopen")) @call
        "#,
        implies: Implies::Nothing,
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
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "python:path-literal",
        query: r"(string) @path",
        implies: Implies::Nothing,
    },
];

bundled::plugin! {
    name: "python-source",
    summary: "reads Python sources",
    commands: &bundled::NO_COMMANDS,
    sources: &SCANNER,
}
