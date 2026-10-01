//! Reads C, the base for C++ sources (`.c`, `.h`) for what the built program will need at run
//! time. The query engine is `bundled-source`.

use bundled_source::{Implies, Language, Scanner, SourceQuery, tree_sitter};

static SCANNER: Scanner = Scanner::new(&[Language {
    name: "c",
    extensions: &["c", "h"],
    grammar,
    queries: C_QUERIES,
}]);

fn grammar() -> tree_sitter::Language {
    tree_sitter_c::LANGUAGE.into()
}

/// C, and the base for C++: plain identifier calls plus string literals.
static C_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "c:network-call",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#any-of? @_fn
                "socket" "socketpair" "connect" "bind" "listen" "accept" "accept4"
                "getaddrinfo" "gethostbyname" "getnameinfo" "sendto" "recvfrom")) @call
        "#,
        implies: Implies::Network,
    },
    SourceQuery {
        name: "c:spawn-call",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#any-of? @_fn
                "fork" "vfork" "system" "popen" "posix_spawn" "posix_spawnp"
                "execl" "execlp" "execle" "execv" "execvp" "execvpe" "execve")) @call
        "#,
        implies: Implies::Spawn,
    },
    SourceQuery {
        name: "c:exec-path",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list . (string_literal) @exec.path)
              (#any-of? @_fn
                "execl" "execlp" "execle" "execv" "execvp" "execvpe" "execve"
                "posix_spawn" "posix_spawnp")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "c:fopen-mode",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path . (string_literal) @mode)
              (#any-of? @_fn "fopen" "fopen64" "freopen")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "c:open-flags",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path) @mode
              (#any-of? @_fn "open" "open64" "openat")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "c:create-path",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list . (string_literal) @write.path)
              (#any-of? @_fn "creat" "mkdir" "unlink" "rename" "truncate")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "c:path-literal",
        query: r"(string_literal) @path",
        implies: Implies::Nothing,
    },
];

bundled::plugin! {
    name: "c-source",
    summary: "reads C, the base for C++ sources",
    commands: &bundled::NO_COMMANDS,
    sources: &SCANNER,
}
