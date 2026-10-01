//! Reads C++ sources (`.cc`, `.cpp`, `.cxx`, `.c++`, `.hpp`, `.hh`, `.hxx`) for what the built program will need at run
//! time. The query engine is `bundled-source`.

use bundled_source::{Implies, Language, Scanner, SourceQuery, tree_sitter};

static SCANNER: Scanner = Scanner::new(&[Language {
    name: "cpp",
    extensions: &["cc", "cpp", "cxx", "c++", "hpp", "hh", "hxx"],
    grammar,
    queries: CPP_QUERIES,
}]);

fn grammar() -> tree_sitter::Language {
    tree_sitter_cpp::LANGUAGE.into()
}

/// C++: everything C does, plus the qualified-call and `ofstream` forms C has no node for.
static CPP_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "cpp:network-call",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#any-of? @_fn
                "socket" "socketpair" "connect" "bind" "listen" "accept"
                "getaddrinfo" "gethostbyname" "sendto" "recvfrom")) @call
        "#,
        implies: Implies::Network,
    },
    SourceQuery {
        name: "cpp:network-call-qualified",
        query: r#"
            (call_expression
              function: (qualified_identifier name: (identifier) @_fn)
              (#any-of? @_fn
                "socket" "socketpair" "connect" "bind" "listen" "accept"
                "getaddrinfo" "gethostbyname" "sendto" "recvfrom")) @call
        "#,
        implies: Implies::Network,
    },
    SourceQuery {
        name: "cpp:spawn-call",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#any-of? @_fn
                "fork" "vfork" "system" "popen" "posix_spawn"
                "execl" "execlp" "execv" "execvp" "execve")) @call
        "#,
        implies: Implies::Spawn,
    },
    SourceQuery {
        name: "cpp:spawn-call-qualified",
        query: r#"
            (call_expression
              function: (qualified_identifier name: (identifier) @_fn)
              (#any-of? @_fn
                "fork" "vfork" "system" "popen" "posix_spawn"
                "execl" "execlp" "execv" "execvp" "execve")) @call
        "#,
        implies: Implies::Spawn,
    },
    SourceQuery {
        name: "cpp:fopen-mode",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path . (string_literal) @mode)
              (#any-of? @_fn "fopen" "fopen64" "freopen")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "cpp:open-flags",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path) @mode
              (#any-of? @_fn "open" "open64" "openat")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "cpp:ofstream",
        query: r#"
            (declaration
              type: (qualified_identifier name: (type_identifier) @_ty)
              declarator: (init_declarator
                (argument_list . (string_literal) @write.path))
              (#any-of? @_ty "ofstream" "fstream" "ofstream_t")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "cpp:path-literal",
        query: r"(string_literal) @path",
        implies: Implies::Nothing,
    },
];

bundled::plugin! {
    name: "cpp-source",
    summary: "reads C++ sources",
    commands: &bundled::NO_COMMANDS,
    sources: &SCANNER,
}
