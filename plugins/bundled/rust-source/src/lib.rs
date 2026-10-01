//! Reads Rust sources (`.rs`) for what the built program will need at run
//! time. The query engine is `bundled-source`.

use bundled_source::{Implies, Language, Scanner, SourceQuery, tree_sitter};

static SCANNER: Scanner = Scanner::new(&[Language {
    name: "rust",
    extensions: &["rs"],
    grammar,
    queries: RUST_QUERIES,
}]);

fn grammar() -> tree_sitter::Language {
    tree_sitter_rust::LANGUAGE.into()
}

/// Rust: `use` trees name the crate, and the standard library's constructors name the mode.
static RUST_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "rust:net-import",
        query: r#"
            (use_declaration
              [(scoped_identifier path: (scoped_identifier name: (identifier) @_m))
               (scoped_use_list path: (scoped_identifier name: (identifier) @_m))
               (scoped_identifier path: (identifier) @_m)
               (scoped_use_list path: (identifier) @_m)
               (identifier) @_m]
              (#any-of? @_m
                "net" "reqwest" "hyper" "ureq" "curl" "tonic" "socket2" "isahc")) @call
        "#,
        implies: Implies::Network,
    },
    SourceQuery {
        name: "rust:net-call",
        query: r#"
            (call_expression
              function: (scoped_identifier
                path: (identifier) @_ty
                name: (identifier) @_fn)
              (#any-of? @_ty "TcpStream" "TcpListener" "UdpSocket" "reqwest" "hyper" "ureq")) @call
        "#,
        implies: Implies::Network,
    },
    SourceQuery {
        name: "rust:process-import",
        query: r#"
            (use_declaration
              [(scoped_identifier path: (scoped_identifier name: (identifier) @_m))
               (scoped_use_list path: (scoped_identifier name: (identifier) @_m))]
              (#any-of? @_m "process")) @call
        "#,
        implies: Implies::Spawn,
    },
    SourceQuery {
        name: "rust:command-new",
        query: r#"
            (call_expression
              function: (scoped_identifier
                path: (identifier) @_ty
                name: (identifier) @_fn)
              (#eq? @_ty "Command")
              (#eq? @_fn "new")) @call
        "#,
        implies: Implies::Spawn,
    },
    SourceQuery {
        name: "rust:command-program",
        query: r#"
            (call_expression
              function: (scoped_identifier
                path: (identifier) @_ty
                name: (identifier) @_fn)
              arguments: (arguments . (string_literal) @exec.path)
              (#eq? @_ty "Command")
              (#eq? @_fn "new")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "rust:file-create",
        query: r#"
            (call_expression
              function: (scoped_identifier name: (identifier) @_fn)
              arguments: (arguments . (string_literal) @write.path)
              (#any-of? @_fn
                "create" "create_new" "create_dir" "create_dir_all"
                "write" "remove_file" "remove_dir_all" "rename")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "rust:path-literal",
        query: r"(string_literal) @path",
        implies: Implies::Nothing,
    },
];

bundled::plugin! {
    name: "rust-source",
    summary: "reads Rust sources",
    commands: &bundled::NO_COMMANDS,
    sources: &SCANNER,
}
