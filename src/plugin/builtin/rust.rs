//! Rust: Cargo, and the Rust grammar.

use tree_sitter::Language;

use super::{Builtin, FETCHING_TOOLCHAIN, WANTS_NETWORK, WANTS_NOTHING, WANTS_SPAWN};
use crate::{
    perms::source::{LanguageRules, SourceQuery},
    policy::Fingerprint,
};

pub(super) static PLUGIN: Builtin = Builtin {
    name: "rust",
    summary: "cargo and rustc; reads `.rs` sources",
    fingerprints: FINGERPRINTS,
    languages: &[LanguageRules {
        name: "rust",
        extensions: &["rs"],
        grammar,
        queries: RUST_QUERIES,
    }],
};

static FINGERPRINTS: &[Fingerprint] = &[Fingerprint {
    name: "cargo",
    // Cargo resolves and downloads the dependency graph itself.
    pattern: program!(r"cargo|rustc"),
    capabilities: &FETCHING_TOOLCHAIN,
}];

fn grammar() -> Language {
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
        implies: &WANTS_NETWORK,
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
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "rust:process-import",
        query: r#"
            (use_declaration
              [(scoped_identifier path: (scoped_identifier name: (identifier) @_m))
               (scoped_use_list path: (scoped_identifier name: (identifier) @_m))]
              (#any-of? @_m "process")) @call
        "#,
        implies: &WANTS_SPAWN,
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
        implies: &WANTS_SPAWN,
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
        implies: &WANTS_NOTHING,
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
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "rust:path-literal",
        query: r"(string_literal) @path",
        implies: &WANTS_NOTHING,
    },
];
