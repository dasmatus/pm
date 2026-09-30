//! Go: the go command, and the Go grammar.

use tree_sitter::Language;

use super::{Builtin, FETCHING_TOOLCHAIN, WANTS_NETWORK, WANTS_NOTHING, WANTS_SPAWN};
use crate::{
    perms::source::{LanguageRules, SourceQuery},
    policy::Fingerprint,
};

pub(super) static PLUGIN: Builtin = Builtin {
    name: "go",
    summary: "the go command; reads `.go` sources",
    fingerprints: FINGERPRINTS,
    languages: &[LanguageRules {
        name: "go",
        extensions: &["go"],
        grammar,
        queries: GO_QUERIES,
    }],
};

static FINGERPRINTS: &[Fingerprint] = &[Fingerprint {
    name: "go",
    // `go build` fetches modules; `gofmt` is a different word and does not
    // match, because the pattern demands a word terminator after `go`.
    pattern: program!(r"go"),
    capabilities: &FETCHING_TOOLCHAIN,
}];

fn grammar() -> Language {
    tree_sitter_go::LANGUAGE.into()
}

/// Go: the import path is a string literal, so the import itself is queryable.
static GO_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "go:net-import",
        query: r#"
            (import_spec
              path: (interpreted_string_literal (interpreted_string_literal_content) @_p)
              (#any-of? @_p
                "net" "net/http" "net/url" "net/rpc" "net/smtp" "crypto/tls"
                "golang.org/x/net/http2")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "go:net-call",
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              (#any-of? @_pkg "net" "http" "tls" "smtp")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "go:spawn-import",
        query: r#"
            (import_spec
              path: (interpreted_string_literal (interpreted_string_literal_content) @_p)
              (#any-of? @_p "os/exec" "syscall")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "go:spawn-call",
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              (#any-of? @_pkg "exec" "os" "syscall")
              (#any-of? @_fn "Command" "CommandContext" "StartProcess" "Exec" "ForkExec")) @call
        "#,
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "go:openfile-flags",
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              arguments: (argument_list (interpreted_string_literal) @path) @mode
              (#eq? @_pkg "os")
              (#any-of? @_fn "OpenFile")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "go:write-call",
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              arguments: (argument_list . (interpreted_string_literal) @write.path)
              (#any-of? @_pkg "os" "ioutil")
              (#any-of? @_fn
                "Create" "WriteFile" "Remove" "RemoveAll" "Mkdir" "MkdirAll" "Rename")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "go:path-literal",
        query: r"[(interpreted_string_literal) (raw_string_literal)] @path",
        implies: &WANTS_NOTHING,
    },
];
