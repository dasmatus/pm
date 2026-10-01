//! Reads Go sources (`.go`) for what the built program will need at run
//! time. The query engine is `bundled-source`.

use bundled_source::{Implies, Language, Scanner, SourceQuery, tree_sitter};

static SCANNER: Scanner = Scanner::new(&[Language {
    name: "go",
    extensions: &["go"],
    grammar,
    queries: GO_QUERIES,
}]);

fn grammar() -> tree_sitter::Language {
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
        implies: Implies::Network,
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
        implies: Implies::Network,
    },
    SourceQuery {
        name: "go:spawn-import",
        query: r#"
            (import_spec
              path: (interpreted_string_literal (interpreted_string_literal_content) @_p)
              (#any-of? @_p "os/exec" "syscall")) @call
        "#,
        implies: Implies::Spawn,
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
        implies: Implies::Spawn,
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
        implies: Implies::Nothing,
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
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "go:path-literal",
        query: r"[(interpreted_string_literal) (raw_string_literal)] @path",
        implies: Implies::Nothing,
    },
];

bundled::plugin! {
    name: "go-source",
    summary: "reads Go sources",
    commands: &bundled::NO_COMMANDS,
    sources: &SCANNER,
}
