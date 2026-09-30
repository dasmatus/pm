//! C and C++: the compilers, binutils and pkg-config, and both grammars.

use tree_sitter::Language;

use super::{Builtin, WANTS_NETWORK, WANTS_NOTHING, WANTS_SPAWN};
use crate::{
    perms::source::{LanguageRules, SourceQuery},
    policy::{Capability, Fingerprint},
};

pub(super) static PLUGIN: Builtin = Builtin {
    name: "c",
    summary: "C and C++ compilers, binutils and pkg-config; reads C and C++ sources",
    fingerprints: FINGERPRINTS,
    languages: &[
        LanguageRules {
            name: "c",
            extensions: &["c", "h"],
            grammar: c_grammar,
            queries: C_QUERIES,
        },
        LanguageRules {
            name: "cpp",
            extensions: &["cc", "cpp", "cxx", "c++", "hpp", "hh", "hxx"],
            grammar: cpp_grammar,
            queries: CPP_QUERIES,
        },
    ],
};

static FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        name: "pkg-config",
        pattern: program!(r"pkg-config|pkgconf"),
        capabilities: &[Capability::Toolchain],
    },
    Fingerprint {
        name: "compiler",
        // `cc`, `gcc`, `g++`, `clang`, `clang++`, their versioned spellings
        // (`gcc-14`) and their cross-compiler spellings.
        pattern: prefixed_program!(r"(?:cc|c\+\+|gcc|g\+\+|clang|clang\+\+)(?:-\d+(?:\.\d+)*)?"),
        capabilities: &[Capability::Toolchain, Capability::Coreutils],
    },
    Fingerprint {
        name: "ld",
        // The linker and the rest of binutils, including cross spellings.
        pattern: prefixed_program!(r"ld|ld\.bfd|ld\.gold|ld\.lld|lld|ar|ranlib|nm|strip|objcopy"),
        capabilities: &[Capability::Toolchain],
    },
];

fn c_grammar() -> Language {
    tree_sitter_c::LANGUAGE.into()
}

fn cpp_grammar() -> Language {
    tree_sitter_cpp::LANGUAGE.into()
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
        implies: &WANTS_NETWORK,
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
        implies: &WANTS_SPAWN,
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
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "c:fopen-mode",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path . (string_literal) @mode)
              (#any-of? @_fn "fopen" "fopen64" "freopen")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "c:open-flags",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path) @mode
              (#any-of? @_fn "open" "open64" "openat")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "c:create-path",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list . (string_literal) @write.path)
              (#any-of? @_fn "creat" "mkdir" "unlink" "rename" "truncate")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "c:path-literal",
        query: r"(string_literal) @path",
        implies: &WANTS_NOTHING,
    },
];

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
        implies: &WANTS_NETWORK,
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
        implies: &WANTS_NETWORK,
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
        implies: &WANTS_SPAWN,
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
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "cpp:fopen-mode",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path . (string_literal) @mode)
              (#any-of? @_fn "fopen" "fopen64" "freopen")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "cpp:open-flags",
        query: r#"
            (call_expression
              function: (identifier) @_fn
              arguments: (argument_list (string_literal) @path) @mode
              (#any-of? @_fn "open" "open64" "openat")) @call
        "#,
        implies: &WANTS_NOTHING,
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
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "cpp:path-literal",
        query: r"(string_literal) @path",
        implies: &WANTS_NOTHING,
    },
];
