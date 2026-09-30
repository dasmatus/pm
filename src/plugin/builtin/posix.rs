//! The POSIX userland: coreutils and their neighbours, the shells, the archivers, and
//! the Bash grammar.

use tree_sitter::Language;

use super::{Builtin, WANTS_NETWORK, WANTS_NOTHING, WANTS_SPAWN};
use crate::{
    perms::source::{LanguageRules, SourceQuery},
    policy::{Capability, Fingerprint},
};

pub(super) static PLUGIN: Builtin = Builtin {
    name: "posix",
    summary: "coreutils, sed, awk, grep, the shells and the archivers; reads shell scripts",
    fingerprints: FINGERPRINTS,
    languages: &[LanguageRules {
        name: "bash",
        extensions: &["sh", "bash"],
        grammar,
        queries: BASH_QUERIES,
    }],
};

static FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        name: "coreutils",
        // Not literally GNU coreutils - `sed`, `awk`, `grep` and `patch` live
        // here too, because they need exactly the same thing from the jail:
        // the files in the workdir and the destdir, and nothing else.
        pattern: program!(
            r"install|cp|mv|rm|mkdir|rmdir|chmod|chown|ln|ls|cat|echo|printf|touch|true|false|test|pwd|env|mktemp|sed|awk|gawk|grep|find|xargs|sort|head|tail|cut|tr|sync|patch"
        ),
        capabilities: &[Capability::Coreutils],
    },
    Fingerprint {
        name: "shell",
        pattern: program!(r"sh|bash|dash|ash|zsh"),
        capabilities: &[Capability::Shell, Capability::Coreutils],
    },
    Fingerprint {
        name: "archive",
        pattern: program!(r"tar|unzip|zip|xz|unxz|gzip|gunzip|bzip2|bunzip2|zstd|unzstd|7z|cpio"),
        capabilities: &[Capability::Archive, Capability::Coreutils],
    },
];

fn grammar() -> Language {
    tree_sitter_bash::LANGUAGE.into()
}

/// Bash: a command name is its own node, and a redirection target is a node too - so
/// `> /var/log/x` is a write with no heuristics at all.
static BASH_QUERIES: &[SourceQuery] = &[
    SourceQuery {
        name: "bash:network-command",
        query: r#"
            (command
              name: (command_name (word) @_cmd)
              (#any-of? @_cmd
                "curl" "wget" "nc" "netcat" "ftp" "sftp" "scp" "rsync" "ssh"
                "telnet" "git" "pip" "pip3" "npm" "cargo" "apt" "apt-get" "dnf")) @call
        "#,
        implies: &WANTS_NETWORK,
    },
    SourceQuery {
        name: "bash:spawn-command",
        query: r"(command name: (command_name) @call)",
        implies: &WANTS_SPAWN,
    },
    SourceQuery {
        name: "bash:exec-command",
        query: r#"
            (command
              name: (command_name (word) @_cmd)
              argument: (word) @exec.path
              (#any-of? @_cmd "exec" "nohup" "setsid" "sudo" "env" "timeout")) @call
        "#,
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "bash:redirect-write",
        query: r"(file_redirect destination: [(word) (string)] @write.path) @call",
        implies: &WANTS_NOTHING,
    },
    SourceQuery {
        name: "bash:path-literal",
        query: r"[(word) (string) (raw_string)] @path",
        implies: &WANTS_NOTHING,
    },
];
