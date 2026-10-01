//! Reads Bash sources (`.sh`, `.bash`) for what the built program will need at run
//! time. The query engine is `bundled-source`.

use bundled_source::{Implies, Language, Scanner, SourceQuery, tree_sitter};

static SCANNER: Scanner = Scanner::new(&[Language {
    name: "bash",
    extensions: &["sh", "bash"],
    grammar,
    queries: BASH_QUERIES,
}]);

fn grammar() -> tree_sitter::Language {
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
        implies: Implies::Network,
    },
    SourceQuery {
        name: "bash:spawn-command",
        query: r"(command name: (command_name) @call)",
        implies: Implies::Spawn,
    },
    SourceQuery {
        name: "bash:exec-command",
        query: r#"
            (command
              name: (command_name (word) @_cmd)
              argument: (word) @exec.path
              (#any-of? @_cmd "exec" "nohup" "setsid" "sudo" "env" "timeout")) @call
        "#,
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "bash:redirect-write",
        query: r"(file_redirect destination: [(word) (string)] @write.path) @call",
        implies: Implies::Nothing,
    },
    SourceQuery {
        name: "bash:path-literal",
        query: r"[(word) (string) (raw_string)] @path",
        implies: Implies::Nothing,
    },
];

bundled::plugin! {
    name: "bash-source",
    summary: "reads Bash sources",
    commands: &bundled::NO_COMMANDS,
    sources: &SCANNER,
}
