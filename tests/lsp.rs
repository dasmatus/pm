//! End-to-end test of the `pm-lsp` language server over stdio.

use std::{
    io::Write as _,
    process::{Command, Stdio},
};

use serde_json::{Value, json};

fn frame(message: &Value) -> Vec<u8> {
    let body = message.to_string();
    format!("Content-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

/// Runs a whole LSP session and returns everything the server wrote to stdout.
fn session(text: &str) -> String {
    let uri = "file:///tmp/pm-lsp-test/build.package";
    let mut input = Vec::new();
    for message in [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"capabilities": {}, "rootUri": "file:///tmp/pm-lsp-test"}}),
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
        json!({"jsonrpc": "2.0", "method": "textDocument/didOpen",
               "params": {"textDocument": {"uri": uri, "languageId": "pm", "version": 1, "text": text}}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "textDocument/hover",
               "params": {"textDocument": {"uri": uri}, "position": {"line": 0, "character": 1}}}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
        json!({"jsonrpc": "2.0", "method": "exit"}),
    ] {
        input.extend(frame(&message));
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_pm-lsp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start pm-lsp");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&input)
        .expect("send");
    let output = child.wait_with_output().expect("pm-lsp exits after `exit`");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn flags_undefined_names_and_documents_builtins() {
    let out = session("package(name = \"a\", version = \"1\", steps = [stpe(1)])\n");
    assert!(out.contains("publishDiagnostics"), "{out}");
    assert!(out.contains("undefined variable `stpe`"), "{out}");
    assert!(
        out.contains("Declare the package this file builds"),
        "{out}"
    );
}

#[test]
fn reports_syntax_errors() {
    let out = session("package(\n");
    assert!(out.contains("publishDiagnostics"), "{out}");
    assert!(out.contains("\"severity\":1"), "{out}");
}

#[test]
fn known_builtins_are_not_flagged() {
    let out = session("package(\"a\", \"1\", steps = [step(Prepare, \"x\", [])])\n");
    assert!(!out.contains("undefined"), "{out}");
}
