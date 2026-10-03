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
    session_at("file:///tmp/pm-lsp-test/build.rhai", text)
}

fn session_at(uri: &str, text: &str) -> String {
    session_with(&["--no-plugins"], uri, text, 1)
}

/// A session with `args` on the server's command line, hovering at `character` on the
/// first line.
fn session_with(args: &[&str], uri: &str, text: &str, character: u32) -> String {
    let mut input = Vec::new();
    for message in [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"capabilities": {}, "rootUri": "file:///tmp/pm-lsp-test"}}),
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
        json!({"jsonrpc": "2.0", "method": "textDocument/didOpen",
               "params": {"textDocument": {"uri": uri, "languageId": "rhai", "version": 1, "text": text}}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "textDocument/hover",
               "params": {"textDocument": {"uri": uri}, "position": {"line": 0, "character": character}}}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
        json!({"jsonrpc": "2.0", "method": "exit"}),
    ] {
        input.extend(frame(&message));
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_pm-lsp"))
        .args(args)
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
    let out = session("package(#{ name: \"a\", version: \"1\", steps: [stpe(1)] });\n");
    assert!(out.contains("publishDiagnostics"), "{out}");
    assert!(out.contains("stpe"), "{out}");
    // The error points at the call, not the start of the file.
    assert!(out.contains("\"character\":44"), "{out}");
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
fn a_valid_recipe_has_no_diagnostics() {
    let out =
        session("package(#{ name: \"a\", version: \"1\", steps: [step(Prepare, \"x\", [])] });\n");
    assert!(out.contains("\"diagnostics\":[]"), "{out}");
}

#[test]
fn starlark_files_are_flagged_as_deprecated() {
    let out = session_at(
        "file:///tmp/pm-lsp-test/build.package",
        "package(name = \"a\", version = \"1\")\n",
    );
    assert!(out.contains("pm migrate"), "{out}");
    assert!(out.contains("\"severity\":2"), "{out}");
}

#[test]
fn plugin_modules_resolve_and_are_documented() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        std::path::Path::new(env!("PM_TEST_PLUGIN_DIR")).join("systemd.wasm"),
        dir.path().join("systemd.wasm"),
    )
    .expect("stage the systemd plugin");
    let plugin_dir = dir.path().to_str().expect("a UTF-8 path");
    let text = "let s = systemd::install_unit(\"a.service\"); package(#{ name: \"a\", version: \"1\", steps: [s] });\n";
    let out = session_with(
        &["--plugin-dir", plugin_dir, "--allow-unsigned-plugins"],
        "file:///tmp/pm-lsp-test/build.rhai",
        text,
        20,
    );
    assert!(out.contains("\"diagnostics\":[]"), "{out}");
    assert!(out.contains("systemd::install_unit(file) -> Step"), "{out}");

    // Without the plugin, the same recipe is an error.
    let out = session(text);
    assert!(out.contains("\"severity\":1"), "{out}");
}

#[test]
fn definitions_can_be_printed() {
    let output = Command::new(env!("CARGO_BIN_EXE_pm-lsp"))
        .args(["--no-plugins", "--definitions"])
        .output()
        .expect("run pm-lsp");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("fn Package("), "{text}");
}
