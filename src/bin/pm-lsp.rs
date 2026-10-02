//! `pm-lsp`: a language server for pm build files (`*.package`).
//!
//! Speaks LSP over stdio. Build files are Starlark, so this is the stock
//! Starlark language server configured for pm: the dialect `pm build` evaluates
//! with, and a global scope of the Starlark core library plus `package`, `step`
//! and the stage constants - so `pm`'s own builtins complete, show their
//! documentation on hover, and a misspelt name is flagged before a build runs.
//!
//! `load()` is not offered, because pm does not evaluate it (see
//! [`pm::star`]).

use std::{collections::HashSet, fs::read_to_string, path::Path};

use miette::IntoDiagnostic;
use pm::star;
use starlark::{
    analysis::{AstModuleLint, EvalMessage},
    docs::DocModule,
    syntax::AstModule,
};
use starlark_lsp::{
    error::eval_message_to_lsp_diagnostic,
    server::{LspContext, LspEvalResult, LspUri, StringLiteralResult, stdio_server},
};

const NO_LOAD: &str = "load() is not supported in pm build files: a signature covers one file";

struct PmContext {
    globals: starlark::environment::Globals,
    names: HashSet<String>,
}

impl PmContext {
    fn new() -> Self {
        let globals = star::globals();
        let names = globals
            .names()
            .map(|name| name.as_str().to_owned())
            .collect();
        Self { globals, names }
    }
}

impl LspContext for PmContext {
    fn parse_file_with_contents(&self, uri: &LspUri, content: String) -> LspEvalResult {
        let (LspUri::File(path) | LspUri::Starlark(path)) = uri else {
            return LspEvalResult::default();
        };
        match AstModule::parse(&path.to_string_lossy(), content, &star::dialect()) {
            Ok(ast) => {
                let diagnostics = ast
                    .lint(Some(&self.names))
                    .into_iter()
                    .map(|lint| eval_message_to_lsp_diagnostic(EvalMessage::from(lint)))
                    .collect();
                LspEvalResult {
                    diagnostics,
                    ast: Some(ast),
                }
            }
            Err(error) => LspEvalResult {
                diagnostics: vec![eval_message_to_lsp_diagnostic(EvalMessage::from_error(
                    path, &error,
                ))],
                ast: None,
            },
        }
    }

    fn resolve_load(
        &self,
        _path: &str,
        _current_file: &LspUri,
        _workspace_root: Option<&Path>,
    ) -> Result<LspUri, String> {
        Err(NO_LOAD.to_owned())
    }

    fn render_as_load(
        &self,
        _target: &LspUri,
        _current_file: &LspUri,
        _workspace_root: Option<&Path>,
    ) -> Result<String, String> {
        Err(NO_LOAD.to_owned())
    }

    fn resolve_string_literal(
        &self,
        _literal: &str,
        _current_file: &LspUri,
        _workspace_root: Option<&Path>,
    ) -> Result<Option<StringLiteralResult>, String> {
        Ok(None)
    }

    fn get_load_contents(&self, uri: &LspUri) -> Result<Option<String>, String> {
        match uri {
            LspUri::File(path) => match read_to_string(path) {
                Ok(text) => Ok(Some(text)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.to_string()),
            },
            _ => Ok(None),
        }
    }

    fn get_environment(&self, _uri: &LspUri) -> DocModule {
        self.globals.documentation()
    }

    fn get_uri_for_global_symbol(
        &self,
        _current_file: &LspUri,
        _symbol: &str,
    ) -> Result<Option<LspUri>, String> {
        Ok(None)
    }
}

fn main() -> miette::Result<()> {
    stdio_server(PmContext::new()).into_diagnostic()
}
