//! `pm-lsp`: a language server for pm recipes (`*.rhai`).
//!
//! Speaks LSP over stdio. On every change it evaluates the recipe exactly as
//! `pm build` would - hermetic, and under the same operation limits, so an
//! endless loop costs a moment and not the editor - and reports the first error
//! where it happened: a syntax error, an undeclared variable, a misspelt
//! builtin, a missing `package(...)`, or a package that is not a valid build
//! file. It also completes pm's builtins and documents them on hover.
//!
//! Recipes are evaluated with the installed plugins' modules in scope, as `pm
//! build` would: `systemd::install_unit(...)` resolves, and completes, when the
//! systemd plugin is installed. Plugins load from `<config>/pm/plugins` with their
//! signatures checked, or from `--plugin-dir DIR`; `--allow-unsigned-plugins` and
//! `--no-plugins` mean what they mean to `pm`. A plugin directory that does not
//! load is reported once and the server carries on without plugins.
//!
//! `pm-lsp --definitions` prints a Rhai definitions file (`.d.rhai`) for pm's
//! builtins, types and plugin modules instead of serving, for editors that run a
//! Rhai language server of their own.
//!
//! Deprecated Starlark `.package` files get a warning pointing at `pm migrate`,
//! plus any error evaluating them.

use std::{collections::HashMap, io::IsTerminal};

use lsp_server::{Connection, Message, Notification, Request, Response};
use lsp_types::{
    CompletionItem, CompletionItemKind, CompletionOptions, Diagnostic, DiagnosticSeverity,
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams, Hover,
    HoverContents, HoverParams, HoverProviderCapability, MarkupContent, MarkupKind, Position,
    PublishDiagnosticsParams, Range, ServerCapabilities, TextDocumentSyncCapability,
    TextDocumentSyncKind, Uri,
    notification::{
        DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument, Notification as _,
        PublishDiagnostics,
    },
    request::{Completion, HoverRequest, Request as _},
};
use miette::IntoDiagnostic;
use pm::{
    plugin::{Loader, Registry, default_plugin_dir},
    recipe, star,
};
use tracing::warn;
use tracing_subscriber::EnvFilter;

fn main() -> miette::Result<()> {
    // Logs go to stderr, which editors show in the server's output panel: stdout
    // is the protocol, and one stray line there breaks the session.
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let mut args = std::env::args().skip(1);
    let mut definitions = false;
    let mut no_plugins = false;
    let mut allow_unsigned = false;
    let mut plugin_dir = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--definitions" => definitions = true,
            "--no-plugins" => no_plugins = true,
            "--allow-unsigned-plugins" => allow_unsigned = true,
            "--plugin-dir" => {
                let Some(dir) = args.next() else {
                    return Err(miette::miette!("--plugin-dir needs a directory"));
                };
                plugin_dir = Some(std::path::PathBuf::from(dir));
            }
            "--version" => {
                println!("pm-lsp {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => {
                return Err(miette::miette!(
                    help = "Usage: pm-lsp [--definitions] [--plugin-dir DIR] \
                            [--allow-unsigned-plugins] [--no-plugins]",
                    "unknown argument {other:?}"
                ));
            }
        }
    }
    let plugins = if no_plugins {
        Registry::empty()
    } else {
        load_plugins(plugin_dir, allow_unsigned)
    };
    if definitions {
        print!("{}", recipe::definitions(&plugins));
        return Ok(());
    }

    let (connection, io_threads) = Connection::stdio();
    let capabilities = ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        completion_provider: Some(CompletionOptions::default()),
        ..ServerCapabilities::default()
    };
    connection
        .initialize(serde_json::to_value(capabilities).into_diagnostic()?)
        .into_diagnostic()?;
    serve(&connection, &plugins)?;
    drop(connection);
    io_threads.join().into_diagnostic()
}

/// The installed plugins, or none when they do not load: an editor is better served
/// by a server that checks recipes without plugin modules than by none at all.
fn load_plugins(dir: Option<std::path::PathBuf>, allow_unsigned: bool) -> Registry {
    let loaded = dir
        .map_or_else(default_plugin_dir, Ok)
        .and_then(|dir| Loader::new(dir).allow_unsigned(allow_unsigned).load());
    loaded.unwrap_or_else(|report| {
        warn!("carrying on without plugins: {report:?}");
        Registry::empty()
    })
}

/// Answer requests until the client shuts the server down.
fn serve(connection: &Connection, plugins: &Registry) -> miette::Result<()> {
    // Keyed by the URI's text: `Uri` caches parts of itself, so it is a poor key.
    let mut documents = HashMap::<String, String>::new();
    for message in &connection.receiver {
        match message {
            Message::Request(request) => {
                if connection.handle_shutdown(&request).into_diagnostic()? {
                    return Ok(());
                }
                let response = respond(&documents, plugins, request);
                connection
                    .sender
                    .send(Message::Response(response))
                    .into_diagnostic()?;
            }
            Message::Notification(notification) => {
                if let Some((uri, text)) = update(&mut documents, notification) {
                    let diagnostics = text.as_deref().map(|text| check(&uri, text, plugins));
                    let params = PublishDiagnosticsParams {
                        uri,
                        diagnostics: diagnostics.unwrap_or_default(),
                        version: None,
                    };
                    connection
                        .sender
                        .send(Message::Notification(Notification::new(
                            PublishDiagnostics::METHOD.to_owned(),
                            params,
                        )))
                        .into_diagnostic()?;
                }
            }
            Message::Response(_) => {}
        }
    }
    Ok(())
}

/// Apply a document notification. Returns the document it touched and its new
/// text, `None` once it is closed.
fn update(
    documents: &mut HashMap<String, String>,
    notification: Notification,
) -> Option<(Uri, Option<String>)> {
    match notification.method.as_str() {
        DidOpenTextDocument::METHOD => {
            let params: DidOpenTextDocumentParams =
                notification.extract(DidOpenTextDocument::METHOD).ok()?;
            let document = params.text_document;
            documents.insert(document.uri.as_str().to_owned(), document.text.clone());
            Some((document.uri, Some(document.text)))
        }
        DidChangeTextDocument::METHOD => {
            let params: DidChangeTextDocumentParams =
                notification.extract(DidChangeTextDocument::METHOD).ok()?;
            // Full sync: the last change is the whole document.
            let text = params.content_changes.into_iter().last()?.text;
            let uri = params.text_document.uri;
            documents.insert(uri.as_str().to_owned(), text.clone());
            Some((uri, Some(text)))
        }
        DidCloseTextDocument::METHOD => {
            let params: DidCloseTextDocumentParams =
                notification.extract(DidCloseTextDocument::METHOD).ok()?;
            documents.remove(params.text_document.uri.as_str());
            Some((params.text_document.uri, None))
        }
        _ => None,
    }
}

fn respond(documents: &HashMap<String, String>, plugins: &Registry, request: Request) -> Response {
    let id = request.id.clone();
    match request.method.as_str() {
        HoverRequest::METHOD => {
            let hover = request
                .extract::<HoverParams>(HoverRequest::METHOD)
                .ok()
                .and_then(|(_, params)| {
                    let position = params.text_document_position_params;
                    let text = documents.get(position.text_document.uri.as_str())?;
                    hover(text, position.position, plugins)
                });
            Response::new_ok(id, hover)
        }
        Completion::METHOD => Response::new_ok(id, completions(plugins)),
        _ => Response::new_err(
            id,
            lsp_server::ErrorCode::MethodNotFound as i32,
            format!("pm-lsp does not handle {}", request.method),
        ),
    }
}

/// Every problem with the document at `uri`.
fn check(uri: &Uri, text: &str, plugins: &Registry) -> Vec<Diagnostic> {
    if uri.as_str().ends_with(&format!(".{}", star::EXTENSION)) {
        let mut diagnostics = vec![Diagnostic {
            range: Range::default(),
            severity: Some(DiagnosticSeverity::WARNING),
            source: Some("pm".to_owned()),
            message: "Starlark recipes are deprecated and will stop loading in a future \
                      release; convert this file to Rhai with `pm migrate`"
                .to_owned(),
            ..Diagnostic::default()
        }];
        if let Err(error) = star::parse("recipe", text.to_owned()) {
            diagnostics.push(Diagnostic {
                range: Range::default(),
                severity: Some(DiagnosticSeverity::ERROR),
                source: Some("pm".to_owned()),
                message: error.to_string(),
                ..Diagnostic::default()
            });
        }
        return diagnostics;
    }
    let Err(error) = recipe::evaluate_with(text, plugins) else {
        return Vec::new();
    };
    let start = error
        .position
        .map_or_else(Position::default, |(line, column)| {
            lsp_position(text, line, column)
        });
    let mut message = error.message;
    if let Some(help) = error.help {
        message.push('\n');
        message.push_str(&help);
    }
    vec![Diagnostic {
        range: Range { start, end: start },
        severity: Some(DiagnosticSeverity::ERROR),
        source: Some("pm".to_owned()),
        message,
        ..Diagnostic::default()
    }]
}

/// An LSP position, which counts UTF-16 units, for a 1-based line and character column.
fn lsp_position(text: &str, line: usize, column: usize) -> Position {
    let line_text = text.lines().nth(line.saturating_sub(1)).unwrap_or_default();
    let character = line_text
        .chars()
        .take(column.saturating_sub(1))
        .map(char::len_utf16)
        .sum::<usize>();
    Position {
        line: u32::try_from(line.saturating_sub(1)).unwrap_or(u32::MAX),
        character: u32::try_from(character).unwrap_or(u32::MAX),
    }
}

/// The documentation of the builtin or plugin function under `position`, if there is
/// one.
fn hover(text: &str, position: Position, plugins: &Registry) -> Option<Hover> {
    let line = text.lines().nth(usize::try_from(position.line).ok()?)?;
    // Walk to the UTF-16 offset, then widen to the identifier around it, taking in a
    // `plugin::` path in front of it.
    let mut units = 0;
    let at = line
        .char_indices()
        .find(|(_, c)| {
            units += c.len_utf16();
            units > position.character as usize
        })
        .map_or(line.len(), |(offset, _)| offset);
    let is_ident = |c: char| c.is_alphanumeric() || c == '_' || c == ':';
    let start = line[..at]
        .rfind(|c: char| !is_ident(c))
        .map_or(0, |offset| offset + 1);
    let end = line[at..]
        .find(|c: char| !is_ident(c))
        .map_or(line.len(), |offset| at + offset);
    let word = line[start..end].trim_matches(':');
    let (signature, doc) = match word.split_once("::") {
        Some(_) => plugin_items(plugins)
            .into_iter()
            .find(|item| item.label == word)
            .map(|item| (item.signature, item.doc))?,
        None => recipe::BUILTINS
            .iter()
            .find(|builtin| builtin.name == word)
            .map(|builtin| (builtin.signature.to_owned(), builtin.doc.to_owned()))?,
    };
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: format!("```rhai\n{signature}\n```\n\n{doc}"),
        }),
        range: None,
    })
}

/// One thing a plugin adds to recipes, as completion and hover describe it.
struct PluginItem {
    label: String,
    signature: String,
    doc: String,
    constant: bool,
}

/// Every recipe function and symbol constant the plugins add.
fn plugin_items(plugins: &Registry) -> Vec<PluginItem> {
    let mut items = Vec::new();
    for module in plugins.recipe_modules() {
        let namespace = module.namespace();
        for function in module.functions() {
            items.push(PluginItem {
                label: format!("{namespace}::{}", function.name),
                signature: format!(
                    "{namespace}::{}({}) -> {}",
                    function.name,
                    function.params.join(", "),
                    function.returns.label()
                ),
                doc: function.doc.clone(),
                constant: false,
            });
        }
        for symbol in module.symbols() {
            let name = symbol.name.replace('-', "_");
            items.push(PluginItem {
                label: format!("{namespace}::{name}"),
                signature: format!("const {namespace}::{name} = {:?}", symbol.value),
                doc: symbol.summary.clone(),
                constant: true,
            });
        }
    }
    items
}

fn completions(plugins: &Registry) -> Vec<CompletionItem> {
    let markdown = |value: String| {
        Some(lsp_types::Documentation::MarkupContent(MarkupContent {
            kind: MarkupKind::Markdown,
            value,
        }))
    };
    let builtins = recipe::BUILTINS.iter().map(|builtin| CompletionItem {
        label: builtin.name.to_owned(),
        kind: Some(if recipe::STAGES.contains(&builtin.name) {
            CompletionItemKind::CONSTANT
        } else if !builtin.signature.starts_with(builtin.name) {
            // `step.push(command)`: called on a value.
            CompletionItemKind::METHOD
        } else {
            CompletionItemKind::FUNCTION
        }),
        detail: Some(builtin.signature.to_owned()),
        documentation: markdown(builtin.doc.to_owned()),
        ..CompletionItem::default()
    });
    let from_plugins = plugin_items(plugins)
        .into_iter()
        .map(|item| CompletionItem {
            label: item.label,
            kind: Some(if item.constant {
                CompletionItemKind::CONSTANT
            } else {
                CompletionItemKind::FUNCTION
            }),
            detail: Some(item.signature),
            documentation: markdown(item.doc),
            ..CompletionItem::default()
        });
    builtins.chain(from_plugins).collect()
}
