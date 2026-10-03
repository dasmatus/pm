//! `pm-lsp`: a language server for pm recipes (`*.rhai`).
//!
//! Speaks LSP over stdio. On every change it evaluates the recipe exactly as
//! `pm build` would - hermetic, and under the same operation limits, so an
//! endless loop costs a moment and not the editor - and reports the first error
//! where it happened: a syntax error, an undeclared variable, a misspelt
//! builtin, a missing `package(...)`, or a package that is not a valid build
//! file. It also completes pm's builtins and documents them on hover.
//!
//! Deprecated Starlark `.package` files get a warning pointing at `pm migrate`,
//! plus any error evaluating them.

use std::collections::HashMap;

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
use pm::{recipe, star};

fn main() -> miette::Result<()> {
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
    serve(&connection)?;
    drop(connection);
    io_threads.join().into_diagnostic()
}

/// Answer requests until the client shuts the server down.
fn serve(connection: &Connection) -> miette::Result<()> {
    let mut documents = HashMap::<Uri, String>::new();
    for message in &connection.receiver {
        match message {
            Message::Request(request) => {
                if connection.handle_shutdown(&request).into_diagnostic()? {
                    return Ok(());
                }
                let response = respond(&documents, request);
                connection
                    .sender
                    .send(Message::Response(response))
                    .into_diagnostic()?;
            }
            Message::Notification(notification) => {
                if let Some((uri, text)) = update(&mut documents, notification) {
                    let diagnostics = text.as_deref().map(|text| check(&uri, text));
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
    documents: &mut HashMap<Uri, String>,
    notification: Notification,
) -> Option<(Uri, Option<String>)> {
    match notification.method.as_str() {
        DidOpenTextDocument::METHOD => {
            let params: DidOpenTextDocumentParams =
                notification.extract(DidOpenTextDocument::METHOD).ok()?;
            let document = params.text_document;
            documents.insert(document.uri.clone(), document.text.clone());
            Some((document.uri, Some(document.text)))
        }
        DidChangeTextDocument::METHOD => {
            let params: DidChangeTextDocumentParams =
                notification.extract(DidChangeTextDocument::METHOD).ok()?;
            // Full sync: the last change is the whole document.
            let text = params.content_changes.into_iter().last()?.text;
            let uri = params.text_document.uri;
            documents.insert(uri.clone(), text.clone());
            Some((uri, Some(text)))
        }
        DidCloseTextDocument::METHOD => {
            let params: DidCloseTextDocumentParams =
                notification.extract(DidCloseTextDocument::METHOD).ok()?;
            documents.remove(&params.text_document.uri);
            Some((params.text_document.uri, None))
        }
        _ => None,
    }
}

fn respond(documents: &HashMap<Uri, String>, request: Request) -> Response {
    let id = request.id.clone();
    match request.method.as_str() {
        HoverRequest::METHOD => {
            let hover = request
                .extract::<HoverParams>(HoverRequest::METHOD)
                .ok()
                .and_then(|(_, params)| {
                    let position = params.text_document_position_params;
                    let text = documents.get(&position.text_document.uri)?;
                    hover(text, position.position)
                });
            Response::new_ok(id, hover)
        }
        Completion::METHOD => Response::new_ok(id, completions()),
        _ => Response::new_err(
            id,
            lsp_server::ErrorCode::MethodNotFound as i32,
            format!("pm-lsp does not handle {}", request.method),
        ),
    }
}

/// Every problem with the document at `uri`.
fn check(uri: &Uri, text: &str) -> Vec<Diagnostic> {
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
    let Err(error) = recipe::evaluate(text) else {
        return Vec::new();
    };
    let start = error
        .position
        .map_or_else(Position::default, |(line, column)| {
            lsp_position(text, line, column)
        });
    let mut message = error.message;
    if let Some(help) = error.help {
        message.push_str("\n");
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

/// The documentation of the builtin under `position`, if there is one.
fn hover(text: &str, position: Position) -> Option<Hover> {
    let line = text.lines().nth(usize::try_from(position.line).ok()?)?;
    // Walk to the UTF-16 offset, then widen to the identifier around it.
    let mut units = 0;
    let at = line
        .char_indices()
        .find(|(_, c)| {
            units += c.len_utf16();
            units > position.character as usize
        })
        .map_or(line.len(), |(offset, _)| offset);
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let start = line[..at]
        .rfind(|c: char| !is_ident(c))
        .map_or(0, |offset| offset + 1);
    let end = line[at..]
        .find(|c: char| !is_ident(c))
        .map_or(line.len(), |offset| at + offset);
    let word = &line[start..end];
    let builtin = recipe::BUILTINS
        .iter()
        .find(|builtin| builtin.name == word)?;
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: format!("```rhai\n{}\n```\n\n{}", builtin.signature, builtin.doc),
        }),
        range: None,
    })
}

fn completions() -> Vec<CompletionItem> {
    recipe::BUILTINS
        .iter()
        .map(|builtin| CompletionItem {
            label: builtin.name.to_owned(),
            kind: Some(if recipe::STAGES.contains(&builtin.name) {
                CompletionItemKind::CONSTANT
            } else {
                CompletionItemKind::FUNCTION
            }),
            detail: Some(builtin.signature.to_owned()),
            documentation: Some(lsp_types::Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::Markdown,
                value: builtin.doc.to_owned(),
            })),
            ..CompletionItem::default()
        })
        .collect()
}
