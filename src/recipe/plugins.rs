//! Plugins as Rhai packages.
//!
//! Every plugin that publishes symbols or recipe functions becomes a static module named
//! after it, with each `-` in the name written `_`:
//!
//! ```rhai
//! let unit = systemd::install_unit("foo.service");   // a recipe function
//! let dir = systemd::unitdir;                        // a symbol, as a constant
//! ```
//!
//! A recipe function's arguments are handed to the plugin as JSON (a `Step`, `Kernel` or
//! `Package` as the object map it stands for), and its answer comes back as the pm type
//! the plugin declared it returns, checked exactly as if the recipe had built it itself.
//! See [`crate::plugin::RecipeFunction`].

use rhai::{Dynamic, EvalAltResult, FnNamespace, FuncRegistration, Module, NativeCallContext};
use serde_json::Value as Json;

use super::{RhaiResult, types};
use crate::plugin::{RecipeFunction, RecipeModule};

/// The Rhai module for one plugin.
pub(super) fn module(plugin: &RecipeModule) -> Module {
    let mut module = Module::new();
    module.set_id(plugin.namespace());
    for symbol in plugin.symbols() {
        let name = symbol.name.replace('-', "_");
        if rhai::is_valid_identifier(&name) {
            module.set_var(name, symbol.value.clone());
        }
    }
    for function in plugin.functions() {
        register(&mut module, plugin, function);
    }
    module
}

/// Add one recipe function, at its declared arity.
///
/// Every parameter is `Dynamic`, so a call with the right number of arguments of any
/// types reaches the plugin, and the plugin decides what it accepts.
fn register(module: &mut Module, plugin: &RecipeModule, function: &RecipeFunction) {
    let mut params: Vec<String> = function.params.clone();
    params.push(function.returns.label().to_owned());
    let comments: String = function
        .doc
        .lines()
        .map(|line| format!("/// {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let registration = FuncRegistration::new(function.name.clone())
        .with_namespace(FnNamespace::Internal)
        // A call runs plugin code; keep it where the recipe wrote it rather than letting
        // the optimiser run it at compile time.
        .with_volatility(true)
        .with_params_info(params)
        .with_comments([comments]);
    let call = Call {
        plugin: plugin.clone(),
        function: function.clone(),
    };
    match function.params.len() {
        0 => {
            registration.set_into_module(module, move |context: NativeCallContext| {
                call.invoke(&context, Vec::new())
            });
        }
        1 => {
            registration.set_into_module(module, move |context: NativeCallContext, a: Dynamic| {
                call.invoke(&context, vec![a])
            });
        }
        2 => {
            registration.set_into_module(
                module,
                move |context: NativeCallContext, a: Dynamic, b: Dynamic| {
                    call.invoke(&context, vec![a, b])
                },
            );
        }
        3 => {
            registration.set_into_module(
                module,
                move |context: NativeCallContext, a: Dynamic, b: Dynamic, c: Dynamic| {
                    call.invoke(&context, vec![a, b, c])
                },
            );
        }
        4 => {
            registration.set_into_module(
                module,
                move |context: NativeCallContext,
                      a: Dynamic,
                      b: Dynamic,
                      c: Dynamic,
                      d: Dynamic| { call.invoke(&context, vec![a, b, c, d]) },
            );
        }
        5 => {
            registration.set_into_module(
                module,
                move |context: NativeCallContext,
                      a: Dynamic,
                      b: Dynamic,
                      c: Dynamic,
                      d: Dynamic,
                      e: Dynamic| { call.invoke(&context, vec![a, b, c, d, e]) },
            );
        }
        // `convert::recipe_functions` drops anything with more than
        // `RECIPE_PARAMS_MAX` (six) parameters.
        _ => {
            registration.set_into_module(
                module,
                move |context: NativeCallContext,
                      a: Dynamic,
                      b: Dynamic,
                      c: Dynamic,
                      d: Dynamic,
                      e: Dynamic,
                      f: Dynamic| { call.invoke(&context, vec![a, b, c, d, e, f]) },
            );
        }
    }
}

/// One recipe function, ready to be called from a recipe.
struct Call {
    plugin: RecipeModule,
    function: RecipeFunction,
}

impl Call {
    fn invoke(&self, context: &NativeCallContext, args: Vec<Dynamic>) -> RhaiResult<Dynamic> {
        let position = context.call_position();
        let qualified = format!("{}::{}", self.plugin.namespace(), self.function.name);
        let fail = |message: String| -> Box<EvalAltResult> {
            EvalAltResult::ErrorRuntime(message.into(), position).into()
        };
        let args = args
            .into_iter()
            .enumerate()
            .map(|(index, arg)| {
                let json: Json =
                    rhai::serde::from_dynamic(&types::plain(arg)).map_err(|error| {
                        fail(format!(
                            "{qualified}: argument {} cannot be passed to a plugin: {}",
                            index + 1,
                            error.unwrap_inner()
                        ))
                    })?;
                Ok(json.to_string())
            })
            .collect::<RhaiResult<Vec<String>>>()?;
        let answer = self
            .plugin
            .call(&self.function.name, &args)
            .map_err(|report| fail(report.to_string()))?;
        let answer: Json = serde_json::from_str(&answer)
            .map_err(|error| fail(format!("{qualified} answered with invalid JSON: {error}")))?;
        types::from_json(answer, self.function.returns).map_err(|error| {
            let message = match *error {
                EvalAltResult::ErrorRuntime(ref value, _) if value.is_string() => value.to_string(),
                ref other => other.to_string(),
            };
            fail(format!(
                "{qualified} answered with something unusable: {message}"
            ))
        })
    }
}
