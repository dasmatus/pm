//! The bindings generated from `wit/plugin.wit`.
//!
//! The generated tree is rooted at `pm::plugin::*` - the WIT package name, which is
//! also the name of this crate - so it lives in a module of its own rather than at the
//! crate root, where `pm::plugin::types` (the guest's view) and `crate::plugin` (the
//! host's) would be two unrelated things spelled almost the same.
//!
//! Nothing here is written by hand and nothing here is public: [`super::convert`] turns
//! every generated value into the pm type it mirrors before it reaches the rest of the
//! crate, so the generated names stop at this module's boundary.

// The generated code is not ours to lint.
#![allow(clippy::all, clippy::pedantic, missing_docs, unreachable_pub)]

wasmtime::component::bindgen!({
    path: "wit",
    world: "plugin",
});

pub(super) use self::{
    Plugin as Bindings,
    pm::plugin::{
        host::{Host as LogHost, Level as WitLevel},
        types::{
            Capability as WitCapability, Grant as WitGrant, Hook as WitHook, Host as TypesHost,
            Manifest as WitManifest, Permission as WitPermission, SourceFile as WitSourceFile,
            Symbol as WitSymbol, Verdict as WitVerdict,
        },
    },
};
