//! The daemon side of `pm`.
//!
//! Today this holds exactly one thing: the worker process that runs one job
//! and holds its jail, in [`worker`]. Everything else in
//! `docs/superpowers/specs/2026-09-18-dbus-daemon-design.md` - the `pmd`
//! service that owns `org.pm1`, the supervisor thread, the job registry -
//! is a later task's work landing in this same module tree. There is no
//! `zbus` code reachable from here: see [`worker`]'s own docs for exactly
//! where the boundary sits and why.

/// `pmd --worker --fd N`: one process, one job, speaking a length-prefixed
/// frame protocol on its inherited socket.
pub mod worker;
