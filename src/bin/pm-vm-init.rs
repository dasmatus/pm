//! The init of a package's virtual machine.
//!
//! `pm run` copies this binary into the initramfs it boots a package's own kernel
//! with, when it sits beside `pm`, because it is a small fraction of `pm`'s size and
//! every byte of init is a byte the guest has to unpack. `pm` itself can be init
//! too, and is when this binary is missing; see [`pm::vm::guest`].

use std::process::ExitCode;

fn main() -> ExitCode {
    if pm::vm::guest::is_guest_init() {
        pm::vm::guest::run();
    }
    eprintln!(
        "pm-vm-init only runs as PID 1 inside a package's virtual machine, which `pm run` \
         boots; it does nothing on its own"
    );
    ExitCode::FAILURE
}
