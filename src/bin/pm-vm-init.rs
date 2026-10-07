//! The init of a package's virtual machine.
//!
//! `pm run` copies this binary into the initramfs it boots a package's own kernel
//! with, when it sits beside `pm`, because it is a small fraction of `pm`'s size and
//! every byte of init is a byte the guest has to unpack. `pm` itself can be init
//! too, and is when this binary is missing; see [`pm::vm::guest`].

fn main() -> miette::Result<()> {
    if pm::vm::guest::is_guest_init() {
        pm::vm::guest::run();
    }
    Err(miette::miette!(
        help = "`pm run` boots it as PID 1 inside a package's virtual machine",
        "pm-vm-init does nothing on its own"
    ))
}
