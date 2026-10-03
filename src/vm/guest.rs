//! The guest side of a VM run: pm itself, running as PID 1 inside the package's
//! own kernel.
//!
//! [`super::boot`] copies a pm binary - `pm-vm-init`, or `pm` itself when that is
//! missing - into the initramfs as `/init` and puts [`INIT_ARG`] after the `--` of
//! the kernel command line, which the kernel hands to init as an argument. Both
//! binaries check for that first thing in `main` with [`is_guest_init`] and, when
//! it holds, call [`run`] instead of doing anything else.
//!
//! Init's whole job is small: mount the pseudo-filesystems a program expects, run
//! the entrypoint named in [`super::GUEST_CONFIG`], reap everything until it
//! exits, report how it exited on the second serial port, and power the machine
//! off. The first serial port is the console, which is the entrypoint's stdin,
//! stdout and stderr; keeping the report off it means nothing the program prints
//! can be mistaken for its exit status.

use std::{
    ffi::OsStr,
    fs::{OpenOptions, read_to_string},
    io::Write,
    process::Command,
};

use nix::{
    mount::{MsFlags, mount},
    sys::{
        reboot::{RebootMode, reboot},
        termios::tcdrain,
        wait::{WaitStatus, waitpid},
    },
    unistd::{Pid, sync},
};

use super::{GUEST_CONFIG, GuestConfig, STATUS_PORT};

/// The argument that tells a pm binary it is the guest's init.
pub const INIT_ARG: &str = "__pm-vm-init";

/// The environment the entrypoint starts with: the run jail's, give or take.
///
/// Init's own environment is not passed on. The kernel turns every command-line
/// parameter it does not recognise into an environment variable for init, so it
/// holds whatever the package's command line said.
const ENVIRONMENT: [(&str, &str); 4] = [
    ("PATH", super::GUEST_PATH),
    ("HOME", "/tmp"),
    ("TMPDIR", "/tmp"),
    ("LC_ALL", "C"),
];

/// Whether this process is the init of a pm guest.
///
/// Both halves are needed. PID 1 alone is any container's init, and the argument
/// alone is something anyone can type; only the kernel starts a process that is both.
/// The argument is looked for anywhere rather than in `argv[1]`, because the kernel
/// also passes init every command-line word it does not recognise, ahead of the
/// ones after `--`.
#[must_use]
pub fn is_guest_init() -> bool {
    std::process::id() == 1
        && std::env::args_os()
            .skip(1)
            .any(|arg| arg == OsStr::new(INIT_ARG))
}

/// Run the entrypoint, report its exit and power off. Never returns.
///
/// Failures are printed on the console, which is the only place left to put them,
/// and reported on the status port, so the host says why the run failed instead
/// of only that it did.
pub fn run() -> ! {
    let report = match supervise() {
        Ok(report) => report,
        Err(message) => {
            eprintln!("pm guest init: {message}");
            format!("error {message}")
        }
    };
    if let Ok(mut port) = OpenOptions::new().write(true).open(STATUS_PORT) {
        let _ = writeln!(port, "{report}");
        let _ = tcdrain(&port);
    } else {
        eprintln!("pm guest init: cannot open {STATUS_PORT} to report `{report}`");
    }
    let _ = std::io::stdout().flush();
    let _ = tcdrain(std::io::stdout());
    sync();
    // Powering off ends QEMU. Should it fail, returning from init panics the
    // kernel, and `panic=-1` with `-no-reboot` ends QEMU just the same.
    let _ = reboot(RebootMode::RB_POWER_OFF);
    std::process::exit(1);
}

/// Mount what a program expects, run the entrypoint and wait for it.
fn supervise() -> Result<String, String> {
    for (source, target, fstype) in [
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("tmpfs", "/tmp", "tmpfs"),
    ] {
        if let Err(error) = mount(
            Some(source),
            target,
            Some(fstype),
            MsFlags::empty(),
            None::<&str>,
        ) {
            eprintln!("pm guest init: cannot mount {fstype} on {target}: {error}");
        }
    }

    let text = read_to_string(GUEST_CONFIG)
        .map_err(|error| format!("cannot read {GUEST_CONFIG}: {error}"))?;
    let config: GuestConfig = serde_json::from_str(&text)
        .map_err(|error| format!("cannot parse {GUEST_CONFIG}: {error}"))?;

    let child = Command::new(&config.entrypoint)
        .current_dir(&config.cwd)
        .env_clear()
        .envs(ENVIRONMENT)
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", config.entrypoint.display()))?;
    let pid = Pid::from_raw(i32::try_from(child.id()).map_err(|error| error.to_string())?);

    // As PID 1, every orphan in the guest is ours to reap, so wait on anything and
    // stop only when it is the entrypoint that exited.
    loop {
        match waitpid(None, None) {
            Ok(WaitStatus::Exited(exited, code)) if exited == pid => {
                return Ok(format!("exit {code}"));
            }
            Ok(WaitStatus::Signaled(exited, signal, _)) if exited == pid => {
                return Ok(format!("signal {}", signal as i32));
            }
            Ok(_) => {}
            Err(error) => {
                // ECHILD would mean the entrypoint was reaped behind our back, which
                // nothing in the guest can do; say so rather than spin.
                return Err(format!("waiting for the entrypoint failed: {error}"));
            }
        }
    }
}
