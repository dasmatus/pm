//! Packages that ship their own kernel.
//!
//! The default tests need no QEMU and no kernel: the build tests check what a
//! `kernel(...)` declaration puts in the archive, and the run tests hand
//! `PackageRunner` a stand-in QEMU that records how it was invoked, keeps the
//! initramfs and answers with a made-up exit status. That covers everything pm
//! does on the host side of the boot.
//!
//! The guest side - pm as init, inside a real kernel - needs a real QEMU and a real
//! kernel image, so it is `#[ignore]`d:
//!
//! ```sh
//! PM_TEST_KERNEL=/boot/vmlinuz-$(uname -r) cargo test --test vm -- --ignored
//! ```
//!
//! That also boots the probe through the `libvirt` plugin, which needs `virsh` and a
//! libvirt daemon that lets this user start a QEMU domain at libvirt's default URI
//! (`LIBVIRT_DEFAULT_URI` picks another).

use std::fs::{create_dir_all, read, read_to_string, set_permissions, write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use pm::bf::{BuildFile, BuildOptions};
use pm::context::BuildContext;
use pm::metadata::{Metadata, Type};
use pm::perms::{Enforcement, Permissions};
use pm::plugin::Loader;
use pm::progress::Progress;
use pm::run::PackageRunner;
use pm::vm::{Kernel, Launch, LaunchFile, Launcher, Machine};
use serde_yaml::{from_str, to_string};
use tempfile::{TempDir, tempdir};

/// The smallest file [`pm::vm::ImageFormat`] takes for an x86 `bzImage`.
fn fake_bzimage(path: &Path) {
    let mut bytes = vec![0u8; 0x400];
    bytes[0x202..0x206].copy_from_slice(b"HdrS");
    write(path, bytes).expect("write the fake kernel");
}

/// Build a Rhai recipe whose install step runs `script`, unsandboxed.
fn build(work: &Path, kernel: &str, script: &str) -> miette::Result<PathBuf> {
    let script_path = work.join("stage.sh");
    write(&script_path, script).expect("write the staging script");
    let recipe = work.join("build.rhai");
    write(
        &recipe,
        format!(
            "package(#{{\n    name: \"kernelled\",\n    version: \"0.1.0\",\n    steps: [\n        \
             step(Install, \"stage\", [\"/bin/sh {}\"]),\n    ],\n    kernel: {kernel},\n}});\n",
            script_path.display()
        ),
    )
    .expect("write the recipe");
    let build = BuildFile::load_unverified(&recipe)?;
    build.run_with_progress_in(
        &BuildContext::from_env()?.with_output_dir(work.to_path_buf()),
        BuildOptions {
            unsandboxed: true,
            ..BuildOptions::default()
        },
        &Progress::disabled(),
    )
}

/// Every message in `report`'s chain on one line, so a test can match a phrase
/// the terminal renderer would have wrapped.
fn chain(report: &miette::Report) -> String {
    report
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn extract(archive: &Path) -> TempDir {
    let dest = tempdir().expect("extraction directory");
    let status = Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest.path())
        .status()
        .expect("run tar");
    assert!(status.success());
    dest
}

fn stage_script(work: &Path) -> String {
    let image = work.join("vmlinuz");
    fake_bzimage(&image);
    format!(
        "set -eu\n\
         install -Dm755 {} \"$DESTDIR/boot/vmlinuz\"\n\
         mkdir -p \"$DESTDIR/usr/bin\"\n\
         printf '#!/bin/sh\\nexit 0\\n' > \"$DESTDIR/usr/bin/hello\"\n\
         chmod 755 \"$DESTDIR/usr/bin/hello\"\n",
        image.display()
    )
}

#[test]
fn a_declared_kernel_is_recorded_and_is_not_an_entrypoint() {
    let work = tempdir().unwrap();
    let script = stage_script(work.path());
    let archive = build(
        work.path(),
        "kernel(\"boot/vmlinuz\", \"mitigations=off\")",
        &script,
    )
    .expect("the build must succeed");

    let dest = extract(&archive);
    let metadata: Metadata =
        from_str(&read_to_string(dest.path().join("metadata")).unwrap()).unwrap();
    assert_eq!(
        metadata.kernel(),
        Some(&Kernel {
            image: PathBuf::from("boot/vmlinuz"),
            cmdline: Some("mitigations=off".into()),
        })
    );
    // Installed 0755, and still not offered as a program.
    let entrypoints: Vec<_> = metadata.entrypoints().map(|(path, _)| path).collect();
    assert_eq!(entrypoints, [Path::new("usr/bin/hello")]);
    assert!(dest.path().join("boot/vmlinuz").is_file());
}

#[test]
fn the_file_a_kernel_symlink_points_at_is_not_an_entrypoint_either() {
    let work = tempdir().unwrap();
    let image = work.path().join("vmlinuz");
    fake_bzimage(&image);
    let script = format!(
        "set -eu\n\
         install -Dm755 {} \"$DESTDIR/boot/vmlinuz-6.8\"\n\
         ln -s vmlinuz-6.8 \"$DESTDIR/boot/vmlinuz\"\n\
         mkdir -p \"$DESTDIR/usr/bin\"\n\
         printf '#!/bin/sh\\nexit 0\\n' > \"$DESTDIR/usr/bin/hello\"\n\
         chmod 755 \"$DESTDIR/usr/bin/hello\"\n",
        image.display()
    );
    let archive =
        build(work.path(), "kernel(\"boot/vmlinuz\")", &script).expect("the build must succeed");
    let dest = extract(&archive);
    let metadata: Metadata =
        from_str(&read_to_string(dest.path().join("metadata")).unwrap()).unwrap();
    let entrypoints: Vec<_> = metadata.entrypoints().map(|(path, _)| path).collect();
    assert_eq!(entrypoints, [Path::new("usr/bin/hello")]);
}

#[test]
fn a_kernel_the_steps_never_installed_fails_the_build() {
    let work = tempdir().unwrap();
    let error = build(
        work.path(),
        "kernel(\"boot/vmlinuz\")",
        "mkdir -p \"$DESTDIR/boot\"\n",
    )
    .expect_err("a missing kernel must fail the build");
    assert!(
        chain(&error).contains("did not install it"),
        "{}",
        chain(&error)
    );
}

#[test]
fn a_file_that_is_not_a_kernel_fails_the_build() {
    let work = tempdir().unwrap();
    let error = build(
        work.path(),
        "kernel(\"boot/vmlinuz\")",
        "mkdir -p \"$DESTDIR/boot\"\necho not a kernel > \"$DESTDIR/boot/vmlinuz\"\n",
    )
    .expect_err("a non-kernel must fail the build");
    assert!(
        chain(&error).contains("not a Linux kernel image"),
        "{}",
        chain(&error)
    );
}

#[test]
fn a_kernel_outside_destdir_is_refused() {
    let work = tempdir().unwrap();
    let error = build(work.path(), "kernel(\"/boot/vmlinuz\")", "true\n")
        .expect_err("an absolute kernel path must fail the build");
    assert!(
        chain(&error).contains("package-relative"),
        "{}",
        chain(&error)
    );
}

#[test]
fn a_package_without_a_kernel_records_none() {
    let work = tempdir().unwrap();
    let script = "mkdir -p \"$DESTDIR/usr/bin\"\nprintf '#!/bin/sh\\n' > \"$DESTDIR/usr/bin/x\"\n";
    let archive = build(work.path(), "()", script).expect("the build must succeed");
    let dest = extract(&archive);
    let text = read_to_string(dest.path().join("metadata")).unwrap();
    assert!(!text.contains("\nkernel:"), "{text}");
    let metadata: Metadata = from_str(&text).unwrap();
    assert_eq!(metadata.kernel(), None);
}

/// A package with a kernel and one script entrypoint, written directly rather
/// than built, so the run tests need no build.
fn kernelled_package(work: &Path, kernel: Kernel) -> PathBuf {
    let root = work.join("root");
    create_dir_all(root.join("usr/bin")).unwrap();
    create_dir_all(root.join("boot")).unwrap();
    fake_bzimage(&root.join("boot/vmlinuz"));
    write(root.join("usr/bin/hello"), "#!/bin/sh\nexit 0\n").unwrap();
    set_permissions(
        root.join("usr/bin/hello"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let metadata = Metadata::create(
        "kernelled".into(),
        vec!["0".into(), "1".into()],
        Vec::new(),
        [(PathBuf::from("usr/bin/hello"), Type::Binary)]
            .into_iter()
            .collect(),
        Permissions::default(),
        Enforcement::Audit,
    )
    .with_kernel(kernel);
    write(root.join("metadata"), to_string(&metadata).unwrap()).unwrap();
    let archive = work.join("kernelled.cpkg");
    let status = Command::new("tar")
        .arg("-cJf")
        .arg(&archive)
        .arg("-C")
        .arg(&root)
        .arg(".")
        .status()
        .unwrap();
    assert!(status.success());
    archive
}

/// A stand-in for `qemu-system-x86_64` that writes its arguments to
/// `<out>/args`, keeps the initramfs as `<out>/initrd`, and reports `exit 7` on
/// the status socket the way pm's init would.
fn fake_qemu(out: &Path) -> PathBuf {
    let script = out.join("qemu");
    write(
        &script,
        format!(
            r#"#!/usr/bin/env python3
import shutil, socket, sys
out = {out:?}
args = sys.argv[1:]
with open(out + "/args", "w") as f:
    f.write("".join(a + "\n" for a in args))
for flag, value in zip(args, args[1:]):
    if flag == "-initrd":
        shutil.copy(value, out + "/initrd")
    if flag == "-chardev":
        options = dict(o.split("=", 1) for o in value.replace(",,", "\0").split(",")[1:])
        status = socket.socket(socket.AF_UNIX)
        status.connect(options["path"].replace("\0", ","))
        status.sendall(b"exit 7\r\n")
        status.close()
"#,
            out = out.display().to_string()
        ),
    )
    .unwrap();
    set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

/// The member names of a `newc` archive, in order.
fn cpio_names(bytes: &[u8]) -> Vec<String> {
    let field = |at: usize, index: usize| {
        let text =
            std::str::from_utf8(&bytes[at + 6 + index * 8..at + 6 + (index + 1) * 8]).unwrap();
        usize::from_str_radix(text, 16).unwrap()
    };
    let pad = |n: usize| (n + 3) & !3;
    let mut names = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        assert_eq!(&bytes[at..at + 6], b"070701", "bad magic at {at}");
        let size = field(at, 6);
        let name_size = field(at, 11);
        let name = String::from_utf8(bytes[at + 110..at + 110 + name_size - 1].to_vec()).unwrap();
        if name == "TRAILER!!!" {
            break;
        }
        names.push(name);
        at = pad(at + 110 + name_size);
        at = pad(at + size);
    }
    names
}

/// The guest's init when no guest runs.
///
/// Nothing executes it in these tests, so any small host ELF stands in for it: an
/// unoptimised `pm-vm-init` carries hundreds of megabytes of debug info, and every
/// test would copy it into an initramfs twice.
fn stand_in_init() -> PathBuf {
    ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("a `true` binary to stand in for init")
}

/// A runner that boots with the stand-in QEMU.
fn runner(archive: PathBuf, qemu: PathBuf) -> PackageRunner {
    let mut runner = PackageRunner::new(archive);
    runner
        .allow_unsigned(true)
        .qemu(qemu)
        .guest_init(stand_in_init());
    runner
}

#[test]
fn a_kernelled_package_boots_its_kernel_with_an_initramfs_of_itself() {
    let work = tempdir().unwrap();
    let archive = kernelled_package(
        work.path(),
        Kernel {
            image: PathBuf::from("boot/vmlinuz"),
            cmdline: Some("mitigations=off".into()),
        },
    );
    let qemu = fake_qemu(work.path());

    let status = runner(archive, qemu)
        .run(Some("hello".into()))
        .expect("the run must succeed");
    assert_eq!(
        (status.code, status.exit_code),
        (7, Some(7)),
        "{}",
        status.reason
    );

    let args = read_to_string(work.path().join("args")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    let after = |flag: &str| {
        args[args
            .iter()
            .position(|arg| *arg == flag)
            .unwrap_or_else(|| panic!("no {flag}: {args:?}"))
            + 1]
    };
    assert!(after("-kernel").ends_with("boot/vmlinuz"), "{args:?}");
    // The package's parameters go before the ones pm relies on, so a repeated
    // parameter cannot override them.
    let append = after("-append");
    assert!(append.contains("mitigations=off console=ttyS0"), "{append}");
    assert!(append.ends_with("rdinit=/init -- __pm-vm-init"), "{append}");
    assert_eq!(after("-nic"), "none");

    let names = cpio_names(&read(work.path().join("initrd")).unwrap());
    for wanted in [
        "init",
        "pm-vm.json",
        "dev/console",
        "dev/ttyS1",
        "pkg/usr/bin/hello",
        "pkg/metadata",
        "bin/sh",
    ] {
        assert!(
            names.iter().any(|name| name == wanted),
            "{wanted} missing from {names:?}"
        );
    }
    assert!(
        !names.iter().any(|name| name == "pkg/boot/vmlinuz"),
        "the kernel image has no business inside its own initramfs"
    );
    let directories = names.iter().position(|name| name == "pkg").unwrap();
    let file = names
        .iter()
        .position(|name| name == "pkg/usr/bin/hello")
        .unwrap();
    assert!(
        directories < file,
        "a directory must come before what is in it"
    );
}

#[test]
fn network_and_audit_are_refused_for_a_kernelled_package() {
    let work = tempdir().unwrap();
    let archive = kernelled_package(
        work.path(),
        Kernel {
            image: PathBuf::from("boot/vmlinuz"),
            cmdline: None,
        },
    );
    let qemu = fake_qemu(work.path());

    let mut networked = runner(archive.clone(), qemu.clone());
    networked.allow_network(true);
    let error = networked.run(Some("hello".into())).unwrap_err();
    assert!(
        chain(&error).contains("no network device"),
        "{}",
        chain(&error)
    );

    let mut audited = runner(archive, qemu);
    audited.audit(true);
    let error = audited.run(Some("hello".into())).unwrap_err();
    assert!(chain(&error).contains("--audit"), "{}", chain(&error));
    assert!(
        !work.path().join("args").exists(),
        "QEMU must not have started"
    );
}

#[test]
fn a_kernel_path_in_the_metadata_that_escapes_the_package_is_refused() {
    let work = tempdir().unwrap();
    let archive = kernelled_package(
        work.path(),
        Kernel {
            image: PathBuf::from("../../../boot/vmlinuz"),
            cmdline: None,
        },
    );
    let qemu = fake_qemu(work.path());
    let error = runner(archive, qemu).run(Some("hello".into())).unwrap_err();
    assert!(
        chain(&error).contains("package-relative"),
        "{}",
        chain(&error)
    );
    assert!(
        !work.path().join("args").exists(),
        "QEMU must not have started"
    );
}

#[test]
fn a_cmdline_in_the_metadata_that_picks_init_is_refused() {
    let work = tempdir().unwrap();
    let archive = kernelled_package(
        work.path(),
        Kernel {
            image: PathBuf::from("boot/vmlinuz"),
            cmdline: Some("rdinit=/pkg/usr/bin/hello".into()),
        },
    );
    let qemu = fake_qemu(work.path());
    let error = runner(archive, qemu).run(Some("hello".into())).unwrap_err();
    assert!(chain(&error).contains("rdinit"), "{}", chain(&error));
    assert!(
        !work.path().join("args").exists(),
        "QEMU must not have started"
    );
}

/// A launcher that checks the machine pm laid out, then has pm run `program` with
/// `args` and write `files`. Whatever the launcher saw is written to `<out>/machine`.
struct TestLauncher {
    out: PathBuf,
    program: PathBuf,
    files: Vec<LaunchFile>,
}

impl Launcher for TestLauncher {
    fn launch(&self, machine: &Machine<'_>) -> miette::Result<Option<Launch>> {
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(machine.directory),
            0o711,
            "a launcher's program may run QEMU as another user, who has to reach the files"
        );
        assert_eq!(mode(machine.kernel), 0o600);
        assert_eq!(mode(machine.initramfs), 0o600);
        assert!(machine.kernel.starts_with(machine.directory));
        assert!(machine.name.starts_with("pm-"), "{}", machine.name);
        assert_eq!(machine.title, "pm run: usr/bin/hello");
        assert!(
            machine.cmdline.contains("console=ttyS0"),
            "{}",
            machine.cmdline
        );
        write(
            self.out.join("machine"),
            format!("{}\n", machine.directory.display()),
        )
        .unwrap();
        Ok(Some(Launch {
            by: "test".into(),
            program: self.program.clone(),
            args: vec![
                self.out.display().to_string(),
                machine.status_socket.display().to_string(),
            ],
            files: self.files.clone(),
        }))
    }
}

/// A stand-in for a launcher's program, run with `<out> <status socket>`: it
/// records its directory and whether it has a terminal, copies `domain.xml`, and
/// reports `exit 9` the way pm's init would, unless `report` is false, in which case
/// it exits 3 without reporting.
fn fake_launcher_program(out: &Path, report: bool) -> PathBuf {
    let script = out.join("launch");
    write(
        &script,
        format!(
            r#"#!/usr/bin/env python3
import os, shutil, socket, sys
out, status = sys.argv[1], sys.argv[2]
with open(out + "/cwd", "w") as f:
    f.write(os.getcwd() + "\n")
with open(out + "/tty", "w") as f:
    f.write(str(os.isatty(0) and os.isatty(1)))
if os.path.exists("domain.xml"):
    shutil.copy("domain.xml", out + "/domain.xml")
print("hello from the console")
if {report}:
    report = socket.socket(socket.AF_UNIX)
    report.connect(status)
    report.sendall(b"exit 9\r\n")
    report.close()
else:
    sys.exit(3)
"#,
            report = if report { "True" } else { "False" }
        ),
    )
    .unwrap();
    set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

/// A runner with no QEMU of its own, so the launcher is asked.
fn launched(archive: PathBuf, launcher: impl Launcher + 'static) -> PackageRunner {
    let mut runner = PackageRunner::new(archive);
    runner
        .allow_unsigned(true)
        .guest_init(stand_in_init())
        .launcher(Box::new(launcher));
    runner
}

#[test]
fn a_launcher_starts_the_machine_and_the_guests_report_is_the_exit_status() {
    let work = tempdir().unwrap();
    let archive = kernelled_package(
        work.path(),
        Kernel {
            image: PathBuf::from("boot/vmlinuz"),
            cmdline: None,
        },
    );
    let program = fake_launcher_program(work.path(), true);
    let launcher = TestLauncher {
        out: work.path().to_path_buf(),
        program,
        files: vec![LaunchFile {
            name: "domain.xml".into(),
            contents: b"<domain/>".to_vec(),
        }],
    };
    let status = launched(archive, launcher)
        .run(Some("hello".into()))
        .expect("the launcher must run");
    assert_eq!(status.code, 9, "{}", status.reason);

    let machine = read_to_string(work.path().join("machine")).unwrap();
    assert_eq!(
        read_to_string(work.path().join("cwd")).unwrap(),
        machine,
        "the program runs in the machine's directory"
    );
    assert_eq!(
        read_to_string(work.path().join("tty")).unwrap(),
        "True",
        "the program owns a terminal even when pm has none"
    );
    assert_eq!(read(work.path().join("domain.xml")).unwrap(), b"<domain/>");
}

#[test]
fn a_launcher_that_exits_before_the_guest_reports_fails_the_run() {
    let work = tempdir().unwrap();
    let archive = kernelled_package(
        work.path(),
        Kernel {
            image: PathBuf::from("boot/vmlinuz"),
            cmdline: None,
        },
    );
    let program = fake_launcher_program(work.path(), false);
    let launcher = TestLauncher {
        out: work.path().to_path_buf(),
        program,
        files: Vec::new(),
    };
    let error = launched(archive, launcher)
        .run(Some("hello".into()))
        .unwrap_err();
    assert!(
        chain(&error).contains("before the guest reported anything"),
        "{}",
        chain(&error)
    );
}

#[test]
fn a_launcher_cannot_write_outside_the_machine_or_over_its_files() {
    for name in ["../escape", "kernel", ".hidden", ""] {
        let work = tempdir().unwrap();
        let archive = kernelled_package(
            work.path(),
            Kernel {
                image: PathBuf::from("boot/vmlinuz"),
                cmdline: None,
            },
        );
        let program = fake_launcher_program(work.path(), true);
        let launcher = TestLauncher {
            out: work.path().to_path_buf(),
            program,
            files: vec![LaunchFile {
                name: name.into(),
                contents: b"x".to_vec(),
            }],
        };
        let error = launched(archive, launcher)
            .run(Some("hello".into()))
            .unwrap_err();
        let message = chain(&error);
        assert!(
            message.contains("not a plain file name") || message.contains("cannot be replaced"),
            "{name:?}: {message}"
        );
        assert!(
            !work.path().join("cwd").exists(),
            "{name:?}: the program must not have started"
        );
    }
}

#[test]
fn a_launcher_that_fails_fails_the_boot_instead_of_starting_qemu() {
    struct Broken;
    impl Launcher for Broken {
        fn launch(&self, _machine: &Machine<'_>) -> miette::Result<Option<Launch>> {
            Err(miette::miette!("the hypervisor is not there"))
        }
    }
    let work = tempdir().unwrap();
    let archive = kernelled_package(
        work.path(),
        Kernel {
            image: PathBuf::from("boot/vmlinuz"),
            cmdline: None,
        },
    );
    let error = launched(archive, Broken)
        .run(Some("hello".into()))
        .unwrap_err();
    assert!(
        chain(&error).contains("the hypervisor is not there"),
        "{}",
        chain(&error)
    );
}

/// Boots a real kernel and runs a real program in it.
///
/// The probe exits 40, plus 1 if it can read a file from its own package and 2 if
/// it can read the host's `/etc/hostname`, which the guest must not have.
#[test]
#[ignore = "needs qemu-system-x86_64 and a kernel image in PM_TEST_KERNEL"]
fn a_real_kernel_runs_the_entrypoint_and_reports_its_exit() {
    boot_the_probe(None);
}

/// The same probe, started by the `libvirt` plugin through `virsh` instead of by pm.
#[test]
#[ignore = "needs virsh, a libvirt daemon with QEMU, and a kernel image in PM_TEST_KERNEL"]
fn a_real_kernel_runs_through_the_libvirt_plugin() {
    let plugins = tempdir().unwrap();
    std::fs::copy(
        Path::new(env!("PM_TEST_PLUGIN_DIR")).join("libvirt.wasm"),
        plugins.path().join("libvirt.wasm"),
    )
    .unwrap();
    let registry = Loader::new(plugins.path().to_path_buf())
        .allow_unsigned(true)
        .load()
        .expect("the libvirt plugin must load");
    boot_the_probe(Some(Box::new(registry)));
}

fn boot_the_probe(launcher: Option<Box<dyn Launcher>>) {
    let kernel = PathBuf::from(
        std::env::var_os("PM_TEST_KERNEL").expect("set PM_TEST_KERNEL to a kernel image"),
    );
    let work = tempdir().unwrap();
    let root = work.path().join("root");
    create_dir_all(root.join("usr/bin")).unwrap();
    create_dir_all(root.join("share")).unwrap();
    create_dir_all(root.join("boot")).unwrap();
    std::fs::copy(&kernel, root.join("boot/vmlinuz")).unwrap();
    write(root.join("share/canary"), "in the package\n").unwrap();
    let source = work.path().join("probe.c");
    write(
        &source,
        r#"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
static int readable(const char *path) {
    char buf[1];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, 1);
    close(fd);
    return n >= 0;
}
int main(void) {
    int code = 40;
    printf("hello from the guest\n");
    if (readable("/pkg/share/canary")) code |= 1;
    if (readable("/etc/hostname")) code |= 2;
    return code;
}
"#,
    )
    .unwrap();
    let compiled = Command::new("cc")
        .arg(&source)
        .arg("-o")
        .arg(root.join("usr/bin/probe"))
        .status()
        .unwrap();
    assert!(compiled.success());
    let metadata = Metadata::create(
        "probe".into(),
        vec!["0".into(), "1".into()],
        Vec::new(),
        [(PathBuf::from("usr/bin/probe"), Type::Binary)]
            .into_iter()
            .collect(),
        Permissions::default(),
        Enforcement::Audit,
    )
    .with_kernel(Kernel {
        image: PathBuf::from("boot/vmlinuz"),
        cmdline: None,
    });
    write(root.join("metadata"), to_string(&metadata).unwrap()).unwrap();
    let archive = work.path().join("probe.cpkg");
    assert!(
        Command::new("tar")
            .arg("-cJf")
            .arg(&archive)
            .arg("-C")
            .arg(&root)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );

    let mut runner = PackageRunner::new(archive);
    runner
        .allow_unsigned(true)
        .guest_init(PathBuf::from(env!("CARGO_BIN_EXE_pm-vm-init")));
    if let Some(launcher) = launcher {
        runner.launcher(launcher);
    }
    let status = runner.run(Some("probe".into())).expect("the VM must run");
    assert_eq!(status.code, 41, "{}", status.reason);
}
