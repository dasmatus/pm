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

use std::fs::{create_dir_all, read, read_to_string, set_permissions, write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use pm::bf::{BuildFile, BuildOptions};
use pm::context::BuildContext;
use pm::metadata::{Metadata, Type};
use pm::perms::{Enforcement, Permissions};
use pm::progress::Progress;
use pm::run::PackageRunner;
use pm::vm::Kernel;
use serde_yaml::{from_str, to_string};
use tempfile::{TempDir, tempdir};

/// The smallest file [`pm::vm::ImageFormat`] takes for an x86 `bzImage`.
fn fake_bzimage(path: &Path) {
    let mut bytes = vec![0u8; 0x400];
    bytes[0x202..0x206].copy_from_slice(b"HdrS");
    write(path, bytes).expect("write the fake kernel");
}

/// Build a Starlark recipe whose install step runs `script`, unsandboxed.
fn build(work: &Path, kernel: &str, script: &str) -> miette::Result<PathBuf> {
    let script_path = work.join("stage.sh");
    write(&script_path, script).expect("write the staging script");
    let recipe = work.join("build.package");
    write(
        &recipe,
        format!(
            "package(\n    name = \"kernelled\",\n    version = \"0.1.0\",\n    steps = [\n        \
             step(Install, \"stage\", [\"/bin/sh {}\"]),\n    ],\n    kernel = {kernel},\n)\n",
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
        "kernel(image = \"boot/vmlinuz\", cmdline = \"mitigations=off\")",
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
fn a_kernel_the_steps_never_installed_fails_the_build() {
    let work = tempdir().unwrap();
    let error = build(
        work.path(),
        "kernel(image = \"boot/vmlinuz\")",
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
        "kernel(image = \"boot/vmlinuz\")",
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
    let error = build(work.path(), "kernel(image = \"/boot/vmlinuz\")", "true\n")
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
    let archive = build(work.path(), "None", script).expect("the build must succeed");
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
/// the status port the way pm's init would.
fn fake_qemu(out: &Path) -> PathBuf {
    let script = out.join("qemu");
    write(
        &script,
        format!(
            "#!/bin/sh\nset -eu\nout={}\nprintf '%s\\n' \"$@\" > \"$out/args\"\nprev=\nstatus=\n\
             for a in \"$@\"; do\n  if [ \"$prev\" = -initrd ]; then cp \"$a\" \"$out/initrd\"; fi\n  \
             case \"$a\" in file:*) status=\"${{a#file:}}\" ;; esac\n  prev=\"$a\"\ndone\n\
             printf 'exit 7\\r\\n' > \"$status\"\n",
            out.display()
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

/// A runner that boots with the stand-in QEMU.
///
/// Nothing executes the guest's init here, so any small host ELF stands in for
/// it: an unoptimised `pm-vm-init` carries hundreds of megabytes of debug info,
/// and every test would copy it into an initramfs twice.
fn runner(archive: PathBuf, qemu: PathBuf) -> PackageRunner {
    let init = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("a `true` binary to stand in for init");
    let mut runner = PackageRunner::new(archive);
    runner.allow_unsigned(true).qemu(qemu).guest_init(init);
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
    let append = after("-append");
    assert!(append.contains("rdinit=/init"), "{append}");
    assert!(
        append.contains("mitigations=off -- __pm-vm-init"),
        "{append}"
    );
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

/// Boots a real kernel and runs a real program in it.
///
/// The probe exits 40, plus 1 if it can read a file from its own package and 2 if
/// it can read the host's `/etc/hostname`, which the guest must not have.
#[test]
#[ignore = "needs qemu-system-x86_64 and a kernel image in PM_TEST_KERNEL"]
fn a_real_kernel_runs_the_entrypoint_and_reports_its_exit() {
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
    let status = runner.run(Some("probe".into())).expect("the VM must run");
    assert_eq!(status.code, 41, "{}", status.reason);
}
