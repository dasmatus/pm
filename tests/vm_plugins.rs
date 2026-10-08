//! Plugins that start virtual machines: the `libvirt` plugin in `plugins/`, and what
//! pm refuses from a `vm-plugin` that misbehaves.
//!
//! These call the plugins the way a boot does, through [`Launcher`] on a
//! [`Registry`], with a machine whose paths need not exist: a plugin only describes
//! how to start it. `tests/vm.rs` runs what a launcher answers, and boots a real
//! kernel through the libvirt plugin when asked to.

use std::{
    collections::BTreeSet,
    fs::{copy, create_dir_all},
    path::{Path, PathBuf},
};

use pm::{
    plugin::{Loader, Registry},
    vm::{Launch, Launcher, Machine},
};
use tempfile::{TempDir, tempdir};

/// Where `build.rs` generated the test components.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("PM_TEST_PLUGIN_DIR")).join(format!("{name}.wasm"))
}

/// A registry of exactly `names`, loaded in that order.
fn registry(names: &[&str]) -> (TempDir, Registry) {
    let root = tempdir().expect("a temporary directory");
    let dir = root.path().join("plugins");
    create_dir_all(&dir).expect("create the plugin directory");
    for name in names {
        copy(fixture(name), dir.join(format!("{name}.wasm")))
            .unwrap_or_else(|error| panic!("stage the {name} fixture: {error}"));
    }
    let registry = Loader::new(dir)
        .allow_unsigned(true)
        .load()
        .expect("the plugins must load");
    (root, registry)
}

/// Ask `registry` to start a machine titled `title`, with or without KVM.
fn launch(registry: &Registry, title: &str, kvm: bool) -> miette::Result<Option<Launch>> {
    registry.launch(&Machine {
        name: "pm-vm-abc123",
        title,
        directory: Path::new("/tmp/pm-vm-abc123"),
        kernel: Path::new("/tmp/pm-vm-abc123/kernel"),
        initramfs: Path::new("/tmp/pm-vm-abc123/initramfs"),
        cmdline: "quiet console=ttyS0 panic=-1 rdinit=/init -- pm-vm-init",
        memory_mib: 512,
        cpus: 2,
        kvm,
        status_socket: Path::new("/tmp/pm-vm-abc123/status.sock"),
    })
}

/// Every message in `report`'s chain, unwrapped.
fn chain(report: &miette::Report) -> String {
    report
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

/// The domain definition the libvirt plugin wrote for `launch`.
fn domain(launch: &Launch) -> String {
    let [file] = launch.files.as_slice() else {
        panic!("one file, the domain: {:?}", launch.files);
    };
    assert_eq!(file.name, "domain.xml");
    String::from_utf8(file.contents.clone()).expect("the domain is text")
}

#[test]
fn the_libvirt_plugin_may_only_ever_run_virsh() {
    let (_root, registry) = registry(&["libvirt"]);
    let [plugin] = registry.plugins() else {
        panic!("one plugin");
    };
    let manifest = plugin.manifest();
    assert_eq!(manifest.name, "libvirt");
    assert_eq!(manifest.launchers, BTreeSet::from(["virsh".to_owned()]));
    assert!(
        manifest.hooks.is_empty(),
        "it neither classifies commands nor scans sources"
    );
}

#[test]
fn the_libvirt_plugin_starts_a_transient_domain_attached_to_its_console() {
    let (_root, registry) = registry(&["libvirt"]);
    let launch = launch(&registry, "pm run: usr/bin/hello", true)
        .expect("libvirt must answer")
        .expect("libvirt must launch the machine");
    assert_eq!(launch.by, "libvirt");
    assert_eq!(launch.program, Path::new("virsh"));
    assert_eq!(
        launch.args,
        [
            "-q",
            "create",
            "--console",
            "--autodestroy",
            "/tmp/pm-vm-abc123/domain.xml"
        ],
        "no -c: virsh connects wherever LIBVIRT_DEFAULT_URI and libvirt's defaults say"
    );

    let xml = domain(&launch);
    for expected in [
        "<domain type='kvm'>",
        "<name>pm-vm-abc123</name>",
        "<title>pm run: usr/bin/hello</title>",
        "<memory unit='MiB'>512</memory>",
        "<vcpu>2</vcpu>",
        "<kernel>/tmp/pm-vm-abc123/kernel</kernel>",
        "<initrd>/tmp/pm-vm-abc123/initramfs</initrd>",
        "<cmdline>quiet console=ttyS0 panic=-1 rdinit=/init -- pm-vm-init</cmdline>",
        "<cpu mode='host-passthrough'/>",
        "<acpi/>",
        "<on_poweroff>destroy</on_poweroff>",
        "<on_reboot>destroy</on_reboot>",
        "<serial type='pty'>",
        "<source mode='connect' path='/tmp/pm-vm-abc123/status.sock'/>",
        "<controller type='usb' model='none'/>",
        "<memballoon model='none'/>",
    ] {
        assert!(xml.contains(expected), "{expected} is missing from\n{xml}");
    }
    assert!(
        !xml.contains("<interface") && !xml.contains("<disk"),
        "the guest gets no network and no disk:\n{xml}"
    );
    // An XML comment may not hold `--`, and libvirt refuses a domain that does.
    for comment in xml.split("<!--").skip(1) {
        let body = comment.split("-->").next().unwrap_or_default();
        assert!(!body.contains("--"), "a comment holds `--`: {body}");
    }
}

#[test]
fn without_kvm_the_libvirt_plugin_asks_for_an_emulated_machine() {
    let (_root, registry) = registry(&["libvirt"]);
    let launch = launch(&registry, "pm run: usr/bin/hello", false)
        .unwrap()
        .unwrap();
    let xml = domain(&launch);
    assert!(xml.contains("<domain type='qemu'>"), "{xml}");
    assert!(
        !xml.contains("host-passthrough"),
        "TCG has no host CPU to pass through:\n{xml}"
    );
}

#[test]
fn the_libvirt_plugin_escapes_what_a_package_names() {
    let (_root, registry) = registry(&["libvirt"]);
    let launch = launch(&registry, "pm run: usr/bin/<a href='x'>&\"", true)
        .unwrap()
        .unwrap();
    let xml = domain(&launch);
    assert!(
        xml.contains("<title>pm run: usr/bin/&lt;a href=&apos;x&apos;&gt;&amp;&quot;</title>"),
        "{xml}"
    );
}

#[test]
fn a_plugin_keeps_only_the_bare_program_names_it_lists() {
    let (_root, registry) = registry(&["launcher"]);
    let [plugin] = registry.plugins() else {
        panic!("one plugin");
    };
    assert_eq!(
        plugin.manifest().launchers,
        BTreeSet::from(["env".to_owned(), "true".to_owned()]),
        "a path is not a launcher: what runs is whatever PATH finds under the name"
    );
}

#[test]
fn a_listed_launcher_is_run_and_the_answer_names_its_plugin() {
    let (_root, registry) = registry(&["launcher"]);
    let launch = launch(&registry, "pm run: usr/bin/hello", false)
        .unwrap()
        .expect("the fixture launches this one");
    assert_eq!(launch.by, "launcher-fixture");
    assert_eq!(launch.program, Path::new("true"));
    assert_eq!(launch.args, ["/tmp/pm-vm-abc123"]);
    assert_eq!(launch.files[0].name, "note");
    assert_eq!(launch.files[0].contents, b"pm-vm-abc123");
}

#[test]
fn a_plugin_may_run_nothing_it_did_not_list() {
    let (_root, registry) = registry(&["launcher"]);
    for (title, expected) in [
        ("pm run: usr/bin/unlisted", "not among the launchers"),
        ("pm run: usr/bin/path", "not among the launchers"),
        ("pm run: usr/bin/nul", "NUL"),
    ] {
        let error = launch(&registry, title, false).unwrap_err();
        assert!(chain(&error).contains(expected), "{title}: {error:?}");
    }
}

#[test]
fn a_plugin_that_refuses_fails_the_boot_with_its_message() {
    let (_root, registry) = registry(&["launcher"]);
    let error = launch(&registry, "pm run: usr/bin/refuse", false).unwrap_err();
    let message = chain(&error);
    assert!(message.contains("this fixture refuses"), "{message}");
    assert!(message.contains("launcher-fixture"), "{message}");
}

#[test]
fn a_plugin_that_passes_leaves_the_machine_to_the_next_one() {
    let (_root, registry) = registry(&["launcher", "libvirt"]);
    let first = launch(&registry, "pm run: usr/bin/hello", false)
        .unwrap()
        .unwrap();
    assert_eq!(
        first.by, "launcher-fixture",
        "plugins are asked in load order"
    );
    let next = launch(&registry, "pm run: usr/bin/pass", false)
        .unwrap()
        .unwrap();
    assert_eq!(next.by, "libvirt");
}

#[test]
fn with_no_vm_plugin_pm_starts_qemu_itself() {
    let (_root, registry) = registry(&["systemd"]);
    assert_eq!(
        launch(&registry, "pm run: usr/bin/hello", false).unwrap(),
        None
    );
    assert_eq!(
        launch(Registry::none(), "pm run: usr/bin/hello", false).unwrap(),
        None
    );
}
