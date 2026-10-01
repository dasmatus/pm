//! The POSIX userland: coreutils and their neighbours, the shells and the archivers.
//! The Bash grammar is `bash-source`.

use bundled::{Capability, Fingerprint, Table};

/// The fingerprints, in precedence order.
static FINGERPRINTS: Table = Table::new(&[
    Fingerprint {
        name: "coreutils",
        // Not literally GNU coreutils - `sed`, `awk`, `grep` and `patch` live
        // here too, because they need exactly the same thing from the jail:
        // the files in the workdir and the destdir, and nothing else.
        pattern: bundled::program!(
            r"install|cp|mv|rm|mkdir|rmdir|chmod|chown|ln|ls|cat|echo|printf|touch|true|false|test|pwd|env|mktemp|sed|awk|gawk|grep|find|xargs|sort|head|tail|cut|tr|sync|patch"
        ),
        capabilities: &[Capability::Coreutils],
    },
    Fingerprint {
        name: "shell",
        pattern: bundled::program!(r"sh|bash|dash|ash|zsh"),
        capabilities: &[Capability::Shell, Capability::Coreutils],
    },
    Fingerprint {
        name: "archive",
        pattern: bundled::program!(
            r"tar|unzip|zip|xz|unxz|gzip|gunzip|bzip2|bunzip2|zstd|unzstd|7z|cpio"
        ),
        capabilities: &[Capability::Archive, Capability::Coreutils],
    },
]);

bundled::plugin! {
    name: "posix",
    summary: "coreutils, sed, awk, grep, the shells and the archivers",
    commands: &FINGERPRINTS,
    sources: &bundled::NoSources,
}
