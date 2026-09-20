//! Individual build steps and the stages they belong to.

use std::{
    collections::HashMap,
    fs::create_dir_all,
    path::{Path, PathBuf},
};

use miette::miette;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use url::Url;

use crate::{download::Downloader, progress::Task, sandbox::BuildSandbox};

/// A single step of a build: an optional set of downloads followed by a list of
/// commands to run.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Step {
    /// Which stage of the build this step belongs to.
    pub stage: Stage,
    /// Files to fetch before running the commands, mapped to their expected SHA-256.
    pub dl_urls: Option<HashMap<Url, String>>,
    /// Human-readable name, used for logging and diagnostics only.
    pub name: String,
    /// Commands to run, in order.
    pub run: Vec<String>,
}

impl Step {
    /// Run this step: fetch its downloads on the host, then run its commands inside
    /// `sandbox`.
    ///
    /// `workdir` is the **host-side** working directory, and must be the same directory
    /// `sandbox` was built for: downloads land there directly, while commands see it
    /// through the sandbox at [`crate::sandbox::CONTAINER_WORKDIR`].
    ///
    /// # Downloads
    ///
    /// Downloads, if any, are fetched **in-process on the host**, in parallel, each into
    /// its own subdirectory of `workdir` so that two URLs sharing a basename cannot
    /// overwrite one another, and each one's SHA-256 is checked case-insensitively against
    /// the expected hash from the build file. They do not go through the sandbox because
    /// they are not child processes: [`Downloader`] fetches them from this process, so
    /// confining them would mean confining `pm` itself. Their *output* is nonetheless
    /// written where the confined commands will read it, which is the part that matters.
    ///
    /// # Command execution
    ///
    /// Every command in [`Step::run`] is handed to [`BuildSandbox::run`] **sequentially, in
    /// declaration order** - build commands are order dependent (`./configure`, then
    /// `make`, then `make install`), so they must never run concurrently.
    ///
    /// Each command string is split on whitespace and executed directly: the first word is
    /// the program, the rest are its arguments. No shell is involved, so quoting, globbing,
    /// pipes, redirection and variable expansion are **not** available and a command
    /// containing them will receive them as literal argument text.
    ///
    /// `DESTDIR` reaches the command through its environment, pointing at the staging
    /// directory the sandbox was built with. It is passed through the environment rather
    /// than substituted into the command because that is the Makefile convention: `make
    /// install` reads `DESTDIR` from the environment and the Makefile's own install rules
    /// expand `$(DESTDIR)$(PREFIX)/bin` themselves, redirecting the install into the
    /// staging tree without the build file having to name it. A step is therefore expected
    /// to be a build system invocation (`make install`, `ninja install`, `cargo install
    /// --root`), not a hand-written `cp` - a bare `cp foo $DESTDIR/bin/` will NOT work,
    /// because nothing expands `$DESTDIR`.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if `workdir` does not exist, if a download URL has no usable
    /// file name, if a download directory cannot be created, or if a download fails or its
    /// hash does not match. Command failures are reported by [`BuildSandbox::run`]: an
    /// empty or blank command, a program that cannot be found or is unreachable inside the
    /// jail, a program that cannot be spawned, or a non-zero exit - in which case the
    /// diagnostic carries the command, the exit status and the child's captured stderr.
    pub fn execute(&self, sandbox: &BuildSandbox, workdir: &Path) -> miette::Result<()> {
        info!(stage = ?self.stage, step = %self.name, "Running step");

        if !workdir.is_dir() {
            return Err(miette!(
                "Working directory `{}` for step `{}` does not exist",
                workdir.display(),
                self.name
            ));
        }

        self.download(sandbox.progress(), workdir)?;
        self.run_commands(sandbox)
    }

    /// Fetch every download of this step into `workdir` and verify its hash.
    ///
    /// Downloads are independent of one another, so unlike the commands they are safe to
    /// run in parallel. Each opens its own line under `progress`, which is what makes a
    /// step fetching four tarballs legible rather than four interleaved log streams.
    fn download(&self, progress: &Task, workdir: &Path) -> miette::Result<()> {
        let Some(dl_urls) = self.dl_urls.as_ref() else {
            return Ok(());
        };

        let downloader = Downloader::new();

        dl_urls
            .par_iter()
            .try_for_each(|(url, expected)| -> miette::Result<()> {
                let dest = Self::download_dest(workdir, url)?;
                let task = progress.child(Self::download_file_name(url)?);

                downloader
                    .fetch_verified(url, &dest, expected, |done, total| {
                        task.set_bytes(done, total);
                    })
                    .map_err(|report| {
                        report.wrap_err(format!("cannot fetch `{url}` for step `{}`", self.name))
                    })?;

                info!("{url} downloaded and verified.");
                Ok(())
            })
    }

    /// Derive the on-disk file name for a download from the URL's last non-empty path
    /// segment.
    ///
    /// [`Url::to_file_path`] cannot be used here: it only succeeds for `file://` URLs and
    /// returns `Err(())` for everything else, including the `https://` URLs build files
    /// actually contain.
    fn download_file_name(url: &Url) -> miette::Result<&str> {
        url.path_segments()
            .and_then(|mut segments| {
                segments.rfind(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
            })
            .ok_or_else(|| {
                miette!(
                    "Cannot derive a file name from the URL `{url}`: it has no usable path segment"
                )
            })
    }

    /// Build the on-disk destination for a download and create the directory holding it.
    ///
    /// Two URLs in the same step can easily end in the same basename
    /// (`https://a/v1/source.tar.gz` and `https://b/v2/source.tar.gz`), and since downloads
    /// run in parallel they would race on one path and clobber each other. Each download
    /// therefore gets its own subdirectory, named from a digest of the full URL, so the
    /// file keeps its natural basename without ever colliding.
    fn download_dest(workdir: &Path, url: &Url) -> miette::Result<PathBuf> {
        let relative = Self::download_path(url)?;
        let dest = workdir.join(&relative);
        let dir = dest.parent().ok_or_else(|| {
            miette!(
                "Cannot derive a download directory from destination `{}` for `{url}`",
                dest.display()
            )
        })?;
        create_dir_all(dir).map_err(|e| {
            miette!(
                "Failed to create download directory `{}` for `{url}`: {e}",
                dir.display()
            )
        })?;

        debug!(%url, dest = %dest.display(), "Download destination");
        Ok(dest)
    }

    /// The path of a verified download, relative to the build working directory.
    ///
    /// This is the same path used by [`Self::execute`], without downloading anything
    /// or creating directories. Recipe generators should query it rather than
    /// reproduce pm's URL hashing algorithm. Inside the build jail, join it onto
    /// [`crate::sandbox::CONTAINER_WORKDIR`]; for an unconfined build, join it onto
    /// that build's host working directory.
    ///
    /// # Errors
    ///
    /// Fails if the URL has no usable file name.
    pub fn download_path(url: &Url) -> miette::Result<PathBuf> {
        Ok(PathBuf::from(Self::url_digest(url)).join(Self::download_file_name(url)?))
    }

    /// A short, stable hex digest of a URL string.
    ///
    /// This is FNV-1a, written out inline: it only has to turn a URL into a deterministic
    /// directory name, so a non-cryptographic hash is enough and pulling in a dependency
    /// for it is not warranted. The SHA-256 [`Downloader`] computes is no use here - it
    /// covers the file's contents, and the file does not exist yet.
    fn url_digest(url: &Url) -> String {
        const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;

        let digest = url.as_str().bytes().fold(OFFSET_BASIS, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(PRIME)
        });
        format!("{digest:016x}")
    }

    /// Run every command of this step inside `sandbox`, in order.
    ///
    /// The sandbox owns everything about how a command runs - program resolution, the
    /// working directory, `DESTDIR`, the environment, whether there is a network - so
    /// there is nothing left to decide here but the order. Blank commands are rejected by
    /// [`BuildSandbox::run`], which is the single place that knows how a command string is
    /// split.
    fn run_commands(&self, sandbox: &BuildSandbox) -> miette::Result<()> {
        // Sequential on purpose. Build commands depend on the effects of the ones before
        // them, so running them through rayon would be a race, not a speed-up.
        self.run
            .iter()
            .try_for_each(|cmd| sandbox.run(cmd, &self.name))
    }
}

/// The stage of the build a [`Step`] belongs to.
///
/// The declaration order is the execution order, and the derived [`Ord`] follows it, so
/// sorting steps by stage yields a valid build sequence.
#[derive(
    Serialize, Deserialize, Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum Stage {
    /// Fetch and unpack sources, apply patches.
    #[default]
    Prepare,
    /// Compile.
    Build,
    /// Stage the built files under `DESTDIR`.
    Install,
    /// Run the package's test suite.
    Test,
}
