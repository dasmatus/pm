//! Integration tests for [`pm::step::Step`]: command execution semantics,
//! stage ordering, and the environment the child process sees.

use std::collections::HashMap;
use std::fs::{read_dir, read_to_string};
use std::path::Path;
use std::process::Command;

use pm::sandbox::BuildSandbox;
use pm::step::{Stage, Step};
use tempfile::{TempDir, tempdir};
use url::Url;

mod common;
use common::{Body, TestServer};

/// A step with no downloads attached.
fn step(stage: Stage, name: &str, run: Vec<String>) -> Step {
    Step {
        stage,
        dl_urls: None,
        name: name.into(),
        run,
    }
}

/// A step that runs `commands` through the shell in the `Install` stage.
fn install_step(name: &str, commands: &[&str]) -> Step {
    step(
        Stage::Install,
        name,
        commands.iter().map(|c| (*c).to_string()).collect(),
    )
}

/// A step whose single command runs `script` through `/bin/sh <path>`.
///
/// `Step` execs directly with no shell, so anything needing `$DESTDIR`,
/// redirection or quoting has to live in a script file. `make install` is the
/// intended real-world form; this is the shape a build file takes without make.
fn script_step(name: &str, dir: &Path, script: &str) -> Step {
    let path = dir.join(format!("{name}.sh"));
    std::fs::write(&path, script).expect("write the script");
    install_step(name, &[&format!("/bin/sh {}", path.display())])
}

/// A step that fetches exactly `url`, with an expected hash that cannot match.
fn download_step(name: &str, url: &str) -> Step {
    let mut dl_urls = HashMap::new();
    dl_urls.insert(Url::parse(url).expect("a parseable URL"), "0".repeat(64));
    Step {
        stage: Stage::Prepare,
        dl_urls: Some(dl_urls),
        name: name.into(),
        run: Vec::new(),
    }
}

/// The SHA-256 of a fixture payload, as the build file would declare it.
fn expected_hash(payload: &str) -> String {
    match payload {
        "first payload" => "bdaddc7127911b7a4d96de6f704ac24eea1357ec52d7249750e88d2baddd14d9",
        "second payload" => "969e6ff862080fc76166b4f8eb362588b21d8e946c93a649ce8da91d1ab5e1ad",
        other => panic!("no recorded digest for the payload {other:?}"),
    }
    .to_string()
}

/// The names of the entries directly under `dir`, sorted.
fn entries_of(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = read_dir(dir)
        .expect("read the directory")
        .map(|entry| {
            entry
                .expect("a readable directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// A working directory and a `DESTDIR`, each in its own temporary directory so
/// a test can tell the two apart.
/// A `BuildSandbox` that runs commands unconfined on the host.
///
/// `Step::execute` drives commands through a sandbox now. These tests exercise
/// step *mechanics* - download hashing, command ordering, DESTDIR, failure
/// reporting - not confinement, and the unsandboxed mode keeps exactly the
/// contract they assert: `current_dir` is the workdir and `DESTDIR` is the
/// staging directory. Confinement itself is covered by tests/escape.rs, which
/// needs user namespaces and is ignored by default.
fn host_sandbox(work: &Path, dest: &Path) -> BuildSandbox {
    BuildSandbox::unsandboxed(work, dest)
}

fn workdirs() -> (TempDir, TempDir) {
    (
        tempdir().expect("work directory"),
        tempdir().expect("destination directory"),
    )
}

#[test]
fn a_failing_command_is_an_error_carrying_the_child_stderr() {
    let (work, dest) = workdirs();
    // `cat` on a missing file exits non-zero and explains itself on stderr,
    // prefixing the message with its own name.
    let missing = "/pm-integration-test-missing-file";
    let failing = step(Stage::Build, "doomed", vec![format!("/bin/cat {missing}")]);

    let error = failing
        .execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect_err("a command that exits non-zero must fail the step");

    let rendered = format!("{error}\n{error:?}");
    assert!(
        rendered.contains(missing),
        "the diagnostic must name what failed, got: {rendered}"
    );
    assert!(
        rendered.contains("cat:"),
        "the child's captured stderr must be surfaced, got: {rendered}"
    );
}

#[test]
fn a_missing_program_is_an_error_not_a_panic() {
    let (work, dest) = workdirs();
    let bogus = step(
        Stage::Build,
        "bogus",
        vec!["/pm-integration-test/no-such-program".into()],
    );

    assert!(
        bogus
            .execute(&host_sandbox(work.path(), dest.path()), work.path())
            .is_err(),
        "a command naming a program that does not exist must return a diagnostic"
    );
}

#[test]
fn blank_and_whitespace_only_commands_do_not_panic() {
    let (work, dest) = workdirs();
    let blank = step(
        Stage::Build,
        "blank",
        vec![String::new(), "   ".into(), "\t\n ".into()],
    );

    // Skipping them or rejecting them are both defensible; indexing argv[0] of
    // an empty split is not. Reaching the assertion at all is the test.
    let outcome = blank.execute(&host_sandbox(work.path(), dest.path()), work.path());
    if let Err(error) = outcome {
        assert!(
            !format!("{error}").trim().is_empty(),
            "a rejection must still say something"
        );
    }
}

#[test]
fn commands_run_sequentially_in_the_authored_order() {
    let (work, dest) = workdirs();
    let one = work.path().join("one");
    let two = work.path().join("two");
    let three = work.path().join("three");

    // Each command consumes what the previous one produced, so any reordering
    // or parallel dispatch turns into a hard failure rather than a flake.
    let chain = step(
        Stage::Build,
        "chain",
        vec![
            format!("/bin/mkdir {}", one.display()),
            format!("/bin/mv {} {}", one.display(), two.display()),
            format!("/bin/mv {} {}", two.display(), three.display()),
        ],
    );

    chain
        .execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect("a chain of dependent commands must succeed when run in order");

    assert!(!one.exists());
    assert!(!two.exists());
    assert!(three.is_dir(), "the final rename must have happened last");
}

#[test]
fn a_failing_command_stops_the_ones_after_it() {
    let (work, dest) = workdirs();
    let never = work.path().join("never-created");

    let aborting = step(
        Stage::Build,
        "aborting",
        vec![
            "/bin/cat /pm-integration-test-missing-file".into(),
            format!("/bin/mkdir {}", never.display()),
        ],
    );

    assert!(
        aborting
            .execute(&host_sandbox(work.path(), dest.path()), work.path())
            .is_err()
    );
    assert!(
        !never.exists(),
        "execution must stop at the first failing command"
    );
}

#[test]
fn destdir_and_the_working_directory_reach_the_child_process() {
    let (work, dest) = workdirs();
    // `DESTDIR` reaches the child through its ENVIRONMENT, which is the whole
    // point: `make install` reads it from there and expands `$(DESTDIR)` in its
    // own install rules. The probe is a script so a shell can report what the
    // child actually received.
    let probe = script_step(
        "probe",
        work.path(),
        "pwd > \"$DESTDIR/cwd.txt\"\nprintf '%s' \"$DESTDIR\" > \"$DESTDIR/destdir.txt\"\n",
    );
    probe
        .execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect("the probe commands must run");

    let reported_cwd = read_to_string(dest.path().join("cwd.txt")).expect("cwd.txt");
    assert_eq!(
        Path::new(reported_cwd.trim())
            .canonicalize()
            .expect("canonicalise the reported cwd"),
        work.path()
            .canonicalize()
            .expect("canonicalise the workdir"),
        "commands must run with the working directory as their cwd"
    );

    let reported_destdir = read_to_string(dest.path().join("destdir.txt")).expect("destdir.txt");
    assert_eq!(
        Path::new(reported_destdir.trim())
            .canonicalize()
            .expect("canonicalise the reported DESTDIR"),
        dest.path().canonicalize().expect("canonicalise DESTDIR"),
        "DESTDIR must point at the staging directory, not the work directory"
    );
}

#[test]
fn commands_still_run_when_a_download_map_is_present_but_empty() {
    let (work, dest) = workdirs();
    let made = work.path().join("made");
    let with_downloads = Step {
        stage: Stage::Prepare,
        dl_urls: Some(HashMap::new()),
        name: "downloads-then-commands".into(),
        run: vec![format!("/bin/mkdir {}", made.display())],
    };

    with_downloads
        .execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect("an empty download map must not short-circuit the commands");

    assert!(
        made.is_dir(),
        "downloads and commands are sequential phases of one step, not alternatives"
    );
}

#[test]
fn a_step_with_nothing_to_do_succeeds() {
    let (work, dest) = workdirs();
    let idle = step(Stage::Test, "idle", Vec::new());

    idle.execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect("a step with no commands must succeed");
}

#[test]
fn stages_are_ordered_prepare_build_install_test() {
    assert!(Stage::Prepare < Stage::Build);
    assert!(Stage::Build < Stage::Install);
    assert!(Stage::Install < Stage::Test);
    assert!(Stage::Prepare < Stage::Test);
}

#[test]
fn sorting_steps_by_stage_preserves_the_authored_order_within_a_stage() {
    let mut steps = [
        step(Stage::Test, "t1", Vec::new()),
        step(Stage::Install, "i1", Vec::new()),
        step(Stage::Prepare, "p1", Vec::new()),
        step(Stage::Install, "i2", Vec::new()),
        step(Stage::Build, "b1", Vec::new()),
        step(Stage::Prepare, "p2", Vec::new()),
        step(Stage::Build, "b2", Vec::new()),
    ];

    // `sort_by_key` is stable, which is what keeps two steps of the same stage
    // in the order the build file listed them. This mirrors what `bf.rs` does.
    steps.sort_by_key(|left| left.stage);

    let order: Vec<&str> = steps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(order, ["p1", "p2", "b1", "b2", "i1", "i2", "t1"]);
}

#[test]
fn a_download_whose_hash_does_not_match_is_rejected() {
    let (work, dest) = workdirs();
    let server = TestServer::serving_one(b"contents that hash to something else");

    let mut urls = HashMap::new();
    urls.insert(server.url("/source.tar.gz"), "0".repeat(64));
    let download = Step {
        stage: Stage::Prepare,
        dl_urls: Some(urls),
        name: "download".into(),
        run: Vec::new(),
    };

    let error = download
        .execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect_err("a hash mismatch must fail the step");
    assert!(
        format!("{error}\n{error:?}")
            .to_lowercase()
            .contains("hash"),
        "the diagnostic must explain that the hash did not match"
    );
}

#[test]
fn downloads_sharing_a_basename_do_not_share_a_destination() {
    let (work, dest) = workdirs();
    // Offline by construction: port 1 has nothing listening, so each of these
    // steps fails to connect. The destination directory is derived and created
    // BEFORE the fetch is attempted, though, so what the work directory holds
    // afterwards is exactly the destination mapping this test is about. The
    // end-to-end path is covered by the test below, which serves real bodies.
    let first = download_step("first", "http://127.0.0.1:1/one/source.tar.gz");
    let second = download_step("second", "http://127.0.0.1:1/two/source.tar.gz");

    assert!(
        first
            .execute(&host_sandbox(work.path(), dest.path()), work.path())
            .is_err(),
        "an unfetchable URL must fail the step"
    );
    assert!(
        second
            .execute(&host_sandbox(work.path(), dest.path()), work.path())
            .is_err()
    );

    let after_two = entries_of(work.path());
    assert_eq!(
        after_two.len(),
        2,
        "two URLs sharing the basename `source.tar.gz` must get two destinations, got {after_two:?}"
    );

    // The same URL must map to the same destination every time, or a resumed
    // build would re-download everything.
    let again = download_step("first-again", "http://127.0.0.1:1/one/source.tar.gz");
    assert!(
        again
            .execute(&host_sandbox(work.path(), dest.path()), work.path())
            .is_err()
    );
    assert_eq!(
        entries_of(work.path()),
        after_two,
        "the destination for a URL must be stable across runs"
    );
}

#[test]
fn two_downloads_sharing_a_basename_both_land() {
    let (work, dest) = workdirs();
    // Two different bodies served under different paths but the SAME basename,
    // which is the collision `Step::download_dest` exists to prevent.
    let server = TestServer::serving(HashMap::from([
        (
            "/one/source.tar.gz".to_string(),
            Body::Measured(b"first payload".to_vec()),
        ),
        (
            "/two/source.tar.gz".to_string(),
            Body::Measured(b"second payload".to_vec()),
        ),
    ]));

    let mut dl_urls = HashMap::new();
    for (path, payload) in [
        ("/one/source.tar.gz", "first payload"),
        ("/two/source.tar.gz", "second payload"),
    ] {
        dl_urls.insert(server.url(path), expected_hash(payload));
    }

    let fetching = Step {
        stage: Stage::Prepare,
        dl_urls: Some(dl_urls),
        name: "fetch-two".into(),
        run: Vec::new(),
    };
    fetching
        .execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect("both downloads must succeed");

    for (path, payload) in [
        ("/one/source.tar.gz", "first payload"),
        ("/two/source.tar.gz", "second payload"),
    ] {
        let relative = Step::download_path(&server.url(path)).expect("public source path");
        assert!(relative.is_relative());
        assert_eq!(
            read_to_string(work.path().join(relative)).expect("download at the advertised path"),
            payload
        );
    }

    let landed: Vec<String> = read_dir(work.path())
        .expect("read the work directory")
        .filter_map(|entry| {
            let path = entry.expect("a readable entry").path();
            path.is_dir()
                .then(|| read_to_string(path.join("source.tar.gz")).ok())
                .flatten()
        })
        .collect();
    assert_eq!(
        landed.len(),
        2,
        "both downloads must survive; one overwrote the other"
    );
}

#[test]
fn download_paths_are_pure_and_account_for_the_whole_url() {
    let first = Url::parse("https://example.com/source.tar.gz?version=1").unwrap();
    let second = Url::parse("https://example.com/source.tar.gz?version=2").unwrap();
    let path = Step::download_path(&first).unwrap();
    assert_eq!(path.file_name().unwrap(), "source.tar.gz");
    assert_eq!(path, Step::download_path(&first).unwrap());
    assert_ne!(path, Step::download_path(&second).unwrap());
    assert_eq!(path.components().count(), 2);
    assert!(Step::download_path(&Url::parse("https://example.com/").unwrap()).is_err());
    assert!(Step::download_path(&Url::parse("mailto:user@example.com").unwrap()).is_err());
}

#[test]
fn a_command_string_is_not_interpreted_by_a_shell() {
    let (work, dest) = workdirs();
    // Commands are split on whitespace and exec'd directly. `$DESTDIR` in a
    // command string is therefore literal text, NOT the staging directory.
    // `DESTDIR` is passed through the environment instead, because that is the
    // Makefile convention: `make install` reads it from there and expands
    // `$(DESTDIR)` in its own rules. Pinning this stops anyone reintroducing a
    // shell and silently changing what every existing build file means.
    let literal = install_step("literal", &["/bin/mkdir -p $DESTDIR/oops"]);

    literal
        .execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect("mkdir must succeed; the argument is just an odd directory name");

    assert!(
        work.path().join("$DESTDIR/oops").is_dir(),
        "`$DESTDIR` must reach the program as literal text, not be expanded"
    );
    assert!(
        !dest.path().join("oops").exists(),
        "nothing may be expanded into the staging directory"
    );
}

#[test]
fn make_install_redirects_into_destdir_through_the_environment() {
    // The intended real-world shape of a build step, and the reason `DESTDIR`
    // is an environment variable rather than a substitution.
    if Command::new("make").arg("-v").output().is_err() {
        eprintln!("skipping make_install_redirects_into_destdir: `make` is not installed");
        return;
    }

    let (work, dest) = workdirs();
    std::fs::write(
        work.path().join("Makefile"),
        "PREFIX ?= /usr\n\ninstall:\n\tinstall -d $(DESTDIR)$(PREFIX)/bin\n\tinstall -m755 payload $(DESTDIR)$(PREFIX)/bin/payload\n",
    )
    .expect("write the Makefile");
    std::fs::write(work.path().join("payload"), "#!/bin/sh\nexit 0\n").expect("write the payload");

    install_step("make", &["make install"])
        .execute(&host_sandbox(work.path(), dest.path()), work.path())
        .expect("`make install` must succeed");

    assert!(
        dest.path().join("usr/bin/payload").is_file(),
        "make must expand $(DESTDIR) itself and install into the staging tree"
    );
}
