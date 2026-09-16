//! Tests for what [`pm::sandbox::BuildSandbox`] does with a command's output.
//!
//! A build command's stdout used to go straight to the terminal. It cannot any
//! more: a progress region owns the bottom of the screen, and a `make` writing
//! freely over it would shred the redraw. So stdout is captured instead, its
//! latest line becomes the command's progress message, and the whole of it is
//! reported only if the command fails - which is the one time anybody wants to
//! read it in full.

use std::{
    io::sink,
    path::Path,
    thread::{sleep, spawn},
    time::{Duration, Instant},
};

use pm::{progress::Progress, sandbox::BuildSandbox};
use tempfile::{TempDir, tempdir};

/// Longest a liveness assertion waits before giving up on the region.
const PATIENCE: Duration = Duration::from_secs(10);

/// A marker distinctive enough that finding it in a diagnostic means something.
const MARKER: &str = "pm-integration-test-stdout-marker";

fn workdirs() -> (TempDir, TempDir) {
    (
        tempdir().expect("work directory"),
        tempdir().expect("destination directory"),
    )
}

/// A region that renders normally but draws into nothing, so a test can read
/// `snapshot()` without a terminal.
fn headless() -> Progress {
    Progress::to_writer(Box::new(sink()), 120)
}

/// Write `script` into `dir` and return the command string that runs it.
fn script(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("the script must be writable");
    format!("/bin/sh {}", path.display())
}

#[test]
fn a_failing_command_reports_what_it_printed_to_stdout() {
    let (work, dest) = workdirs();
    let progress = headless();
    let sandbox =
        BuildSandbox::unsandboxed(work.path(), dest.path()).with_progress(progress.task("pkg"));

    let failing = script(
        work.path(),
        "doomed.sh",
        &format!("echo {MARKER}\nexit 3\n"),
    );
    let error = sandbox
        .run(&failing, "build")
        .expect_err("a command that exits non-zero must fail the step");

    let report = format!("{error}\n{error:?}");
    assert!(
        report.contains(MARKER),
        "a captured command's stdout must reach the diagnostic, got: {report}"
    );
}

#[test]
fn a_failing_command_still_reports_its_stderr() {
    let (work, dest) = workdirs();
    let progress = headless();
    let sandbox =
        BuildSandbox::unsandboxed(work.path(), dest.path()).with_progress(progress.task("pkg"));

    let failing = script(
        work.path(),
        "noisy.sh",
        &format!("echo {MARKER} >&2\nexit 4\n"),
    );
    let error = sandbox
        .run(&failing, "build")
        .expect_err("a command that exits non-zero must fail the step");

    let report = format!("{error}\n{error:?}");
    assert!(
        report.contains(MARKER),
        "capturing stdout must not cost us stderr, got: {report}"
    );
}

#[test]
fn a_finished_command_leaves_no_line_behind() {
    let (work, dest) = workdirs();
    let progress = headless();
    let package = progress.task("pkg");
    let sandbox = BuildSandbox::unsandboxed(work.path(), dest.path()).with_progress(package);

    sandbox
        .run("/bin/true", "build")
        .expect("a command that exits zero must succeed");

    assert_eq!(
        progress.snapshot().len(),
        1,
        "only the package line may remain once its command has finished: {:?}",
        progress.snapshot()
    );
}

#[test]
fn a_failed_command_also_leaves_no_line_behind() {
    let (work, dest) = workdirs();
    let progress = headless();
    let package = progress.task("pkg");
    let sandbox = BuildSandbox::unsandboxed(work.path(), dest.path()).with_progress(package);

    sandbox
        .run("/bin/false", "build")
        .expect_err("a command that exits non-zero must fail");

    assert_eq!(
        progress.snapshot().len(),
        1,
        "a failure must clear its line too, not strand it: {:?}",
        progress.snapshot()
    );
}

#[test]
fn a_running_command_shows_its_latest_output_in_the_region() {
    let (work, dest) = workdirs();
    let progress = headless();
    let package = progress.task("pkg");

    // Print the marker, then stay alive long enough for this thread to see the
    // region reflect it. Without the sleep the command is gone before anyone
    // could look, and the test would assert nothing.
    let running = script(work.path(), "slow.sh", &format!("echo {MARKER}\nsleep 3\n"));
    let sandbox = BuildSandbox::unsandboxed(work.path(), dest.path()).with_progress(package);
    let worker = spawn(move || sandbox.run(&running, "build"));

    let deadline = Instant::now() + PATIENCE;
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        seen = progress.snapshot();
        if seen.iter().any(|line| line.contains(MARKER)) {
            break;
        }
        sleep(Duration::from_millis(20));
    }

    assert!(
        seen.iter().any(|line| line.contains(MARKER)),
        "the command's latest stdout line must become its progress message, saw: {seen:?}"
    );
    assert!(
        seen.iter().any(|line| line.contains("sh")),
        "the command's line must name the program running, saw: {seen:?}"
    );

    worker
        .join()
        .expect("the worker must not panic")
        .expect("the command must succeed");
}

#[test]
fn a_command_that_floods_both_streams_does_not_deadlock() {
    let (work, dest) = workdirs();
    let progress = headless();
    let sandbox =
        BuildSandbox::unsandboxed(work.path(), dest.path()).with_progress(progress.task("pkg"));

    // Far more than a pipe buffer holds, on BOTH streams. Draining them one
    // after the other deadlocks here: the child blocks writing to the pipe
    // nobody is reading while the parent blocks reading the pipe nobody is
    // writing. This test hangs rather than fails if that regresses, which is
    // why the body is deliberately enormous.
    let flooding = script(
        work.path(),
        "flood.sh",
        "i=0\nwhile [ $i -lt 4000 ]; do\n  echo \"stdout line $i padding padding padding padding\"\n  echo \"stderr line $i padding padding padding padding\" >&2\n  i=$((i+1))\ndone\nexit 7\n",
    );

    let error = sandbox
        .run(&flooding, "build")
        .expect_err("the command exits non-zero");

    let report = format!("{error:?}");
    assert!(
        report.contains("stdout line 3999"),
        "the whole of a large stdout must survive capture"
    );
    assert!(
        report.contains("stderr line 3999"),
        "the whole of a large stderr must survive capture"
    );
}

#[test]
fn a_sandbox_without_progress_still_runs_commands() {
    let (work, dest) = workdirs();
    // The default path, which every existing caller and test takes: no region,
    // stdout inherited exactly as before.
    let sandbox = BuildSandbox::unsandboxed(work.path(), dest.path());

    sandbox
        .run("/bin/true", "build")
        .expect("a sandbox with no region attached must behave as it always did");
}
