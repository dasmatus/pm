//! End-to-end tests for `pmd --worker`: fork it over a real socketpair, feed
//! it a signed build file, and read the frames it sends back.
//!
//! This is the only place the coalescing gate the whole worker module
//! exists for gets measured against a real build, rather than asserted
//! against `Progress` in isolation: [`a_high_volume_step_coalesces_progress_and_sanitises_control_bytes`]
//! runs a step that prints 10 000 lines and asserts the worker sent at most
//! 13 progress snapshots per second while it did.

use std::{
    io::Write as _,
    os::unix::{io::AsRawFd as _, net::UnixStream, process::CommandExt as _},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use nix::libc;
use pm::{
    daemon::worker::{JobKind, WorkerEvent, WorkerRequest},
    signing::{SigningKey, TrustStore, sign_file},
    wire::{
        frame::{read_frame, write_frame},
        types::{CallerContext, PackageOutcome},
    },
};
use tempfile::tempdir;

/// Where this test's throwaway `$HOME` lives, under `work`.
///
/// The worker sets `HOME` from [`CallerContext::home`] and clears nothing
/// else, so `crate::signing::default_trust_dir` resolves relative to this -
/// see `spawn_worker`, which also removes `XDG_CONFIG_HOME` from the
/// child's environment so a value inherited from whoever runs `cargo test`
/// cannot shadow it.
fn home_dir(work: &Path) -> std::path::PathBuf {
    work.join("home")
}

/// Writes `yaml` as `work/build.yaml`, signs it with a throwaway key, and
/// trusts that key - see [`write_signed_build_file_named`], which this
/// just fixes the file name for.
fn write_signed_build_file(work: &Path, yaml: &str) -> std::path::PathBuf {
    write_signed_build_file_named(work, "build.yaml", yaml)
}

/// Writes `yaml` as `work/<name>`, signs it with a throwaway key, and
/// trusts that key under [`home_dir`]'s config directory - the same
/// layout `crate::signing::default_trust_dir` expects once the worker has
/// set `HOME` to it.
///
/// A distinct name from [`write_signed_build_file`]'s fixed `build.yaml`
/// matters once a test needs more than one build file in the same
/// directory - a root and a dependency it names by path, say.
fn write_signed_build_file_named(work: &Path, name: &str, yaml: &str) -> std::path::PathBuf {
    let path = work.join(name);
    std::fs::write(&path, yaml).expect("write the build file");

    let config = home_dir(work).join(".config").join("pm");
    let key = SigningKey::load_or_create(&config.join("signing.key"))
        .expect("create a throwaway signing key");
    sign_file(&path, &key).expect("sign the build file");

    let trusted = config.join("trusted");
    let mut trust = TrustStore::load(&trusted).expect("load the trust store");
    trust
        .add(&key.public_key_hex(), &trusted)
        .expect("trust the throwaway key");

    path
}

/// A [`CallerContext`] that keeps each test's working tree, output directory,
/// and trust store self-contained.
fn caller_context(work: &Path, home: &Path) -> CallerContext {
    CallerContext {
        cwd: work.display().to_string(),
        output_dir: work.display().to_string(),
        trust_dir: home
            .join(".config")
            .join("pm")
            .join("trusted")
            .display()
            .to_string(),
        path: std::env::var("PATH").expect("PATH must be set for the test to find real tools"),
        home: home.display().to_string(),
    }
}

/// Forks `pmd --worker --fd 3` over a fresh socketpair, dup'd onto fd 3 in
/// the child, and sends it `request` as the first frame.
///
/// Returns the child and the parent's end of the socket, ready to read
/// [`WorkerEvent`] frames from.
fn spawn_worker(request: &WorkerRequest) -> (Child, UnixStream) {
    let (parent_end, child_end) = UnixStream::pair().expect("create a socketpair");
    parent_end
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set a read timeout so a stuck worker fails the test instead of hanging it");

    let child_fd = child_end.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pmd"));
    command
        .arg("--worker")
        .arg("--fd")
        .arg("3")
        // A value inherited from whoever runs `cargo test` must not shadow
        // the `HOME` the worker sets from the job's `CallerContext` - see
        // `home_dir`'s docs.
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // SAFETY: `dup2` is async-signal-safe, and `child_fd` is a real, open
    // descriptor in the forked child's own table - `fork` duplicates the
    // whole table - at the point this closure runs, after fork and before
    // exec. This is the standard way to hand a child an arbitrary fd
    // number rather than only stdin/stdout/stderr.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn().expect("spawn the pmd worker");
    // The child's own copy of this fd (now also at fd 3, via dup2) survives
    // independently of the parent's; dropping the parent's copy here does
    // not touch it.
    drop(child_end);

    let mut writer = parent_end
        .try_clone()
        .expect("clone the control socket for writing the request");
    let payload = serde_json::to_vec(request).expect("serialise the worker request");
    write_frame(&mut writer, &payload).expect("send the worker request frame");

    (child, parent_end)
}

/// Reads [`WorkerEvent`] frames from `stream` until a terminal `Completed`
/// arrives or the worker closes the socket, returning each frame's raw
/// bytes alongside its decoded form.
///
/// The raw bytes matter on their own: [`a_high_volume_step_coalesces_progress_and_sanitises_control_bytes`]
/// checks them directly for a stray ESC byte, which is a stronger claim
/// than checking only the fields this test happens to read back out.
fn read_events(stream: &mut UnixStream) -> Vec<(Vec<u8>, WorkerEvent)> {
    let mut events = Vec::new();
    loop {
        let Ok(payload) = read_frame(stream) else {
            // The worker closed the socket. A well-behaved worker only does
            // this after its terminal frame, but a test must not hang
            // waiting for one that never arrives, so this is treated as
            // "no more events" rather than retried.
            break;
        };
        let event: WorkerEvent =
            serde_json::from_slice(&payload).expect("decode a worker event frame");
        let terminal = matches!(event, WorkerEvent::Completed { .. });
        events.push((payload, event));
        if terminal {
            break;
        }
    }
    events
}

/// Asserts the worker exited cleanly AND actually sent its own terminal
/// frame, rather than exiting 0 having silently dropped it.
///
/// This module once had exactly that bug: an earlier version of the frame
/// codec refused to serialise `WorkerEvent::Completed` wrapping a nested
/// enum, the write failure was swallowed by a `warn!`-and-continue branch,
/// and the worker exited 0 having sent every frame EXCEPT `Completed`.
/// `status.success()` alone cannot tell that apart from a real success -
/// only checking that the LAST frame received actually is `Completed` can,
/// which is why every test that runs a real build calls this instead of
/// asserting on `status` by itself.
fn assert_worker_completed(status: &std::process::ExitStatus, events: &[(Vec<u8>, WorkerEvent)]) {
    assert!(
        status.success(),
        "the worker process itself must exit cleanly, got {status:?}"
    );
    assert!(
        matches!(events.last(), Some((_, WorkerEvent::Completed { .. }))),
        "the worker exited 0 but its last frame was {:?}, not Completed - it exited having \
         silently dropped its own terminal frame",
        events.last().map(|(_, event)| event.clone())
    );
}

/// Guards the codec choice itself, independent of whatever
/// [`WorkerEvent`]'s own frames happen to look like today.
///
/// This is the exact shape that broke this module's original codec
/// (`serde_yaml`): an enum variant whose payload is itself another enum.
/// That codec refused it with `"serializing nested enums in YAML is not
/// supported yet"`, and the failure was easy to miss because nothing about
/// the WRITE call itself panicked - only a later "the terminal frame never
/// arrived" symptom gave it away (see [`assert_worker_completed`]).
/// `WorkerEvent::Completed` no longer has this shape - it is a flat struct
/// on purpose, matching design section 6's own `Completed { status,
/// result }` wording, not a codec workaround - so this test pins the
/// CODEC's own capability directly instead: whatever a future task's new
/// frame variants look like, a nested enum travelling through
/// `write_frame`/`read_frame` via `serde_json` must survive the round trip.
#[test]
fn a_frame_carrying_a_nested_enum_round_trips() {
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    enum Inner {
        A,
        B(String),
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    enum Outer {
        Wraps(Inner),
    }

    let (mut a, mut b) = UnixStream::pair().expect("create a socketpair");
    let sent = Outer::Wraps(Inner::B("nested".to_owned()));
    let payload = serde_json::to_vec(&sent).expect("serialise a nested enum");
    write_frame(&mut a, &payload).expect("write a frame carrying a nested enum");

    let received = read_frame(&mut b).expect("read the frame back");
    let decoded: Outer = serde_json::from_slice(&received).expect("decode a nested enum frame");
    assert_eq!(
        decoded, sent,
        "a nested enum must round-trip through this protocol's codec"
    );
}

#[test]
fn successful_build_reports_progress_a_package_outcome_and_an_archive() {
    let work = tempdir().expect("work dir");
    let home = home_dir(work.path());
    let target = write_signed_build_file(
        work.path(),
        "name: alpha\nversion:\n- '1'\ndependencies: []\nsteps:\n- stage: Build\n  dl_urls: \
         null\n  name: pause\n  run:\n  - sleep 0.3\n",
    );

    let request = WorkerRequest {
        kind: JobKind::Build,
        target: target.display().to_string(),
        context: caller_context(work.path(), &home),
        permissive: true,
        unsandboxed: true,
        jobs: None,
        log_filter: "warn".to_owned(),
    };

    let (mut child, mut control) = spawn_worker(&request);
    let events = read_events(&mut control);
    let status = child.wait().expect("wait for the worker process");
    assert_worker_completed(&status, &events);

    // Check 1: at least one progress snapshot arrived while the 300ms step
    // (well over one 80ms tick) ran.
    let progress_frames = events
        .iter()
        .filter(|(_, event)| matches!(event, WorkerEvent::Progress(_)))
        .count();
    assert!(
        progress_frames >= 1,
        "expected at least one progress snapshot frame while a 300ms step ran"
    );

    // Check 4: one PackageOutcome for the graph's one package, built.
    let outcomes: Vec<&PackageOutcome> = events
        .iter()
        .filter_map(|(_, event)| match event {
            WorkerEvent::PackageOutcome(outcome) => Some(outcome),
            _ => None,
        })
        .collect();
    assert_eq!(
        outcomes.len(),
        1,
        "a one-package graph must report exactly one PackageOutcome, got {outcomes:?}"
    );
    assert_eq!(outcomes[0].outcome, "built");
    assert_eq!(outcomes[0].name, "alpha");

    // Check 5: the terminal result names an archive that exists.
    match events.last().map(|(_, event)| event.clone()) {
        Some(WorkerEvent::Completed {
            archive: Some(archive),
            diagnostic: None,
        }) => {
            assert!(
                Path::new(&archive).is_file(),
                "the reported archive {archive} does not exist"
            );
        }
        other => panic!("expected a terminal Succeeded Completed frame, got {other:?}"),
    }
}

#[test]
fn a_high_volume_step_coalesces_progress_and_sanitises_control_bytes() {
    let work = tempdir().expect("work dir");
    let home = home_dir(work.path());
    // `seq 1 10000` alone is the volume: one command, no shell needed,
    // 10 000 lines to stdout. The `printf` line is a SEPARATE command
    // (`Step::run` entries run sequentially) whose format string contains a
    // raw octal escape - `\033` - that `printf` itself expands to a real
    // ESC byte in its OWN output, with no shell involved at all. The
    // trailing `sleep 2` pads the step's wall time well past a couple of
    // 80ms ticks, so the frames-per-second measurement below is not at the
    // mercy of how fast `seq` happens to run on whatever machine this test
    // executes on.
    let target = write_signed_build_file(
        work.path(),
        "name: tenk\nversion:\n- '1'\ndependencies: []\nsteps:\n- stage: Build\n  dl_urls: \
         null\n  name: flood\n  run:\n  - seq 1 10000\n  - 'printf \\033[31mHELLO\\033[0m\\n'\n  \
         - sleep 2\n",
    );

    let request = WorkerRequest {
        kind: JobKind::Build,
        target: target.display().to_string(),
        context: caller_context(work.path(), &home),
        permissive: true,
        unsandboxed: false,
        jobs: None,
        log_filter: "warn".to_owned(),
    };

    let started = Instant::now();
    let (mut child, mut control) = spawn_worker(&request);
    let events = read_events(&mut control);
    let elapsed = started.elapsed();
    let status = child.wait().expect("wait for the worker process");
    assert_worker_completed(&status, &events);

    // Check 3: no frame's raw bytes ever carry an ESC byte, proving
    // sanitisation held on this untrusted build output all the way to the
    // wire, not merely in whichever field a test happens to inspect.
    for (payload, event) in &events {
        assert!(
            !payload.contains(&0x1b),
            "a frame payload carried a raw ESC byte, so sanitisation did not hold: {event:?}"
        );
    }

    // Check 2: the coalescing gate. Measured over the WHOLE request, not
    // just the `seq` call, so the padding `sleep 2` keeps the denominator
    // meaningful regardless of how fast `seq` printed its 10 000 lines.
    let progress_frames = events
        .iter()
        .filter(|(_, event)| matches!(event, WorkerEvent::Progress(_)))
        .count();
    let seconds = elapsed.as_secs_f64();
    assert!(
        seconds > 1.0,
        "the padding sleep must dominate elapsed time for a frames-per-second measurement to \
         mean anything; only {seconds:.3}s elapsed"
    );
    #[allow(clippy::cast_precision_loss)]
    let rate = progress_frames as f64 / seconds;
    eprintln!(
        "coalescing gate: {progress_frames} progress snapshots over {seconds:.3}s = {rate:.3}/s"
    );
    assert!(
        rate <= 13.0,
        "a 10 000-line step produced {progress_frames} snapshots over {seconds:.3}s = \
         {rate:.3}/s, over the 13/s coalescing gate"
    );

    match events.last().map(|(_, event)| event.clone()) {
        Some(WorkerEvent::Completed {
            archive: Some(_),
            diagnostic: None,
        }) => {}
        other => panic!("expected the flood step to still succeed, got {other:?}"),
    }
}

#[test]
fn a_failing_step_yields_a_diagnostic_not_a_panic_or_a_silent_success() {
    let work = tempdir().expect("work dir");
    let home = home_dir(work.path());
    let target = write_signed_build_file(
        work.path(),
        "name: broken\nversion:\n- '1'\ndependencies: []\nsteps:\n- stage: Build\n  dl_urls: \
         null\n  name: boom\n  run:\n  - false\n",
    );

    let request = WorkerRequest {
        kind: JobKind::Build,
        target: target.display().to_string(),
        context: caller_context(work.path(), &home),
        permissive: true,
        unsandboxed: false,
        jobs: None,
        log_filter: "warn".to_owned(),
    };

    let (mut child, mut control) = spawn_worker(&request);
    let events = read_events(&mut control);
    let status = child.wait().expect("wait for the worker process");
    // A panic would unwind out of the worker's `main` and exit 101 (or die
    // by signal); a controlled build failure exits cleanly and reports
    // itself over the socket instead. This is the "not a panic" half of
    // check 6 - `assert_worker_completed` also confirms the worker did not
    // exit 0 while quietly dropping its own terminal frame.
    assert_worker_completed(&status, &events);

    // The "not a silent success" half: the terminal frame must be a
    // Diagnostic, not a Succeeded.
    match events.last().map(|(_, event)| event.clone()) {
        Some(WorkerEvent::Completed {
            archive: None,
            diagnostic: Some(diagnostic),
        }) => {
            assert!(
                !diagnostic.message.is_empty(),
                "a failure must explain itself, got an empty message"
            );
        }
        other => panic!("expected a terminal Failed frame, got {other:?}"),
    }
}

#[test]
fn read_frame_on_a_truncated_stream_errors_rather_than_hangs() {
    let (mut reader, mut writer) = UnixStream::pair().expect("create a socketpair");

    let writer_thread = thread::spawn(move || {
        // A length prefix claiming far more than actually follows, then the
        // writer vanishes: `read_frame` must fail on the resulting EOF
        // rather than block forever waiting for bytes that are never coming.
        writer
            .write_all(&100u32.to_be_bytes())
            .expect("write a length prefix");
        writer
            .write_all(b"short")
            .expect("write a short, truncated payload");
        drop(writer);
    });

    let (tx, rx) = mpsc::channel();
    let reader_thread = thread::spawn(move || {
        let result = read_frame(&mut reader);
        let _ = tx.send(result.is_err());
    });

    let errored = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("read_frame must return within 5 seconds instead of hanging");
    assert!(
        errored,
        "a truncated frame must be an error, not a short success"
    );

    writer_thread.join().expect("the writer thread panicked");
    reader_thread.join().expect("the reader thread panicked");
}

#[test]
fn a_stale_archive_from_an_earlier_run_is_never_reported_built() {
    // The exact false positive a reviewer found in `package_outcome`: the
    // worker chdirs into the caller's own directory and nothing cleans it
    // between jobs, so a non-root package's archive from an EARLIER,
    // unrelated run is still sitting there when this run's `find_archive`
    // globs for one. Reproduced here with a two-package graph, `top`
    // depending on `dep`: the first run builds both and leaves `dep-1.cpkg`
    // behind; the second run breaks `dep`'s own step so `dep` fails (and
    // `top`, whose dependency failed, is never attempted either), but
    // `dep-1.cpkg` from the first run is untouched on disk. Before the fix,
    // globbing for it reported `dep` "built" - a package manager claiming
    // it built something this run never touched. After the fix it is
    // "unknown": a candidate file exists, but nothing proves this run
    // wrote it.
    let work = tempdir().expect("work dir");
    let home = home_dir(work.path());

    write_signed_build_file_named(
        work.path(),
        "top.yaml",
        "name: top\nversion:\n- '1'\ndependencies:\n- dep.yaml\nsteps:\n- stage: Build\n  \
         dl_urls: null\n  name: noop\n  run:\n  - true\n",
    );
    write_signed_build_file_named(
        work.path(),
        "dep.yaml",
        "name: dep\nversion:\n- '1'\ndependencies: []\nsteps:\n- stage: Build\n  dl_urls: \
         null\n  name: noop\n  run:\n  - true\n",
    );
    let top_path = work.path().join("top.yaml");

    let request = |target: &Path| WorkerRequest {
        kind: JobKind::Build,
        target: target.display().to_string(),
        context: caller_context(work.path(), &home),
        permissive: true,
        unsandboxed: false,
        jobs: None,
        log_filter: "warn".to_owned(),
    };

    // First run: both packages build, and both archives land in `work`.
    let (mut child, mut control) = spawn_worker(&request(&top_path));
    let events = read_events(&mut control);
    let status = child.wait().expect("wait for the worker process");
    assert_worker_completed(&status, &events);
    assert!(
        work.path().join("dep-1.cpkg").is_file(),
        "the first run must leave dep's archive behind for the second run to find stale"
    );

    // Second run: `dep`'s own step now fails, so `dep` never reaches
    // packaging and `top` (whose only dependency just failed) is never
    // attempted either. `dep`'s signature has to be redone: the content
    // changed, and `BuildFile::load` verifies signatures before parsing.
    write_signed_build_file_named(
        work.path(),
        "dep.yaml",
        "name: dep\nversion:\n- '1'\ndependencies: []\nsteps:\n- stage: Build\n  dl_urls: \
         null\n  name: noop\n  run:\n  - false\n",
    );
    let (mut child, mut control) = spawn_worker(&request(&top_path));
    let events = read_events(&mut control);
    let status = child.wait().expect("wait for the worker process");
    assert_worker_completed(&status, &events);

    let outcomes: Vec<&PackageOutcome> = events
        .iter()
        .filter_map(|(_, event)| match event {
            WorkerEvent::PackageOutcome(outcome) => Some(outcome),
            _ => None,
        })
        .collect();
    let dep_outcome = outcomes
        .iter()
        .find(|outcome| outcome.name == "dep")
        .unwrap_or_else(|| panic!("no PackageOutcome named \"dep\" in {outcomes:?}"));

    assert_eq!(
        dep_outcome.outcome, "unknown",
        "dep's stale archive from the FIRST run must not be reported \"built\" for a run in \
         which dep actually failed: got {dep_outcome:?}"
    );
    assert!(
        !dep_outcome.archive.is_empty(),
        "an \"unknown\" outcome still names the candidate file it found: {dep_outcome:?}"
    );

    // The root's own outcome is unaffected by any of this: it is handed
    // `Graph::build`'s exact return value, never guessed at by globbing,
    // so a real failure still reports "failed", not "unknown".
    let top_outcome = outcomes
        .iter()
        .find(|outcome| outcome.name == "top")
        .unwrap_or_else(|| panic!("no PackageOutcome named \"top\" in {outcomes:?}"));
    assert_eq!(top_outcome.outcome, "failed");

    match events.last().map(|(_, event)| event.clone()) {
        Some(WorkerEvent::Completed {
            archive: None,
            diagnostic: Some(_),
        }) => {}
        other => panic!("expected the second run to fail overall, got {other:?}"),
    }
}
