//! Integration tests for [`pm::download::Downloader`]: what lands on disk, the
//! hash that comes back, what the progress callback observes, and what happens
//! when the server or the hash disagrees with the build file.
//!
//! Every test runs against a real socket. A download is HTTP parsing, response
//! framing, redirect following and streaming I/O all at once, and none of that
//! is exercised by a fake that hands back a `Vec<u8>`.

use std::{
    collections::HashMap,
    fs::{read, write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use pm::download::Downloader;
use tempfile::{TempDir, tempdir};

mod common;
use common::{Body, TestServer};

const BODY: &[u8] = b"hello, sources";
/// SHA-256 of [`BODY`], lowercase hex.
const BODY_SHA256: &str = "faae6372e87258f131c99934e24b0761a3c07c34f0801942a6d45f4cd85373d4";

fn dest(dir: &TempDir) -> PathBuf {
    dir.path().join("source.tar.gz")
}

/// One progress report: bytes written so far, and the total if the server
/// declared one.
type Report = (u64, Option<u64>);

/// Collects everything the progress callback was told.
#[derive(Clone, Default)]
struct Observed(Arc<Mutex<Vec<Report>>>);

impl Observed {
    fn record(&self) -> impl FnMut(u64, Option<u64>) + use<> {
        let seen = Arc::clone(&self.0);
        move |done, total| {
            seen.lock()
                .expect("the observer must not be poisoned")
                .push((done, total));
        }
    }

    fn last(&self) -> Option<Report> {
        self.0
            .lock()
            .expect("the observer must not be poisoned")
            .last()
            .copied()
    }

    fn count(&self) -> usize {
        self.0
            .lock()
            .expect("the observer must not be poisoned")
            .len()
    }
}

#[test]
fn writes_the_body_and_returns_its_sha256() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let dest = dest(&dir);
    let server = TestServer::serving_one(BODY);

    let hash = Downloader::new()
        .fetch(&server.url("/source.tar.gz"), &dest, |_, _| {})
        .expect("the download must succeed");

    assert_eq!(read(&dest).expect("the file must exist"), BODY);
    assert_eq!(hash, BODY_SHA256, "the returned hash must cover the body");
}

#[test]
fn reports_bytes_so_far_against_the_content_length() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let server = TestServer::serving_one(BODY);
    let seen = Observed::default();

    Downloader::new()
        .fetch(&server.url("/source.tar.gz"), &dest(&dir), seen.record())
        .expect("the download must succeed");

    assert!(
        seen.count() >= 2,
        "progress must be reported before the first byte and again after it"
    );
    assert_eq!(
        seen.last(),
        Some((BODY.len() as u64, Some(BODY.len() as u64))),
        "the final observation must be the whole body against the declared total"
    );
}

#[test]
fn reports_no_total_when_the_server_declares_no_length() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let server = TestServer::serving_one_unmeasured(BODY);
    let seen = Observed::default();

    Downloader::new()
        .fetch(&server.url("/source.tar.gz"), &dest(&dir), seen.record())
        .expect("the download must succeed");

    assert_eq!(
        seen.last(),
        Some((BODY.len() as u64, None)),
        "a response without Content-Length must report bytes with no total"
    );
}

#[test]
fn a_hash_mismatch_fails_and_removes_the_file() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let dest = dest(&dir);
    let server = TestServer::serving_one(BODY);

    let error = Downloader::new()
        .fetch_verified(
            &server.url("/source.tar.gz"),
            &dest,
            &"0".repeat(64),
            |_, _| {},
        )
        .expect_err("a hash that does not match must fail the download");

    assert!(
        !dest.exists(),
        "a mismatched download must not be left behind for a later step to pick up"
    );
    let report = format!("{error:?}");
    assert!(
        report.contains("Hash mismatch"),
        "the diagnostic must name the problem: {report}"
    );
}

#[test]
fn a_matching_hash_is_accepted_case_insensitively() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let dest = dest(&dir);
    let server = TestServer::serving_one(BODY);

    Downloader::new()
        .fetch_verified(
            &server.url("/source.tar.gz"),
            &dest,
            &BODY_SHA256.to_uppercase(),
            |_, _| {},
        )
        .expect("an upper-case hash must verify against a lower-case digest");

    assert_eq!(read(&dest).expect("the file must exist"), BODY);
}

#[test]
fn an_error_status_fails_without_leaving_a_file() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let dest = dest(&dir);
    let server = TestServer::serving(HashMap::new());

    let error = Downloader::new()
        .fetch(&server.url("/source.tar.gz"), &dest, |_, _| {})
        .expect_err("a 404 must not be reported as a successful download");

    assert!(
        !dest.exists(),
        "a failed request must not leave a truncated file behind"
    );
    let report = format!("{error:?}");
    assert!(
        report.contains("404"),
        "the diagnostic must carry the status: {report}"
    );
}

#[test]
fn a_redirect_is_followed_to_the_body() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let dest = dest(&dir);
    // The shape every real mirror has: a stable URL that 302s to the file.
    let server = TestServer::serving(HashMap::from([
        (
            "/source.tar.gz".to_string(),
            Body::Redirect("/mirror/source.tar.gz".to_string()),
        ),
        (
            "/mirror/source.tar.gz".to_string(),
            Body::Measured(BODY.to_vec()),
        ),
    ]));

    let hash = Downloader::new()
        .fetch(&server.url("/source.tar.gz"), &dest, |_, _| {})
        .expect("a redirect must be followed rather than treated as the body");

    assert_eq!(read(&dest).expect("the file must exist"), BODY);
    assert_eq!(
        hash, BODY_SHA256,
        "the hash must cover the redirected-to body, not the 302"
    );
}

#[test]
fn a_redirect_loop_fails_instead_of_hanging() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let server = TestServer::serving(HashMap::from([
        (
            "/source.tar.gz".to_string(),
            Body::Redirect("/loop.tar.gz".to_string()),
        ),
        (
            "/loop.tar.gz".to_string(),
            Body::Redirect("/source.tar.gz".to_string()),
        ),
    ]));

    let error = Downloader::new()
        .with_max_redirects(4)
        .fetch(&server.url("/source.tar.gz"), &dest(&dir), |_, _| {})
        .expect_err("a redirect cycle must be reported, not followed forever");

    assert!(
        !format!("{error:?}").is_empty(),
        "the diagnostic must say something about the failure"
    );
}

#[test]
fn an_existing_file_is_replaced_rather_than_appended_to() {
    let dir = tempdir().expect("a temporary directory must be creatable");
    let dest = dest(&dir);
    write(&dest, b"stale contents from an earlier run").expect("the fixture must be writable");
    let server = TestServer::serving_one(BODY);

    Downloader::new()
        .fetch(&server.url("/source.tar.gz"), &dest, |_, _| {})
        .expect("the download must succeed");

    assert_eq!(
        read(&dest).expect("the file must exist"),
        BODY,
        "a re-download must truncate what was there, not append to it"
    );
}
