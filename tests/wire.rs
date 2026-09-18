//! Freezes the D-Bus signature of every type in [`pm::wire::types`] as a
//! string literal, and exercises [`pm::wire::frame`]'s length-prefixed
//! framing.
//!
//! A signature assertion here is the point of this module: if a field is
//! ever reordered, added or retyped, one of these fails before a client
//! mis-decodes a live message instead of after.

use std::io::Cursor;

use pm::wire::{
    frame::{MAX_FRAME, read_frame, write_frame},
    types::{CallerContext, Diagnostic, JobRow, LogLine, Observation, PackageOutcome, ProgressNode},
};
use zbus::zvariant::Type;

#[test]
fn caller_context_signature_is_frozen() {
    assert_eq!(
        <CallerContext as Type>::SIGNATURE.to_string(),
        "(sssss)",
        "CallerContext: cwd, output_dir, trust_dir, path, home, all String"
    );
}

#[test]
fn diagnostic_signature_is_frozen() {
    assert_eq!(
        <Diagnostic as Type>::SIGNATURE.to_string(),
        "(sssas)",
        "Diagnostic: name, message, help are String, causes is Vec<String>"
    );
}

#[test]
fn progress_node_signature_is_frozen() {
    // VERIFIED against a probe crate with this exact field order: u32, u32,
    // u32, String, u8, String, u64, u64, u64.
    assert_eq!(
        <ProgressNode as Type>::SIGNATURE.to_string(),
        "(uuusysttt)",
        "ProgressNode: id, parent, depth, label, kind, text, done, total, started_usec"
    );
}

#[test]
fn log_line_signature_is_frozen() {
    assert_eq!(
        <LogLine as Type>::SIGNATURE.to_string(),
        "(tys)",
        "LogLine: seq (u64), stream (u8), text (String)"
    );
}

#[test]
fn job_row_signature_is_frozen() {
    assert_eq!(
        <JobRow as Type>::SIGNATURE.to_string(),
        "(ossssxxi)",
        "JobRow: path (o), id/kind/state/subject (String), created_usec/finished_usec (i64), exit_code (i32)"
    );
}

#[test]
fn observation_signature_is_frozen() {
    assert_eq!(
        <Observation as Type>::SIGNATURE.to_string(),
        "(sisssbbs)",
        "Observation: syscall (s), pid (i), permission/label/path (s), resolved/succeeded (b), evidence (s)"
    );
}

#[test]
fn package_outcome_signature_is_frozen() {
    assert_eq!(
        <PackageOutcome as Type>::SIGNATURE.to_string(),
        "(ssss)",
        "PackageOutcome: name, outcome, archive, error, all String"
    );
}

#[test]
fn a_frame_round_trips_through_write_and_read() {
    let mut buffer = Cursor::new(Vec::new());
    write_frame(&mut buffer, b"hello, worker").expect("a small frame must write");

    buffer.set_position(0);
    let payload = read_frame(&mut buffer).expect("a frame just written must read back");

    assert_eq!(payload, b"hello, worker");
}

#[test]
fn an_empty_frame_round_trips() {
    let mut buffer = Cursor::new(Vec::new());
    write_frame(&mut buffer, b"").expect("an empty frame must write");

    buffer.set_position(0);
    let payload = read_frame(&mut buffer).expect("an empty frame must read back");

    assert!(payload.is_empty());
}

#[test]
fn a_payload_over_the_limit_is_rejected_on_write() {
    // Building an actual `MAX_FRAME + 1`-byte buffer just to prove this would
    // spend real time and memory on every test run for no extra coverage:
    // `write_frame` checks the length before ever touching `writer`, so a
    // cheap zero-filled buffer exercises the exact same branch.
    let oversized = vec![0u8; (MAX_FRAME as usize) + 1];
    let mut sink = Cursor::new(Vec::new());

    let result = write_frame(&mut sink, &oversized);

    assert!(result.is_err(), "a payload over MAX_FRAME must be rejected");
    assert!(
        sink.get_ref().is_empty(),
        "a rejected frame must not have written a partial length prefix"
    );
}

#[test]
fn a_declared_length_over_the_limit_is_rejected_on_read() {
    let mut bogus = Vec::new();
    bogus.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
    let mut reader = Cursor::new(bogus);

    let result = read_frame(&mut reader);

    assert!(
        result.is_err(),
        "a frame claiming to be over MAX_FRAME must be rejected before allocating for it"
    );
}

#[test]
fn reading_past_a_truncated_frame_is_an_error_not_a_panic() {
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&100u32.to_be_bytes());
    truncated.extend_from_slice(b"not enough bytes");
    let mut reader = Cursor::new(truncated);

    let result = read_frame(&mut reader);

    assert!(result.is_err(), "a short read must be an error, not a hang or a panic");
}
