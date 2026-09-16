//! Measures the argv construction in `Step::execute`, before and after the
//! `collect()` was dropped.
//!
//! Both variants end up building the same [`Command`], so the only difference
//! the timer sees is the intermediate allocations the old shape needed.

use std::process::Command;

use divan::{Bencher, black_box};

fn main() {
    divan::main();
}

/// Representative `run:` lines from a build file: a bare invocation, a typical
/// autotools configure and a long cargo command.
const COMMANDS: &[&str] = &[
    "make install",
    "./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-static",
    "cargo build --release --locked --offline --target x86_64-unknown-linux-gnu --features a,b,c",
];

/// The old shape: every word becomes an owned `String` inside a `Vec`, the
/// program name is cloned back out, and `to_vec` copies the tail a second time.
#[divan::bench(args = COMMANDS)]
fn collect_into_vec(bencher: Bencher, cmd: &str) {
    bencher.bench(|| {
        let split: Vec<String> = black_box(cmd)
            .split_whitespace()
            .map(std::convert::Into::into)
            .collect();
        let mut command = Command::new(split[0].clone());
        command.args(split[1..split.len()].to_vec());
        black_box(command)
    });
}

/// The new shape: `args` consumes the `SplitWhitespace` borrows directly, so
/// nothing is allocated on the way in.
#[divan::bench(args = COMMANDS)]
fn lazy_split(bencher: Bencher, cmd: &str) {
    bencher.bench(|| {
        let mut words = black_box(cmd).split_whitespace();
        let mut command = Command::new(words.next().unwrap_or_default());
        command.args(words);
        black_box(command)
    });
}
