//! Bounded, ordered parallel work for plugin integrations.
//!
//! [`Parallelism`] owns a Rayon pool and offers channels for submitting work whose
//! results are consumed independently. Its ordered map is useful for batches of
//! independent plugin calls: work may finish in any order, while results retain their
//! input order.

use std::{
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
};

use rayon::prelude::*;

/// A Rayon worker pool and channel-backed task API for plugin integrations.
///
/// Give an instance to [`super::Registry::classify_parallel`] or
/// [`super::Registry::scan_source_parallel`] to run independent plugin calls
/// concurrently. Each task has its own channel, and ordered map operations preserve
/// submission order in their returned values.
#[derive(Clone)]
pub struct Parallelism {
    pool: Arc<rayon::ThreadPool>,
}

impl Parallelism {
    /// Create a worker pool with the requested non-zero number of workers.
    ///
    /// # Errors
    ///
    /// Returns the Rayon pool construction error.
    pub fn new(threads: NonZeroUsize) -> std::result::Result<Self, rayon::ThreadPoolBuildError> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads.get())
            .build()?;
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    /// The number of workers in this pool.
    #[must_use]
    pub fn threads(&self) -> usize {
        self.pool.current_num_threads()
    }

    /// Create a standard multi-producer, single-consumer channel.
    #[must_use]
    pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
        mpsc::channel()
    }

    /// Schedule one task and return a channel that receives its result.
    ///
    /// If `task` panics, its sender is dropped and `recv` reports disconnection.
    pub fn spawn<T, F>(&self, task: F) -> Receiver<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.pool.spawn(move || {
            // Rayon aborts the process on a panic that escapes a `spawn`ed task. Catch
            // it here so a panicking task only drops its sender: `recv` still reports
            // disconnection, as the docs promise, and one bad plugin cannot take the
            // whole build down.
            if let Ok(value) = catch_unwind(AssertUnwindSafe(task)) {
                let _ = sender.send(value);
            }
        });
        receiver
    }

    /// Apply `task` to each item in parallel, returning results in input order.
    pub fn map<T, R, F>(&self, items: &[T], task: F) -> Vec<R>
    where
        T: Sync,
        R: Send,
        F: Fn(&T) -> R + Sync + Send,
    {
        self.pool.install(|| items.par_iter().map(task).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::Parallelism;

    #[test]
    fn maps_in_parallel_and_keeps_input_order() {
        let parallelism = Parallelism::new(NonZeroUsize::new(2).expect("non-zero worker count"))
            .expect("create worker pool");
        let output = parallelism.map(&[3, 1, 2], |value| value * 2);

        assert_eq!(output, [6, 2, 4]);
    }

    #[test]
    fn spawned_work_returns_its_result_over_a_channel() {
        let parallelism = Parallelism::new(NonZeroUsize::new(1).expect("non-zero worker count"))
            .expect("create worker pool");
        let result = parallelism
            .spawn(|| 42)
            .recv()
            .expect("task sends its result");

        assert_eq!(result, 42);
    }

    #[test]
    fn a_panicking_task_disconnects_instead_of_aborting() {
        let parallelism = Parallelism::new(NonZeroUsize::new(1).expect("non-zero worker count"))
            .expect("create worker pool");
        let receiver = parallelism.spawn(|| -> i32 { panic!("task panicked") });

        assert!(
            receiver.recv().is_err(),
            "a panicking task drops its sender, so recv reports disconnection"
        );
    }

    #[test]
    fn exposes_a_multi_producer_channel() {
        let (sender, receiver) = Parallelism::channel();
        sender.send("result").expect("receiver is open");

        assert_eq!(receiver.recv().expect("sender sent a value"), "result");
    }
}
