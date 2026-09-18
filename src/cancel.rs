//! A best-effort cancellation token threaded through a build.
//!
//! Nothing in this crate spawns a build it does not wait for **today** - but a
//! daemon relaying a client's disconnect will need to ask an in-flight build
//! to stop, without anything so heavy as killing the process that runs it.
//! [`Cancel`] is that ask: a cheap flag a caller holds one end of and a
//! scheduler polls the other end of.
//!
//! # This is best-effort
//!
//! Tripping the token stops [`crate::graph::Graph`] handing out a package that
//! has not started, and stops [`crate::download::Downloader`] writing another
//! chunk of a download in progress. It does **not** reach into a package
//! that is already mid-build: a step's subprocess keeps running to whatever
//! end it was going to reach, because nothing here kills it. Say only that
//! much, everywhere this type is used.

use std::sync::{
    Arc, Condvar, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

/// A cheap, clonable flag asking an in-flight build to stop starting new work.
///
/// Every clone refers to the same underlying flag, so a caller can keep one
/// handle to trip it while a scheduler holds another to poll it. Backed by an
/// [`AtomicBool`] rather than a `Mutex<bool>` because the only operations are
/// "set" and "read", neither of which needs to observe the other's timing
/// beyond what atomics already guarantee.
#[derive(Debug, Clone, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
    /// The condvar a scheduler worker parks on while it has no work, if one
    /// has been registered. Plain [`AtomicBool`] is invisible to a thread
    /// already asleep in [`Condvar::wait`]; nothing wakes it until *something*
    /// notifies the condvar it parked on. Wrapped in a `Mutex` only so
    /// [`Cancel::register_wakeup`] can be called after the token already
    /// exists, since the condvar it needs to point at is not created until
    /// the scheduler that owns it starts up.
    wakeup: Arc<Mutex<Option<Arc<Condvar>>>>,
}

impl Cancel {
    /// A token that has not been tripped.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trip the token, and wake whatever worker is parked on the condvar
    /// registered by [`Cancel::register_wakeup`], if any.
    ///
    /// Waking a worker that turns out to have nothing more to do costs one
    /// spurious loop iteration; leaving it asleep until something else
    /// happens to notify the same condvar could cost the rest of an unrelated
    /// package's build time.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        let registered = self.wakeup.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(condvar) = registered.as_ref() {
            condvar.notify_all();
        }
    }

    /// Whether [`Cancel::cancel`] has been called on this token or a clone of it.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Point this token at the condvar a scheduler's workers park on.
    ///
    /// Crate-private: [`crate::graph::Graph::build_with`] is the only caller,
    /// registering the very condvar its own workers wait on at the moment it
    /// creates it, so that a later [`Cancel::cancel`] can reach a worker that
    /// is already asleep rather than leaving it parked until an unrelated
    /// package happens to settle.
    pub(crate) fn register_wakeup(&self, condvar: Arc<Condvar>) {
        *self.wakeup.lock().unwrap_or_else(PoisonError::into_inner) = Some(condvar);
    }
}
