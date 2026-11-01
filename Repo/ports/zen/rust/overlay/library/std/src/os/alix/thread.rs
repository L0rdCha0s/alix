//! Native pthread handle access for Alix's Rust threads.
#![stable(feature = "alix_thread_extensions", since = "1.97.1")]

use crate::sys::{AsInner, IntoInner};
use crate::thread::JoinHandle;

/// Alix's native 64-bit pthread identifier, matching its C pthread_t ABI.
#[stable(feature = "alix_thread_extensions", since = "1.97.1")]
pub type RawPthread = u64;

/// Access to a Rust thread's actual Alix pthread.
#[stable(feature = "alix_thread_extensions", since = "1.97.1")]
pub trait JoinHandleExt {
    /// Borrow the native pthread identifier while retaining Rust ownership.
    #[stable(feature = "alix_thread_extensions", since = "1.97.1")]
    fn as_pthread_t(&self) -> RawPthread;

    /// Transfer ownership of the native pthread to the caller.
    ///
    /// The caller must join or detach it with Alix's pthread API. The Rust
    /// closure's return value is not returned by pthread_join.
    #[stable(feature = "alix_thread_extensions", since = "1.97.1")]
    fn into_pthread_t(self) -> RawPthread;
}

#[stable(feature = "alix_thread_extensions", since = "1.97.1")]
impl<T> JoinHandleExt for JoinHandle<T> {
    fn as_pthread_t(&self) -> RawPthread { self.as_inner().id() }
    fn into_pthread_t(self) -> RawPthread { self.into_inner().into_id() }
}
