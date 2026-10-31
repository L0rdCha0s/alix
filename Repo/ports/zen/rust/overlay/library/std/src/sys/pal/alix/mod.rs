//! Native Alix platform services. No Linux ABI or host runtime is assumed.
#![allow(unsafe_op_in_unsafe_fn)]

pub mod ffi;
pub mod futex;

pub unsafe fn init(argc: isize, argv: *const *const u8, _sigpipe: u8) {
    unsafe { crate::sys::args::init(argc, argv) };
}

pub unsafe fn cleanup() {}

pub fn unsupported<T>() -> crate::io::Result<T> { Err(unsupported_err()) }
pub fn unsupported_err() -> crate::io::Error { crate::io::Error::UNSUPPORTED_PLATFORM }
pub fn abort_internal() -> ! { unsafe { ffi::abort() } }
