//! Native Alix platform services. No Linux ABI or host runtime is assumed.
#![allow(unsafe_op_in_unsafe_fn)]

pub mod ffi;
pub mod net_ffi;
pub mod futex;

pub unsafe fn init(argc: isize, argv: *const *const u8, _sigpipe: u8) {
    unsafe { crate::sys::args::init(argc, argv) };
}

pub unsafe fn cleanup() {}

pub fn unsupported<T>() -> crate::io::Result<T> { Err(unsupported_err()) }
pub fn unsupported_err() -> crate::io::Error { crate::io::Error::UNSUPPORTED_PLATFORM }
pub fn abort_internal() -> ! { unsafe { ffi::abort() } }

pub trait IsMinusOne: Sized { fn is_minus_one(&self) -> bool; }
macro_rules! minus_one {
    ($($t:ty),*) => {$(impl IsMinusOne for $t { fn is_minus_one(&self) -> bool { *self == -1 } })*};
}
minus_one!(i32, i64, isize);
pub fn cvt<T: IsMinusOne>(value: T) -> crate::io::Result<T> {
    if value.is_minus_one() { Err(crate::io::Error::last_os_error()) } else { Ok(value) }
}
