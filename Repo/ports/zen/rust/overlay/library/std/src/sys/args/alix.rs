pub use super::common::Args;
use crate::ffi::{CStr, OsString};
use crate::sync::Mutex;

static ARGS: Mutex<Option<Vec<OsString>>> = Mutex::new(None);

pub unsafe fn init(argc: isize, argv: *const *const u8) {
    let mut arguments = Vec::new();
    if argc > 0 && !argv.is_null() {
        for index in 0..argc {
            let pointer = unsafe { *argv.offset(index) };
            if pointer.is_null() { break; }
            let bytes = unsafe { CStr::from_ptr(pointer.cast()) }.to_bytes().to_vec();
            // Alix's OsStr representation is lossless bytes.
            arguments.push(unsafe { OsString::from_encoded_bytes_unchecked(bytes) });
        }
    }
    // CRT argv may live on the initial thread's stack. Retain only owned heap
    // copies so another thread never reads that thread's stack through ARGS.
    *ARGS.lock().unwrap_or_else(|error| error.into_inner()) = Some(arguments);
}
pub fn args() -> Args {
    let guard = ARGS.lock().unwrap_or_else(|error| error.into_inner());
    Args::new(guard.as_ref().cloned().unwrap_or_default())
}
