use crate::ffi::CStr;
use crate::io::ErrorKind;
use crate::sys::ffi;

pub fn errno() -> i32 { unsafe { *ffi::__errno_location() } }
pub fn is_interrupted(code: i32) -> bool { code == 4 }
pub fn decode_error_kind(code: i32) -> ErrorKind {
    match code {
        1 | 13 => ErrorKind::PermissionDenied,
        2 => ErrorKind::NotFound,
        4 => ErrorKind::Interrupted,
        11 => ErrorKind::WouldBlock,
        12 => ErrorKind::OutOfMemory,
        17 => ErrorKind::AlreadyExists,
        20 => ErrorKind::NotADirectory,
        21 => ErrorKind::IsADirectory,
        22 => ErrorKind::InvalidInput,
        28 => ErrorKind::StorageFull,
        32 => ErrorKind::BrokenPipe,
        38 | 95 => ErrorKind::Unsupported,
        110 => ErrorKind::TimedOut,
        111 => ErrorKind::ConnectionRefused,
        _ => ErrorKind::Uncategorized,
    }
}
pub fn error_string(code: i32) -> String {
    unsafe { CStr::from_ptr(ffi::strerror(code)) }.to_string_lossy().into_owned()
}
