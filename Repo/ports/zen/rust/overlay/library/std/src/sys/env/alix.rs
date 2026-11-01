//! Owned snapshots share the native C environment lock with C/Rust writers.
pub use super::common::Env;
use crate::ffi::{CStr, CString, OsStr, OsString};
use crate::io;
use crate::os::alix::ffi::{OsStrExt, OsStringExt};
use crate::sys::{cvt, ffi};

struct Snapshot(*mut *mut ffi::c_char);
impl Snapshot {
    fn new() -> Self {
        let value = unsafe { ffi::alix_environment_copy() };
        if value.is_null() {
            // These public std APIs cannot return an allocation error. Match
            // Vec's allocation-failure behavior instead of inventing absence.
            crate::alloc::handle_alloc_error(crate::alloc::Layout::new::<usize>());
        }
        Self(value)
    }
    fn entries(&self) -> impl Iterator<Item = &[u8]> {
        let mut cursor = self.0;
        crate::iter::from_fn(move || {
            let value = unsafe { *cursor };
            if value.is_null() { return None; }
            cursor = unsafe { cursor.add(1) };
            Some(unsafe { CStr::from_ptr(value) }.to_bytes())
        })
    }
}
impl Drop for Snapshot { fn drop(&mut self) { unsafe { ffi::alix_environment_free(self.0); } } }

pub fn env() -> Env {
    let snapshot = Snapshot::new();
    let values = snapshot.entries().filter_map(|bytes| {
        let split = bytes.iter().position(|byte| *byte == b'=')?;
        if split == 0 { return None; }
        Some((OsString::from_vec(bytes[..split].to_vec()), OsString::from_vec(bytes[split + 1..].to_vec())))
    }).collect();
    Env::new(values)
}
pub fn getenv(key: &OsStr) -> Option<OsString> {
    let key = key.as_bytes();
    if key.is_empty() || key.contains(&0) || key.contains(&b'=') { return None; }
    let snapshot = Snapshot::new();
    snapshot.entries().find_map(|bytes| {
        if bytes.len() > key.len() && &bytes[..key.len()] == key && bytes[key.len()] == b'=' {
            Some(OsString::from_vec(bytes[key.len() + 1..].to_vec()))
        } else { None }
    })
}
pub unsafe fn setenv(key: &OsStr, value: &OsStr) -> io::Result<()> {
    let key = CString::new(key.as_bytes()).map_err(|_| io::Error::from_raw_os_error(22))?;
    let value = CString::new(value.as_bytes()).map_err(|_| io::Error::from_raw_os_error(22))?;
    cvt(unsafe { ffi::setenv(key.as_ptr(), value.as_ptr(), 1) }).map(|_| ())
}
pub unsafe fn unsetenv(key: &OsStr) -> io::Result<()> {
    let key = CString::new(key.as_bytes()).map_err(|_| io::Error::from_raw_os_error(22))?;
    cvt(unsafe { ffi::unsetenv(key.as_ptr()) }).map(|_| ())
}
