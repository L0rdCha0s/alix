//! Native Alix namespace and colon-separated PATH conventions.
use crate::ffi::{CStr, CString, OsStr, OsString};
use crate::os::alix::ffi::{OsStrExt, OsStringExt};
use crate::path::{Path, PathBuf};
use crate::sys::{cvt, ffi};
use crate::{fmt, io, iter, ptr, slice};

pub fn getcwd() -> io::Result<PathBuf> {
    let mut bytes = vec![0u8; 4096];
    if unsafe { ffi::getcwd(bytes.as_mut_ptr().cast(), bytes.len()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    let length = unsafe { CStr::from_ptr(bytes.as_ptr().cast()) }.to_bytes().len();
    bytes.truncate(length); Ok(PathBuf::from(OsString::from_vec(bytes)))
}
pub fn chdir(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(22))?;
    cvt(unsafe { ffi::chdir(path.as_ptr()) }).map(|_| ())
}
pub type SplitPaths<'a> = iter::Map<slice::Split<'a, u8, fn(&u8) -> bool>, fn(&[u8]) -> PathBuf>;
pub fn split_paths(value: &OsStr) -> SplitPaths<'_> {
    fn separator(byte: &u8) -> bool { *byte == b':' }
    fn part(bytes: &[u8]) -> PathBuf { PathBuf::from(OsStr::from_bytes(bytes)) }
    value.as_bytes().split(separator as fn(&u8) -> bool).map(part as fn(&[u8]) -> PathBuf)
}
#[derive(Debug)]
pub struct JoinPathsError;
pub fn join_paths<I, T>(paths: I) -> Result<OsString, JoinPathsError>
where I: Iterator<Item = T>, T: AsRef<OsStr> {
    let mut bytes = Vec::new();
    for (index, path) in paths.enumerate() {
        let path = path.as_ref().as_bytes();
        if path.contains(&b':') { return Err(JoinPathsError); }
        if index != 0 { bytes.push(b':'); }
        bytes.extend_from_slice(path);
    }
    Ok(OsString::from_vec(bytes))
}
impl fmt::Display for JoinPathsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("path segment contains separator `:`") }
}
impl crate::error::Error for JoinPathsError {}
pub fn current_exe() -> io::Result<PathBuf> {
    let mut bytes = vec![0u8; 4096];
    let length = cvt(unsafe { ffi::alix_get_executable_path(bytes.as_mut_ptr().cast(), bytes.len()) })? as usize;
    if length >= bytes.len() { return Err(io::Error::from_raw_os_error(36)); }
    bytes.truncate(length); Ok(PathBuf::from(OsString::from_vec(bytes)))
}
pub fn temp_dir() -> PathBuf { crate::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp")) }
pub fn home_dir() -> Option<PathBuf> {
    if let Some(home) = crate::env::var_os("HOME").filter(|home| !home.is_empty()) { return Some(home.into()); }
    let mut capacity = 1024;
    while capacity <= 128 * 1024 {
        let mut bytes = vec![0u8; capacity];
        let mut entry = Box::new(ffi::Passwd { name: ptr::null_mut(), password: ptr::null_mut(),
            uid: 0, gid: 0, gecos: ptr::null_mut(), directory: ptr::null_mut(), shell: ptr::null_mut() });
        let mut result = Box::new(ptr::null_mut());
        let status = unsafe { ffi::getpwuid_r(ffi::getuid(), &mut *entry, bytes.as_mut_ptr().cast(), capacity, &mut *result) };
        if status == 34 { capacity *= 2; continue; }
        if status != 0 || result.is_null() || entry.directory.is_null() { return None; }
        let home = unsafe { CStr::from_ptr(entry.directory) }.to_bytes();
        if home.is_empty() { return None; }
        return Some(PathBuf::from(OsString::from_vec(home.to_vec())));
    }
    None
}
