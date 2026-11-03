use crate::ffi::OsString;
use crate::io;
use crate::os::alix::ffi::OsStringExt;
use crate::sys::{cvt,net_ffi};
pub fn hostname()->io::Result<OsString>{
    let mut bytes=crate::vec![0u8;65];
    cvt(unsafe{net_ffi::gethostname(bytes.as_mut_ptr(),bytes.len())})?;
    let end=bytes.iter().position(|b|*b==0).ok_or_else(||io::const_error!(io::ErrorKind::InvalidData,"unterminated hostname"))?;
    bytes.truncate(end);Ok(OsString::from_vec(bytes))
}
