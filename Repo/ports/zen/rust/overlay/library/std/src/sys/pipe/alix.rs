#![unstable(feature = "std_internals", issue = "none")]
use crate::fmt;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, Read};
use crate::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use crate::sys::{FromInner, IntoInner, cvt, ffi};

pub struct Pipe(OwnedFd);
pub fn pipe() -> io::Result<(Pipe, Pipe)> {
    let mut pair = Box::new([0i32; 2]);
    cvt(unsafe { ffi::pipe2(pair.as_mut_ptr(), 1 << 17) })?;
    Ok((Pipe(unsafe { OwnedFd::from_raw_fd(pair[0]) }), Pipe(unsafe { OwnedFd::from_raw_fd(pair[1]) })))
}
impl Pipe {
    pub fn try_clone(&self) -> io::Result<Self> { self.0.try_clone().map(Self) }
    pub fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        cvt(unsafe { ffi::read(self.as_raw_fd(), bytes.as_mut_ptr(), bytes.len()) }).map(|n| n as usize)
    }
    pub fn write(&self, bytes: &[u8]) -> io::Result<usize> {
        cvt(unsafe { ffi::write(self.as_raw_fd(), bytes.as_ptr(), bytes.len()) }).map(|n| n as usize)
    }
    pub fn read_buf(&self, cursor: BorrowedCursor<'_>) -> io::Result<()> { io::default_read_buf(|b| self.read(b), cursor) }
    pub fn read_vectored(&self, buffers: &mut [IoSliceMut<'_>]) -> io::Result<usize> { io::default_read_vectored(|b| self.read(b), buffers) }
    pub fn write_vectored(&self, buffers: &[IoSlice<'_>]) -> io::Result<usize> { io::default_write_vectored(|b| self.write(b), buffers) }
    pub fn is_read_vectored(&self) -> bool { false }
    pub fn is_write_vectored(&self) -> bool { false }
    pub fn read_to_end(&self, bytes: &mut Vec<u8>) -> io::Result<usize> {
        let mut reader = self;
        io::default_read_to_end(&mut reader, bytes, None)
    }
}
impl Read for &Pipe { fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> { Pipe::read(self, bytes) } }
impl AsRawFd for Pipe { fn as_raw_fd(&self) -> RawFd { self.0.as_raw_fd() } }
impl IntoRawFd for Pipe { fn into_raw_fd(self) -> RawFd { self.0.into_raw_fd() } }
impl AsFd for Pipe { fn as_fd(&self) -> BorrowedFd<'_> { self.0.as_fd() } }
impl FromRawFd for Pipe { unsafe fn from_raw_fd(fd: RawFd) -> Self { Self(unsafe { OwnedFd::from_raw_fd(fd) }) } }
impl FromInner<OwnedFd> for Pipe { fn from_inner(fd: OwnedFd) -> Self { Self(fd) } }
impl IntoInner<OwnedFd> for Pipe { fn into_inner(self) -> OwnedFd { self.0 } }
impl fmt::Debug for Pipe { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_tuple("Pipe").field(&self.0).finish() } }
