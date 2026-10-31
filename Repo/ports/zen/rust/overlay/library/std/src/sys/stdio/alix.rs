use crate::io::{self, IoSlice, IoSliceMut};
use crate::sys::ffi;

pub struct Stdin;
pub struct Stdout;
pub struct Stderr;
impl Stdin { pub const fn new() -> Self { Self } }
impl Stdout { pub const fn new() -> Self { Self } }
impl Stderr { pub const fn new() -> Self { Self } }

fn result(value: isize) -> io::Result<usize> {
    if value < 0 { Err(io::Error::from_raw_os_error(5)) } else { Ok(value as usize) }
}
impl io::Read for Stdin {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        result(unsafe { ffi::sys_read(0, bytes.as_mut_ptr(), bytes.len()) })
    }
    fn read_vectored(&mut self, buffers: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match buffers.iter_mut().find(|buffer| !buffer.is_empty()) {
            Some(buffer) => self.read(buffer), None => Ok(0),
        }
    }
    fn is_read_vectored(&self) -> bool { false }
}
macro_rules! output {
    ($name:ident, $fd:expr) => {
        impl io::Write for $name {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                result(unsafe { ffi::sys_write($fd, bytes.as_ptr(), bytes.len()) })
            }
            fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
                match buffers.iter().find(|buffer| !buffer.is_empty()) {
                    Some(buffer) => self.write(buffer), None => Ok(0),
                }
            }
            fn is_write_vectored(&self) -> bool { false }
            // Writes are synchronous in the native syscall interface.
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
    }
}
output!(Stdout, 1);
output!(Stderr, 2);
pub const STDIN_BUF_SIZE: usize = 8192;
pub fn is_ebadf(error: &io::Error) -> bool { error.raw_os_error() == Some(9) }
pub fn panic_output() -> Option<impl io::Write> { Some(Stderr::new()) }
