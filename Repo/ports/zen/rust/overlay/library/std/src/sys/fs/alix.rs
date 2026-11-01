//! Files backed by Alix's owned descriptors and checked libc/VFS boundary.
use crate::ffi::{CStr, CString, OsString};
use crate::fmt;
use crate::fs::TryLockError;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, SeekFrom};
use crate::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use crate::path::{Path, PathBuf};
use crate::ptr::NonNull;
use crate::sys::{AsInner, FromInner, IntoInner, cvt, ffi, unsupported};
use crate::sys::time::{SystemTime, UNIX_EPOCH};
use crate::time::Duration;
pub use crate::sys::fs::common::Dir;

fn with_path<T>(path: &Path, operation: impl FnOnce(&CStr) -> io::Result<T>) -> io::Result<T> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| io::Error::from_raw_os_error(22))?;
    operation(&path)
}
fn path_from_bytes(bytes: Vec<u8>) -> PathBuf {
    // Alix uses the same byte representation as this std's OsString backend.
    PathBuf::from(unsafe { OsString::from_encoded_bytes_unchecked(bytes) })
}
fn timestamp(seconds: u64) -> io::Result<SystemTime> {
    UNIX_EPOCH.checked_add_duration(&Duration::from_secs(seconds)).ok_or(io::Error::from_raw_os_error(75))
}

#[derive(Clone)]
pub struct FileAttr(ffi::Stat);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePermissions(u32);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileType(u32);
#[derive(Clone, Copy, Debug, Default)]
pub struct FileTimes { accessed: Option<SystemTime>, modified: Option<SystemTime> }
impl FileAttr {
    pub fn size(&self) -> u64 { self.0.size }
    pub fn perm(&self) -> FilePermissions { FilePermissions(self.0.mode) }
    pub fn file_type(&self) -> FileType { FileType(self.0.mode & 0o170000) }
    pub fn modified(&self) -> io::Result<SystemTime> { timestamp(self.0.modified) }
    pub fn accessed(&self) -> io::Result<SystemTime> { timestamp(self.0.accessed) }
    pub fn created(&self) -> io::Result<SystemTime> { unsupported() }
}
impl FilePermissions {
    pub fn readonly(&self) -> bool { self.0 & 0o222 == 0 }
    pub fn set_readonly(&mut self, readonly: bool) {
        if readonly { self.0 &= !0o222; } else { self.0 |= 0o222; }
    }
}
impl FileType {
    pub fn is_dir(&self) -> bool { self.0 == 0o040000 }
    pub fn is_file(&self) -> bool { self.0 == 0o100000 }
    pub fn is_symlink(&self) -> bool { self.0 == 0o120000 }
}
impl FileTimes {
    pub fn set_accessed(&mut self, value: SystemTime) { self.accessed = Some(value); }
    pub fn set_modified(&mut self, value: SystemTime) { self.modified = Some(value); }
}

pub struct FileDesc(OwnedFd);
impl AsInner<OwnedFd> for FileDesc { fn as_inner(&self) -> &OwnedFd { &self.0 } }
impl IntoInner<OwnedFd> for FileDesc { fn into_inner(self) -> OwnedFd { self.0 } }
impl FromInner<OwnedFd> for FileDesc { fn from_inner(fd: OwnedFd) -> Self { Self(fd) } }
impl AsRawFd for FileDesc { fn as_raw_fd(&self) -> RawFd { self.0.as_raw_fd() } }
impl IntoRawFd for FileDesc { fn into_raw_fd(self) -> RawFd { self.0.into_raw_fd() } }
impl AsFd for FileDesc { fn as_fd(&self) -> BorrowedFd<'_> { self.0.as_fd() } }
pub struct File(FileDesc);
impl AsInner<FileDesc> for File { fn as_inner(&self) -> &FileDesc { &self.0 } }
impl IntoInner<FileDesc> for File { fn into_inner(self) -> FileDesc { self.0 } }
impl FromInner<FileDesc> for File { fn from_inner(fd: FileDesc) -> Self { Self(fd) } }
impl AsRawFd for File { fn as_raw_fd(&self) -> RawFd { self.0.as_raw_fd() } }
impl AsFd for File { fn as_fd(&self) -> BorrowedFd<'_> { self.0.as_fd() } }
impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("File").field("fd", &self.as_raw_fd()).finish() }
}
#[derive(Clone, Debug, Default)]
pub struct OpenOptions { read: bool, write: bool, append: bool, truncate: bool, create: bool, create_new: bool }
impl OpenOptions {
    pub fn new() -> Self { Self::default() }
    pub fn read(&mut self, value: bool) { self.read = value; }
    pub fn write(&mut self, value: bool) { self.write = value; }
    pub fn append(&mut self, value: bool) { self.append = value; }
    pub fn truncate(&mut self, value: bool) { self.truncate = value; }
    pub fn create(&mut self, value: bool) { self.create = value; }
    pub fn create_new(&mut self, value: bool) { self.create_new = value; }
}
impl File {
    pub fn open(path: &Path, options: &OpenOptions) -> io::Result<Self> {
        let writable = options.write || options.append;
        if (!options.read && !writable) || ((options.create || options.create_new || options.truncate) && !writable) ||
            (options.append && options.truncate && !options.create_new) { return Err(io::Error::from_raw_os_error(22)); }
        // Alix access bits are READ=1 and WRITE=2, independently of another OS.
        let mut flags = u64::from(options.read) | (u64::from(writable) << 1) | (1 << 17);
        if options.append { flags |= 1 << 16; }
        if options.create_new { flags |= 4 | 16; }
        else {
            if options.create { flags |= 4; }
            if options.truncate { flags |= 8; }
        }
        with_path(path, |path| {
            let fd = cvt(unsafe { ffi::open(path.as_ptr(), flags) })?;
            Ok(Self(FileDesc(unsafe { OwnedFd::from_raw_fd(fd) })))
        })
    }
    pub fn file_attr(&self) -> io::Result<FileAttr> {
        let mut value = Box::new(ffi::Stat::default());
        cvt(unsafe { ffi::fstat(self.as_raw_fd(), &mut *value) })?;
        Ok(FileAttr(*value))
    }
    pub fn fsync(&self) -> io::Result<()> { cvt(unsafe { ffi::fsync(self.as_raw_fd()) }).map(|_| ()) }
    pub fn datasync(&self) -> io::Result<()> { self.fsync() }
    pub fn truncate(&self, size: u64) -> io::Result<()> {
        let size = i64::try_from(size).map_err(|_| io::Error::from_raw_os_error(22))?;
        cvt(unsafe { ffi::ftruncate(self.as_raw_fd(), size) }).map(|_| ())
    }
    pub fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        cvt(unsafe { ffi::read(self.as_raw_fd(), bytes.as_mut_ptr(), bytes.len()) }).map(|n| n as usize)
    }
    pub fn write(&self, bytes: &[u8]) -> io::Result<usize> {
        cvt(unsafe { ffi::write(self.as_raw_fd(), bytes.as_ptr(), bytes.len()) }).map(|n| n as usize)
    }
    pub fn read_vectored(&self, buffers: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        crate::io::default_read_vectored(|b| self.read(b), buffers)
    }
    pub fn write_vectored(&self, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        crate::io::default_write_vectored(|b| self.write(b), buffers)
    }
    pub fn is_read_vectored(&self) -> bool { false }
    pub fn is_write_vectored(&self) -> bool { false }
    pub fn read_buf(&self, cursor: BorrowedCursor<'_>) -> io::Result<()> {
        crate::io::default_read_buf(|bytes| self.read(bytes), cursor)
    }
    pub fn flush(&self) -> io::Result<()> { Ok(()) } // File has no userspace write buffer.
    pub fn seek(&self, position: SeekFrom) -> io::Result<u64> {
        let (offset, whence) = match position {
            SeekFrom::Start(value) => (i64::try_from(value).map_err(|_| io::Error::from_raw_os_error(22))?, 0),
            SeekFrom::Current(value) => (value, 1), SeekFrom::End(value) => (value, 2),
        };
        cvt(unsafe { ffi::lseek(self.as_raw_fd(), offset, whence) }).map(|n| n as u64)
    }
    pub fn tell(&self) -> io::Result<u64> { self.seek(SeekFrom::Current(0)) }
    pub fn size(&self) -> Option<io::Result<u64>> {
        match self.file_attr() { Ok(a) if !a.file_type().is_file() => None, value => Some(value.map(|a| a.size())) }
    }
    pub fn duplicate(&self) -> io::Result<Self> { self.0.0.try_clone().map(|fd| Self(FileDesc(fd))) }
    pub fn lock(&self) -> io::Result<()> { cvt(unsafe { ffi::flock(self.as_raw_fd(), 2) }).map(|_| ()) }
    pub fn lock_shared(&self) -> io::Result<()> { cvt(unsafe { ffi::flock(self.as_raw_fd(), 1) }).map(|_| ()) }
    fn try_flock(&self, operation: i32) -> Result<(), TryLockError> {
        cvt(unsafe { ffi::flock(self.as_raw_fd(), operation | 4) }).map(|_| ()).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock { TryLockError::WouldBlock } else { TryLockError::Error(error) }
        })
    }
    pub fn try_lock(&self) -> Result<(), TryLockError> { self.try_flock(2) }
    pub fn try_lock_shared(&self) -> Result<(), TryLockError> { self.try_flock(1) }
    pub fn unlock(&self) -> io::Result<()> { cvt(unsafe { ffi::flock(self.as_raw_fd(), 8) }).map(|_| ()) }
    pub fn set_permissions(&self, _: FilePermissions) -> io::Result<()> { unsupported() }
    pub fn set_times(&self, _: FileTimes) -> io::Result<()> { unsupported() }
}

pub struct ReadDir { directory: NonNull<ffi::DIR>, root: PathBuf, done: bool }
unsafe impl Send for ReadDir {}
unsafe impl Sync for ReadDir {}
impl Drop for ReadDir { fn drop(&mut self) { unsafe { ffi::closedir(self.directory.as_ptr()); } } }
impl fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("ReadDir").field("root", &self.root).finish() }
}
pub struct DirEntry { root: PathBuf, name: OsString, kind: u8 }
impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done { return None; }
        loop {
            unsafe { *ffi::__errno_location() = 0; }
            let entry = unsafe { ffi::readdir(self.directory.as_ptr()) };
            if entry.is_null() {
                self.done = true;
                let error = unsafe { *ffi::__errno_location() };
                return if error == 0 { None } else { Some(Err(io::Error::from_raw_os_error(error))) };
            }
            let bytes = unsafe { CStr::from_ptr((*entry).name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            return Some(Ok(DirEntry { root: self.root.clone(),
                name: unsafe { OsString::from_encoded_bytes_unchecked(bytes.to_vec()) }, kind: unsafe { (*entry).kind } }));
        }
    }
}
impl DirEntry {
    pub fn path(&self) -> PathBuf { self.root.join(&self.name) }
    pub fn file_name(&self) -> OsString { self.name.clone() }
    pub fn metadata(&self) -> io::Result<FileAttr> { lstat(&self.path()) }
    pub fn file_type(&self) -> io::Result<FileType> {
        match self.kind { 4 => Ok(FileType(0o040000)), 8 => Ok(FileType(0o100000)),
            10 => Ok(FileType(0o120000)), 6 => Ok(FileType(0o060000)), _ => self.metadata().map(|a| a.file_type()) }
    }
}
#[derive(Debug)]
pub struct DirBuilder;
impl DirBuilder {
    pub fn new() -> Self { Self }
    pub fn mkdir(&self, path: &Path) -> io::Result<()> { with_path(path, |p| cvt(unsafe { ffi::mkdir(p.as_ptr(), 0o777) }).map(|_| ())) }
}
pub fn readdir(path: &Path) -> io::Result<ReadDir> {
    with_path(path, |p| {
        let directory = NonNull::new(unsafe { ffi::opendir(p.as_ptr()) }).ok_or_else(io::Error::last_os_error)?;
        Ok(ReadDir { directory, root: path.to_path_buf(), done: false })
    })
}
pub fn unlink(path: &Path) -> io::Result<()> { with_path(path, |p| cvt(unsafe { ffi::unlink(p.as_ptr()) }).map(|_| ())) }
pub fn rmdir(path: &Path) -> io::Result<()> { with_path(path, |p| cvt(unsafe { ffi::rmdir(p.as_ptr()) }).map(|_| ())) }
pub fn rename(old: &Path, new: &Path) -> io::Result<()> {
    with_path(old, |a| with_path(new, |b| cvt(unsafe { ffi::rename(a.as_ptr(), b.as_ptr()) }).map(|_| ())))
}
fn metadata(path: &Path, follow: bool) -> io::Result<FileAttr> {
    with_path(path, |p| {
        let mut value = Box::new(ffi::Stat::default());
        cvt(unsafe { if follow { ffi::stat(p.as_ptr(), &mut *value) } else { ffi::lstat(p.as_ptr(), &mut *value) } })?;
        Ok(FileAttr(*value))
    })
}
pub fn stat(path: &Path) -> io::Result<FileAttr> { metadata(path, true) }
pub fn lstat(path: &Path) -> io::Result<FileAttr> { metadata(path, false) }
pub fn exists(path: &Path) -> io::Result<bool> { crate::sys::fs::common::exists(path) }
pub fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    with_path(path, |p| {
        let value = unsafe { ffi::realpath(p.as_ptr(), crate::ptr::null_mut()) };
        if value.is_null() { return Err(io::Error::last_os_error()); }
        let bytes = unsafe { CStr::from_ptr(value) }.to_bytes().to_vec();
        unsafe { ffi::free(value.cast()); }
        Ok(path_from_bytes(bytes))
    })
}
pub fn readlink(path: &Path) -> io::Result<PathBuf> {
    with_path(path, |p| {
        let mut bytes = vec![0u8; 4096];
        let count = cvt(unsafe { ffi::readlink(p.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) })? as usize;
        if count >= bytes.len() { return Err(io::Error::from_raw_os_error(36)); }
        bytes.truncate(count); Ok(path_from_bytes(bytes))
    })
}
// Native support for these operations requires additional VFS contracts.
// Do not substitute a path-recursive deletion that can follow a raced symlink.
pub fn remove_dir_all(_: &Path) -> io::Result<()> { unsupported() }
pub fn copy(_: &Path, _: &Path) -> io::Result<u64> { unsupported() }
pub fn symlink(_: &Path, _: &Path) -> io::Result<()> { unsupported() }
pub fn link(_: &Path, _: &Path) -> io::Result<()> { unsupported() }
pub fn set_perm(_: &Path, _: FilePermissions) -> io::Result<()> { unsupported() }
pub fn set_times(_: &Path, _: FileTimes) -> io::Result<()> { unsupported() }
pub fn set_times_nofollow(_: &Path, _: FileTimes) -> io::Result<()> { unsupported() }
