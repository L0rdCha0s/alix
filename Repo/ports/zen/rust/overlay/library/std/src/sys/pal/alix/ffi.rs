//! ABI declarations for Alix's own libc and int-0x80 syscall wrappers.
#![allow(dead_code)]
pub use crate::ffi::{c_char, c_int, c_void};

pub const STDIN_FILENO: c_int = 0;
pub const STDOUT_FILENO: c_int = 1;
pub const STDERR_FILENO: c_int = 2;
pub const F_DUPFD_CLOEXEC: c_int = 1030;
pub const F_DUPFD: c_int = 0;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stat {
    pub size: u64, pub mode: u32, pub kind: u32,
    pub accessed: u64, pub modified: u64, pub changed: u64,
}
#[repr(C)]
pub struct Dirent { pub inode: u64, pub kind: u8, pub name: [c_char; 4096] }
pub enum DIR {}
#[repr(C)]
pub struct Passwd {
    pub name: *mut c_char, pub password: *mut c_char,
    pub uid: u32, pub gid: u32, pub gecos: *mut c_char,
    pub directory: *mut c_char, pub shell: *mut c_char,
}
const _: () = assert!(crate::mem::size_of::<Stat>() == 40);
const _: () = assert!(crate::mem::size_of::<Dirent>() == 4112);
const _: () = assert!(crate::mem::size_of::<Passwd>() == 48);
const _: () = assert!(crate::mem::offset_of!(Passwd, directory) == 32);

pub type pthread_t = u64;
#[repr(C)]
pub struct pthread_attr_t {
    pub stack_size: usize,
    pub guard_size: usize,
    pub stack_address: *mut c_void,
    pub detach_state: c_int,
    pub magic: u32,
}
const _: () = assert!(crate::mem::size_of::<pthread_attr_t>() == 32);
const _: () = assert!(crate::mem::align_of::<pthread_attr_t>() == 8);

unsafe extern "C" {
    pub fn alix_environment_copy() -> *mut *mut c_char;
    pub fn alix_environment_free(environment: *mut *mut c_char);
    pub fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    pub fn unsetenv(name: *const c_char) -> c_int;
    pub fn getcwd(buffer: *mut c_char, capacity: usize) -> *mut c_char;
    pub fn alix_get_executable_path(buffer: *mut c_char, capacity: usize) -> isize;
    pub fn chdir(path: *const c_char) -> c_int;
    pub fn getuid() -> u32;
    pub fn getpwuid_r(uid: u32, entry: *mut Passwd, buffer: *mut c_char,
                      capacity: usize, result: *mut *mut Passwd) -> c_int;
    #[link_name = "alix_open_v2"]
    pub fn open(path: *const c_char, flags: u64, ...) -> c_int;
    pub fn close(fd: c_int) -> c_int;
    pub fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    pub fn flock(fd: c_int, operation: c_int) -> c_int;
    pub fn read(fd: c_int, buffer: *mut u8, count: usize) -> isize;
    pub fn write(fd: c_int, buffer: *const u8, count: usize) -> isize;
    pub fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64;
    pub fn fsync(fd: c_int) -> c_int;
    pub fn ftruncate(fd: c_int, size: i64) -> c_int;
    pub fn fstat(fd: c_int, value: *mut Stat) -> c_int;
    pub fn stat(path: *const c_char, value: *mut Stat) -> c_int;
    pub fn lstat(path: *const c_char, value: *mut Stat) -> c_int;
    pub fn mkdir(path: *const c_char, mode: u32) -> c_int;
    pub fn rmdir(path: *const c_char) -> c_int;
    pub fn unlink(path: *const c_char) -> c_int;
    pub fn rename(old: *const c_char, new: *const c_char) -> c_int;
    pub fn realpath(path: *const c_char, output: *mut c_char) -> *mut c_char;
    pub fn readlink(path: *const c_char, output: *mut c_char, count: usize) -> isize;
    pub fn opendir(path: *const c_char) -> *mut DIR;
    pub fn readdir(dir: *mut DIR) -> *mut Dirent;
    pub fn closedir(dir: *mut DIR) -> c_int;
    pub fn pipe2(pair: *mut c_int, flags: c_int) -> c_int;
    pub fn getpid() -> c_int;
    pub fn malloc(size: usize) -> *mut c_void;
    pub fn calloc(count: usize, size: usize) -> *mut c_void;
    pub fn realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    pub fn free(pointer: *mut c_void);
    pub fn posix_memalign(out: *mut *mut c_void, alignment: usize, size: usize) -> c_int;
    pub fn abort() -> !;
    pub fn exit(code: c_int) -> !;
    pub fn __errno_location() -> *mut c_int;
    pub fn strerror(code: c_int) -> *const c_char;
    pub fn sys_read(fd: c_int, buffer: *mut u8, count: usize) -> isize;
    pub fn sys_write(fd: c_int, buffer: *const u8, count: usize) -> isize;
    pub fn getrandom(buffer: *mut u8, count: usize, flags: u32) -> isize;
    pub fn sys_yield() -> c_int;
    pub fn sys_sleep_ms(milliseconds: u32) -> c_int;
    pub fn sys_monotonic_millis() -> u64;
    pub fn sys_time_millis() -> u64;
    pub fn sys_thread_self() -> u64;
    pub fn pthread_attr_init(attribute: *mut pthread_attr_t) -> c_int;
    pub fn pthread_attr_setstacksize(attribute: *mut pthread_attr_t, size: usize) -> c_int;
    pub fn pthread_attr_destroy(attribute: *mut pthread_attr_t) -> c_int;
    pub fn pthread_create(thread: *mut pthread_t, attribute: *const pthread_attr_t,
                          start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
                          argument: *mut c_void) -> c_int;
    pub fn pthread_join(thread: pthread_t, result: *mut *mut c_void) -> c_int;
    pub fn pthread_detach(thread: pthread_t) -> c_int;
    pub fn pthread_setname_np(thread: pthread_t, name: *const c_char) -> c_int;
    pub fn sysconf(name: c_int) -> i64;
    pub fn sys_futex_wait(address: *const u32, expected: u32, timeout_ms: u32) -> c_int;
    pub fn sys_futex_wake(address: *const u32, maximum: u32) -> c_int;
    pub fn alix_tls_key_create(key: *mut u64, destroy: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int;
    pub fn alix_tls_key_delete(key: u64) -> c_int;
    pub fn alix_tls_get(key: u64) -> *mut c_void;
    pub fn alix_tls_set(key: u64, value: *mut c_void) -> c_int;
    pub fn __cxa_thread_atexit_impl(destroy: unsafe extern "C" fn(*mut c_void), value: *mut c_void, dso: *mut c_void) -> c_int;
    pub static __dso_handle: *mut c_void;
}
