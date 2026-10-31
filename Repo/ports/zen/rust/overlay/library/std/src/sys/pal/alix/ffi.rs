//! ABI declarations for Alix's own libc and int-0x80 syscall wrappers.
#![allow(dead_code)]
use crate::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
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
    pub fn sys_thread_create(entry: usize, argument: usize, stack_size: usize, name: *const c_char) -> i64;
    pub fn alix_thread_join(thread: u64, status: *mut c_int) -> c_int;
    pub fn alix_thread_detach(thread: u64) -> c_int;
    pub fn alix_thread_exit(status: c_int) -> !;
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
