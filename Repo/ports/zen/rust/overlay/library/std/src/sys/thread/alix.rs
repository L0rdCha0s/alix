use crate::ffi::CStr;
use crate::io;
use crate::mem::ManuallyDrop;
use crate::num::NonZero;
use crate::sys::ffi;
use crate::thread::ThreadInit;
use crate::time::Duration;

pub const DEFAULT_MIN_STACK_SIZE: usize = 2 * 1024 * 1024;
pub struct Thread { id: u64 }
unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

impl Thread {
    pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Self> {
        let stack = stack.max(16 * 1024);
        // Leave room for page rounding and avoid wrapping the kernel's native
        // stack-size arithmetic. The kernel applies its address-space limits.
        if stack > isize::MAX as usize - 4095 {
            return Err(io::Error::from_raw_os_error(22));
        }
        unsafe extern "C" fn start(argument: *mut crate::ffi::c_void) {
            // The parent publishes only a heap-owned ThreadInit allocation.
            let init = unsafe { Box::from_raw(argument.cast::<ThreadInit>()) };
            let rust_start = init.init();
            rust_start();
            // Native C++-ABI TLS destructors and TSD cleanup run before exit.
            unsafe { ffi::alix_thread_exit(0) }
        }
        let argument = Box::into_raw(init);
        let id = unsafe { ffi::sys_thread_create(start as *const () as usize, argument as usize,
                                                stack, c"rust_thread".as_ptr()) };
        if id < 0 {
            unsafe { drop(Box::from_raw(argument)); }
            Err(io::Error::from_raw_os_error(11))
        } else { Ok(Self { id: id as u64 }) }
    }
    pub fn join(self) {
        let thread = ManuallyDrop::new(self);
        let status = unsafe { ffi::alix_thread_join(thread.id, crate::ptr::null_mut()) };
        if status != 0 { rtabort!("Alix thread join failed: {}", status); }
    }
}
impl Drop for Thread {
    fn drop(&mut self) {
        if unsafe { ffi::alix_thread_detach(self.id) } != 0 { rtabort!("Alix thread detach failed"); }
    }
}
pub fn current_os_id() -> Option<u64> { NonZero::new(unsafe { ffi::sys_thread_self() }).map(NonZero::get) }
pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    let count = unsafe { ffi::sysconf(2) }; // Alix _SC_NPROCESSORS_ONLN
    if count > 0 { Ok(NonZero::new(count as usize).unwrap()) }
    else { Err(io::Error::UNKNOWN_THREAD_COUNT) }
}
pub fn yield_now() { unsafe { ffi::sys_yield(); } }
pub fn sleep(duration: Duration) {
    let mut milliseconds = duration.as_millis().saturating_add(u128::from(duration.subsec_nanos() % 1_000_000 != 0));
    while milliseconds != 0 {
        let part = milliseconds.min(u128::from(u32::MAX)) as u32;
        if unsafe { ffi::sys_sleep_ms(part) } != 0 { rtabort!("Alix thread sleep failed"); }
        milliseconds -= u128::from(part);
    }
}
// Rust preserves Builder names in its own Thread metadata. Alix currently has
// no native rename syscall; the OS-level name remains "rust_thread".
pub fn set_name(_name: &CStr) {}
