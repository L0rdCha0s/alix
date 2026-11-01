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
        unsafe extern "C" fn start(argument: *mut crate::ffi::c_void) -> *mut crate::ffi::c_void {
            // The parent publishes only a heap-owned ThreadInit allocation.
            let init = unsafe { Box::from_raw(argument.cast::<ThreadInit>()) };
            let rust_start = init.init();
            rust_start();
            // Returning to pthread's trampoline publishes completion and runs
            // native C++-ABI TLS/TSD destruction before the kernel exit.
            crate::ptr::null_mut()
        }
        let mut attribute = Box::new(ffi::pthread_attr_t {
            stack_size: 0, guard_size: 0, stack_address: crate::ptr::null_mut(), detach_state: 0, magic: 0,
        });
        let status = unsafe { ffi::pthread_attr_init(&mut *attribute) };
        if status != 0 { return Err(io::Error::from_raw_os_error(status)); }
        let status = unsafe { ffi::pthread_attr_setstacksize(&mut *attribute, stack) };
        if status != 0 {
            unsafe { ffi::pthread_attr_destroy(&mut *attribute); }
            return Err(io::Error::from_raw_os_error(status));
        }
        let mut id = Box::new(0);
        let argument = Box::into_raw(init);
        // All published arguments and publication storage are heap-owned.
        // pthread_create captures attributes before starting the callback.
        let status = unsafe { ffi::pthread_create(&mut *id, &*attribute, start, argument.cast()) };
        unsafe { ffi::pthread_attr_destroy(&mut *attribute); }
        if status != 0 {
            unsafe { drop(Box::from_raw(argument)); }
            Err(io::Error::from_raw_os_error(status))
        } else { Ok(Self { id: *id }) }
    }
    pub fn id(&self) -> u64 { self.id }
    pub fn into_id(self) -> u64 {
        // Transfer the actual joinable pthread to the caller. Do not detach
        // when consuming the Rust handle; its new owner must join or detach.
        ManuallyDrop::new(self).id
    }
    pub fn join(self) {
        let thread = ManuallyDrop::new(self);
        let status = unsafe { ffi::pthread_join(thread.id, crate::ptr::null_mut()) };
        if status != 0 { rtabort!("Alix thread join failed: {}", status); }
    }
}
impl Drop for Thread {
    fn drop(&mut self) {
        if unsafe { ffi::pthread_detach(self.id) } != 0 { rtabort!("Alix thread detach failed"); }
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
pub fn set_name(name: &CStr) {
    // OS naming is best-effort, with the same length limits as native pthreads.
    unsafe { ffi::pthread_setname_np(ffi::sys_thread_self(), name.as_ptr()); }
}
