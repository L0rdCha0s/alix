use crate::sys::ffi;

pub unsafe fn register(value: *mut u8, destroy: unsafe extern "C" fn(*mut u8)) {
    let callback = unsafe { crate::mem::transmute(destroy) };
    let result = unsafe { ffi::__cxa_thread_atexit_impl(callback, value.cast(),
                         (&raw const ffi::__dso_handle).cast_mut().cast()) };
    if result != 0 { rtabort!("Alix TLS destructor registration failed"); }
}
