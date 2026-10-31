use super::{MIN_ALIGN, realloc_fallback};
use crate::alloc::{GlobalAlloc, Layout, System};
use crate::sys::ffi;
use crate::ptr;

#[stable(feature = "alloc_system_type", since = "1.28.0")]
unsafe impl GlobalAlloc for System {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= MIN_ALIGN {
            unsafe { ffi::malloc(layout.size()).cast() }
        } else {
            let mut pointer = ptr::null_mut();
            let error = unsafe { ffi::posix_memalign(&mut pointer, layout.align(), layout.size()) };
            if error == 0 { pointer.cast() } else { ptr::null_mut() }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= MIN_ALIGN {
            unsafe { ffi::calloc(1, layout.size()).cast() }
        } else {
            let pointer = unsafe { self.alloc(layout) };
            if !pointer.is_null() { unsafe { ptr::write_bytes(pointer, 0, layout.size()) }; }
            pointer
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        unsafe { ffi::free(pointer.cast()) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= MIN_ALIGN {
            unsafe { ffi::realloc(pointer.cast(), new_size).cast() }
        } else {
            unsafe { realloc_fallback(self, pointer, layout, new_size) }
        }
    }
}
