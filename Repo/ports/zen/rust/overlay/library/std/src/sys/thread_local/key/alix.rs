use crate::sys::ffi;
pub type Key = u64;
pub fn create(destroy: Option<unsafe extern "C" fn(*mut u8)>) -> Key {
    let mut key = 0;
    let callback = unsafe { crate::mem::transmute(destroy) };
    if unsafe { ffi::alix_tls_key_create(&mut key, callback) } != 0 { rtabort!("out of Alix TLS keys"); }
    key
}
pub unsafe fn set(key: Key, value: *mut u8) {
    if unsafe { ffi::alix_tls_set(key, value.cast()) } != 0 { rtabort!("invalid Alix TLS key"); }
}
#[allow(dead_code)]
pub unsafe fn get(key: Key) -> *mut u8 { unsafe { ffi::alix_tls_get(key).cast() } }
pub unsafe fn destroy(key: Key) {
    if unsafe { ffi::alix_tls_key_delete(key) } != 0 { rtabort!("invalid Alix TLS key deletion"); }
}
