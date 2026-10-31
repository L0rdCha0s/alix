pub fn fill_bytes(bytes: &mut [u8]) {
    let mut filled = 0;
    while filled < bytes.len() {
        let result = unsafe { crate::sys::ffi::getrandom(bytes[filled..].as_mut_ptr(), bytes.len() - filled, 0) };
        if result < 0 && crate::sys::io::errno() == 4 { continue; }
        if result <= 0 { panic!("Alix OS entropy service failed: {}", crate::sys::io::errno()); }
        filled += result as usize;
    }
}
