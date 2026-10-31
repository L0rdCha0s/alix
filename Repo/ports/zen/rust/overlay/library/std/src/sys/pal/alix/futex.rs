use crate::sync::atomic::Atomic;
use crate::time::Duration;
use super::ffi;

pub type Primitive = u32;
pub type SmallPrimitive = u32;
pub type Futex = Atomic<u32>;
pub type SmallFutex = Atomic<u32>;

pub fn futex_wait(futex: &Futex, expected: u32, timeout: Option<Duration>) -> bool {
    let started = unsafe { ffi::sys_monotonic_millis() };
    let milliseconds = timeout.map(|duration| duration.as_millis().saturating_add(u128::from(duration.subsec_nanos() % 1_000_000 != 0)));
    loop {
        let elapsed = u128::from(unsafe { ffi::sys_monotonic_millis() }.wrapping_sub(started));
        let wait = match milliseconds {
            None => u32::MAX,
            Some(total) => total.saturating_sub(elapsed).min(u128::from(u32::MAX - 1)) as u32,
        };
        match unsafe { ffi::sys_futex_wait(futex.as_ptr(), expected, wait) } {
            0 | -11 => return true,
            -110 => {
                if let Some(total) = milliseconds {
                    let elapsed = u128::from(unsafe { ffi::sys_monotonic_millis() }.wrapping_sub(started));
                    if elapsed >= total { return false; }
                }
            }
            error => rtabort!("Alix futex wait failed: {}", error),
        }
    }
}

pub fn futex_wake(futex: &Futex) -> bool {
    let result = unsafe { ffi::sys_futex_wake(futex.as_ptr(), 1) };
    if result < 0 { rtabort!("Alix futex wake failed: {}", result); }
    result != 0
}

pub fn futex_wake_all(futex: &Futex) {
    let result = unsafe { ffi::sys_futex_wake(futex.as_ptr(), u32::MAX) };
    if result < 0 { rtabort!("Alix futex wake-all failed: {}", result); }
}
