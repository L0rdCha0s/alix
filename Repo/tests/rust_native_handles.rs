//! Real Rust/pthread ownership and metadata checks in the native guest.
use std::ffi::{c_char, c_void, CStr};
use std::os::alix::thread::{JoinHandleExt, RawPthread};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[repr(C)]
struct Attribute {
    stack_size: usize, guard_size: usize, stack_address: *mut c_void,
    detach_state: i32, magic: u32,
}
const _: () = assert!(std::mem::size_of::<Attribute>() == 32);
const _: () = assert!(std::mem::size_of::<RawPthread>() == 8);

unsafe extern "C" {
    fn pthread_self() -> RawPthread;
    fn pthread_join(thread: RawPthread, result: *mut *mut c_void) -> i32;
    fn pthread_detach(thread: RawPthread) -> i32;
    fn pthread_getname_np(thread: RawPthread, name: *mut c_char, capacity: usize) -> i32;
    fn pthread_getattr_np(thread: RawPthread, attributes: *mut Attribute) -> i32;
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}

static TLS_DROPS: AtomicUsize = AtomicUsize::new(0);
static RESULT_DROPS: AtomicUsize = AtomicUsize::new(0);
struct TlsGuard;
impl Drop for TlsGuard { fn drop(&mut self) { TLS_DROPS.fetch_add(1, Ordering::SeqCst); } }
struct Returned;
impl Drop for Returned { fn drop(&mut self) { RESULT_DROPS.fetch_add(1, Ordering::SeqCst); } }
thread_local! { static GUARD: TlsGuard = TlsGuard; }

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let start = Instant::now();
    while !predicate() {
        assert!(start.elapsed() < Duration::from_secs(5), "native thread operation timed out");
        thread::yield_now();
    }
}
fn attributes(id: RawPthread) -> Box<Attribute> {
    let mut value = Box::new(Attribute {
        stack_size: 0, guard_size: 0, stack_address: std::ptr::null_mut(), detach_state: -1, magic: 0,
    });
    assert_eq!(unsafe { pthread_getattr_np(id, &mut *value) }, 0);
    assert!(!value.stack_address.is_null());
    assert_eq!(value.guard_size, 4096);
    value
}
fn thread_gone(id: RawPthread) {
    let mut name = vec![0u8; 32];
    wait_until(|| unsafe { pthread_getname_np(id, name.as_mut_ptr().cast(), name.len()) } == 3);
}

pub fn run() {
    assert!(!cfg!(unix));
    assert_eq!(std::env::consts::OS, "alix");
    let published = Arc::new((0..8).map(|_| AtomicU64::new(0)).collect::<Vec<_>>());
    let gate = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    const STACK: usize = 1024 * 1024 + 123;
    for cpu in 0..8 {
        let published = Arc::clone(&published);
        let gate = Arc::clone(&gate);
        handles.push(thread::Builder::new().name(format!("rust_handle_{cpu}")).stack_size(STACK).spawn(move || {
            assert_eq!(unsafe { sys_thread_set_affinity(cpu) }, 0);
            assert_eq!(unsafe { sys_thread_cpu() }, cpu);
            GUARD.with(|_| {});
            let native = unsafe { pthread_self() };
            published[cpu as usize].store(native, Ordering::Release);
            while !gate.load(Ordering::Acquire) { thread::yield_now(); }
            native
        }).unwrap());
    }
    wait_until(|| published.iter().all(|id| id.load(Ordering::Acquire) != 0));
    let mut ids = Vec::new();
    for (cpu, handle) in handles.iter().enumerate() {
        let id = handle.as_pthread_t();
        assert_eq!(id, published[cpu].load(Ordering::Acquire));
        assert_eq!(id, handle.as_pthread_t());
        let attribute = attributes(id);
        assert!((STACK..STACK + 4096).contains(&attribute.stack_size));
        assert_eq!(attribute.detach_state, 0);
        let mut name = vec![0u8; 32];
        assert_eq!(unsafe { pthread_getname_np(id, name.as_mut_ptr().cast(), name.len()) }, 0);
        assert_eq!(CStr::from_bytes_until_nul(&name).unwrap().to_str().unwrap(), format!("rust_handle_{cpu}"));
        ids.push(id);
    }
    ids.sort_unstable(); ids.dedup(); assert_eq!(ids.len(), 8);
    gate.store(true, Ordering::Release);
    for (cpu, handle) in handles.into_iter().enumerate() {
        assert_eq!(handle.join().unwrap(), published[cpu].load(Ordering::Acquire));
    }
    assert_eq!(TLS_DROPS.load(Ordering::SeqCst), 8);

    // Consuming the Rust handle must leave a real joinable C pthread. The
    // closure's Rust result is dropped rather than exported as a C pointer.
    for round in 0..16 {
        let handle = thread::Builder::new().name(format!("rust_raw_join_{round}")).spawn(|| {
            GUARD.with(|_| {});
            Returned
        }).unwrap();
        let borrowed = handle.as_pthread_t();
        let raw = handle.into_pthread_t(); assert_eq!(borrowed, raw);
        let mut result = Box::new(1usize as *mut c_void);
        assert_eq!(unsafe { pthread_join(raw, &mut *result) }, 0);
        assert!(result.is_null());
        assert_eq!(TLS_DROPS.load(Ordering::SeqCst), 9 + round);
        assert_eq!(RESULT_DROPS.load(Ordering::SeqCst), 1 + round);
    }
    for drop_handle in [false, true] {
        for round in 0..16 {
            let done = Arc::new(AtomicBool::new(false));
            let release = Arc::clone(&done);
            let handle = thread::Builder::new().name("rust_raw_detach".into()).spawn(move || {
                GUARD.with(|_| {});
                while !release.load(Ordering::Acquire) { thread::yield_now(); }
                Returned
            }).unwrap();
            let raw = handle.as_pthread_t();
            if drop_handle { drop(handle); }
            else {
                assert_eq!(handle.into_pthread_t(), raw);
                assert_eq!(unsafe { pthread_detach(raw) }, 0);
            }
            assert_eq!(attributes(raw).detach_state, 1);
            assert_eq!(unsafe { pthread_join(raw, std::ptr::null_mut()) }, 22);
            done.store(true, Ordering::Release);
            let count = 25 + round + if drop_handle { 16 } else { 0 };
            wait_until(|| TLS_DROPS.load(Ordering::SeqCst) == count);
            thread_gone(raw);
            assert_eq!(RESULT_DROPS.load(Ordering::SeqCst), count - 8);
        }
    }
    println!("RUST_THREAD_HANDLES_TEST: PASS workers=8 native_ids=1 names=1 stack=1 raw_join=16 raw_detach=16 drop_detach=16 tls_dtors=56");
}
