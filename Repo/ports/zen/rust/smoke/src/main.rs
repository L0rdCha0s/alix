use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

unsafe extern "C" {
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}

static DTORS: AtomicUsize = AtomicUsize::new(0);
struct Guard;
impl Drop for Guard { fn drop(&mut self) { DTORS.fetch_add(1, Ordering::SeqCst); } }
thread_local! {
    static VALUE: Cell<usize> = const { Cell::new(37) };
    static GUARD: Guard = Guard;
}

#[derive(Default)]
struct State { ready: usize, start: bool, count: usize, cpu_mask: u32 }

fn main() {
    assert_eq!(std::env::consts::OS, "alix");
    assert!(std::env::args().count() >= 1);
    let mut values: Vec<String> = (0..1024).map(|value| format!("value-{value}")).collect();
    values.reverse();
    values.sort();
    assert_eq!(values.len(), 1024);
    let mut map = HashMap::new();
    for index in 0..256 { map.insert(format!("key-{index}"), index); }
    assert_eq!(map.get("key-123"), Some(&123));
    let before = Instant::now();
    thread::sleep(Duration::from_millis(25));
    assert!(before.elapsed() >= Duration::from_millis(20));
    assert!(SystemTime::now().duration_since(UNIX_EPOCH).is_ok());
    assert!(UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap() < UNIX_EPOCH);
    assert_eq!(thread::available_parallelism().unwrap().get(), 8);
    assert!(thread::Builder::new().stack_size(usize::MAX).spawn(|| {}).is_err());

    let shared = Arc::new((Mutex::new(State::default()), Condvar::new()));
    let once = Arc::new(OnceLock::<usize>::new());
    let mut workers = Vec::new();
    for cpu in 0..8 {
        let shared = Arc::clone(&shared);
        let once = Arc::clone(&once);
        workers.push(thread::spawn(move || {
            assert_eq!(unsafe { sys_thread_set_affinity(cpu) }, 0);
            assert_eq!(unsafe { sys_thread_cpu() }, cpu);
            GUARD.with(|_| {});
            VALUE.with(|value| { assert_eq!(value.get(), 37); value.set(cpu as usize); });
            let (mutex, condition) = &*shared;
            let mut state = mutex.lock().unwrap();
            state.cpu_mask |= 1 << cpu;
            state.ready += 1;
            condition.notify_all();
            while !state.start { state = condition.wait(state).unwrap(); }
            drop(state);
            assert_eq!(*once.get_or_init(|| 54321), 54321);
            for _ in 0..128 {
                let mut state = mutex.lock().unwrap();
                let previous = state.count;
                thread::yield_now();
                state.count = previous + 1;
                VALUE.with(|value| assert_eq!(value.get(), cpu as usize));
            }
        }));
    }
    let (mutex, condition) = &*shared;
    let state = mutex.lock().unwrap();
    let (mut state, timed) = condition.wait_timeout_while(state, Duration::from_secs(5), |state| state.ready != 8).unwrap();
    assert!(!timed.timed_out());
    state.start = true;
    condition.notify_all();
    drop(state);
    for worker in workers { worker.join().unwrap(); }
    let state = mutex.lock().unwrap();
    assert_eq!(state.count, 1024);
    assert_eq!(state.cpu_mask, 0xFF);
    assert_eq!(DTORS.load(Ordering::SeqCst), 8);
    println!("RUST_STD_TEST: PASS workers=8 cpu_mask=0x{:X} count={} tls_dtors={} hashmap={}",
             state.cpu_mask, state.count, DTORS.load(Ordering::SeqCst), map.len());
}
