//! Exercise the actual public Rust File lock API against native Alix leases.
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

unsafe extern "C" {
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}
const PATH: &str = "/tmp/rust-file-locks";
pub fn run() {
    fs::write(PATH, 0u64.to_le_bytes()).unwrap();
    let first = File::open(PATH).unwrap(); let second = File::open(PATH).unwrap();
    first.lock_shared().unwrap(); second.lock_shared().unwrap();
    assert!(matches!(first.try_lock(), Err(TryLockError::WouldBlock)));
    second.unlock().unwrap(); first.unlock().unwrap();
    first.lock().unwrap(); let alias = first.try_clone().unwrap(); drop(first);
    assert!(matches!(second.try_lock_shared(), Err(TryLockError::WouldBlock)));
    alias.unlock().unwrap(); second.try_lock().unwrap(); second.unlock().unwrap();
    alias.lock().unwrap(); drop(alias); second.try_lock().unwrap(); second.unlock().unwrap();

    let start = Arc::new(Barrier::new(8)); let mut workers = Vec::new();
    for cpu in 0..8u32 {
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            assert_eq!(unsafe { sys_thread_set_affinity(cpu) }, 0); assert_eq!(unsafe { sys_thread_cpu() }, cpu);
            let mut file = OpenOptions::new().read(true).write(true).open(PATH).unwrap();
            let mut bytes = vec![0u8; 8]; start.wait();
            for _ in 0..32 {
                file.lock().unwrap(); file.seek(SeekFrom::Start(0)).unwrap(); file.read_exact(&mut bytes).unwrap();
                let value = u64::from_le_bytes(bytes.as_slice().try_into().unwrap()) + 1;
                thread::yield_now(); file.seek(SeekFrom::Start(0)).unwrap(); file.write_all(&value.to_le_bytes()).unwrap();
                file.unlock().unwrap();
            }
        }));
    }
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(u64::from_le_bytes(fs::read(PATH).unwrap().try_into().unwrap()), 256);

    second.lock_shared().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel(); let (locked_tx, locked_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        let file = File::open(PATH).unwrap(); ready_tx.send(()).unwrap();
        file.lock().unwrap(); locked_tx.send(()).unwrap();
        // Last-close release is exercised when this file leaves scope.
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap(); thread::sleep(Duration::from_millis(20));
    assert!(matches!(locked_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    second.unlock().unwrap(); locked_rx.recv_timeout(Duration::from_secs(5)).unwrap(); writer.join().unwrap();
    second.try_lock().unwrap(); second.unlock().unwrap(); drop(second);
    let (reader, writer) = std::io::pipe().unwrap();
    let unsupported = File::from(OwnedFd::from(reader));
    assert_eq!(unsupported.lock().unwrap_err().kind(), ErrorKind::Unsupported);
    drop(unsupported); drop(writer);
    fs::remove_file(PATH).unwrap();
    println!("RUST_FILE_LOCKS_TEST: PASS cpus=8 sections=256 shared=1 aliases=1 close=1 wait=1 would_block=1 unsupported=1");
}
