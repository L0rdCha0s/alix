//! Execute actual Gecko logging/errno crates and the storage path module.
use std::collections::HashSet;
use std::ffi::{c_int, CStr};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind};
use std::os::fd::IntoRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;

#[path = "../ports/zen/upstream/firefox-159.0/toolkit/components/kvstore/src/fs.rs"]
mod storage_path;
use storage_path::WidePathBuf;

unsafe extern "C" {
    fn alix_rust_os_check_abi(values: *const c_int, count: usize) -> c_int;
    fn alix_rust_os_errno_address() -> *mut c_int;
    fn alix_rust_os_set_errno(value: c_int);
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}
const BASE: &str = "/tmp/rust-os-consumers";
const RECORDS: usize = 32;

fn wide(path: &str) -> WidePathBuf { WidePathBuf::new(path.encode_utf16().collect::<Vec<_>>()) }
fn message(cpu: usize, sequence: usize) -> String {
    format!("cpu={cpu} sequence={sequence} Unicode=🦀 newline=\n quote=\"")
}

fn main() {
    assert_eq!(std::env::consts::OS, "alix");
    let abi = vec![libc::EAGAIN, libc::EWOULDBLOCK, libc::EINVAL, libc::ENOENT,
        libc::EBADF, libc::ESRCH, libc::ERANGE, libc::ENOSYS, libc::ENOTSUP,
        libc::EOPNOTSUPP, libc::EOVERFLOW, libc::ECANCELED, libc::EOWNERDEAD,
        libc::ENOTRECOVERABLE, libc::SIGABRT, libc::SIGKILL, libc::SIGPIPE, libc::SIGSEGV];
    assert_eq!(unsafe { alix_rust_os_check_abi(abi.as_ptr(), abi.len()) }, 0);
    assert_eq!(unsafe { libc::__errno_location() }, unsafe { alix_rust_os_errno_address() });
    errno::set_errno(errno::Errno(libc::EBADF));
    assert_eq!(unsafe { *alix_rust_os_errno_address() }, libc::EBADF);
    unsafe { alix_rust_os_set_errno(libc::EACCES); }
    assert_eq!(errno::errno(), errno::Errno(libc::EACCES));
    let mut small = vec![0x55u8; 1];
    assert_eq!(unsafe { libc::strerror_r(libc::ENOENT, small.as_mut_ptr().cast(), small.len()) }, libc::ERANGE);
    assert_eq!(small[0], 0);
    assert_eq!(errno::errno(), errno::Errno(libc::EACCES));
    for code in [libc::EINVAL, libc::ENOENT, libc::ERANGE, libc::ENOTSUP] {
        let expected = unsafe { CStr::from_ptr(libc::strerror(code)) }.to_str().unwrap();
        assert_eq!(errno::Errno(code).to_string(), expected);
    }
    assert!(errno::Errno(i32::MAX).to_string().contains("strerror_r returned error 22"));
    let pid = unsafe { libc::getpid() };
    assert!(pid > 0);
    assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
    assert_eq!(unsafe { libc::kill(i32::MAX, 0) }, -1);
    assert_eq!(errno::errno(), errno::Errno(libc::ESRCH));
    assert_eq!(unsafe { libc::kill(pid, 32) }, -1);
    assert_eq!(errno::errno(), errno::Errno(libc::EINVAL));

    fs::create_dir(BASE).unwrap();
    assert_eq!(wide("/etc/..").canonicalize().unwrap(), PathBuf::from("/root"));
    assert_eq!(wide("").canonicalize().unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(wide("/tmp/nul\0suffix").canonicalize().unwrap_err().kind(), ErrorKind::InvalidInput);
    assert!(WidePathBuf::new(vec![0xd800]).canonicalize().is_err());
    assert_eq!(wide(&format!("/{:x<4096}", "")).canonicalize().unwrap_err().raw_os_error(), Some(36));

    let (reader, writer) = std::io::pipe().unwrap();
    // The real public API takes ownership of this fd for the logger's lifetime.
    // No caller closes it after transferring it to the global Glean logger.
    glean_core::glean_enable_logging_to_fd(writer.into_raw_fd() as u64);
    assert!(log::log_enabled!(log::Level::Info));
    let collector = thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut seen = vec![vec![false; RECORDS]; 8];
        for _ in 0..8 * RECORDS {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            let record: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(record["level"], "INFO");
            assert_eq!(record["target"], "alix-native");
            let payload = record["message"].as_str().unwrap();
            let mut fields = payload.split_whitespace();
            let cpu: usize = fields.next().unwrap().strip_prefix("cpu=").unwrap().parse().unwrap();
            let sequence: usize = fields.next().unwrap().strip_prefix("sequence=").unwrap().parse().unwrap();
            assert!(cpu < 8 && sequence < RECORDS && !seen[cpu][sequence]);
            assert_eq!(payload, message(cpu, sequence));
            seen[cpu][sequence] = true;
        }
        assert!(seen.iter().flatten().all(|value| *value));
    });
    let start = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for cpu in 0..8usize {
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            assert_eq!(unsafe { sys_thread_set_affinity(cpu as u32) }, 0);
            assert_eq!(unsafe { sys_thread_cpu() }, cpu as u32);
            let address = unsafe { alix_rust_os_errno_address() };
            assert_eq!(address, unsafe { libc::__errno_location() });
            start.wait();
            for sequence in 0..RECORDS {
                let expected = 1000 + cpu as i32;
                errno::set_errno(errno::Errno(expected));
                thread::yield_now();
                assert_eq!(errno::errno(), errno::Errno(expected));
                assert_eq!(unsafe { *address }, expected);
                assert_eq!(errno::Errno(libc::ENOENT).to_string(), "No such file or directory");
                assert_eq!(errno::errno(), errno::Errno(expected));
                let missing = format!("{BASE}/missing-{cpu}-{sequence}");
                assert_eq!(fs::File::open(missing).unwrap_err().kind(), ErrorKind::NotFound);
                assert_eq!(errno::errno(), errno::Errno(libc::ENOENT));
                log::info!(target: "alix-native", "{}", message(cpu, sequence));
            }
            let path = format!("{BASE}/cpu-{cpu}-🦀");
            fs::write(&path, b"native canonical path").unwrap();
            let wide = wide(&path);
            assert_eq!(wide.as_wide(), path.encode_utf16().collect::<Vec<_>>());
            assert!(wide == path.as_str());
            let canonical = wide.canonicalize().unwrap();
            assert_eq!(canonical, PathBuf::from(&path));
            assert_eq!(fs::read(&canonical).unwrap(), b"native canonical path");
            fs::remove_file(canonical).unwrap();
            address as usize
        }));
    }
    let addresses: HashSet<usize> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(addresses.len(), 8);
    collector.join().unwrap();
    fs::remove_dir(BASE).unwrap();
    println!("RUST_OS_CONSUMERS_TEST: PASS cpus=8 actual_glean=1 records=256 errno_tls=8 c_abi=1 strerror=1 wide_paths=1 signal_probe=1");
}
