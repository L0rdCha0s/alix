//! Real std environment, cwd/executable paths and reentrant native accounts.
#![allow(deprecated)]
use std::env;
use std::ffi::{c_char, c_int, CStr, CString, OsString};
use std::fs;
use std::os::alix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Barrier};
use std::thread;

#[repr(C)]
struct Passwd {
    name: *mut c_char, password: *mut c_char, uid: u32, gid: u32,
    gecos: *mut c_char, directory: *mut c_char, shell: *mut c_char,
}
unsafe extern "C" {
    fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    fn putenv(assignment: *mut c_char) -> c_int;
    fn getuid() -> u32;
    fn alix_get_executable_path(buffer: *mut c_char, capacity: usize) -> isize;
    fn getpwuid_r(uid: u32, entry: *mut Passwd, bytes: *mut c_char, capacity: usize, result: *mut *mut Passwd) -> c_int;
    fn getpwnam_r(name: *const c_char, entry: *mut Passwd, bytes: *mut c_char, capacity: usize, result: *mut *mut Passwd) -> c_int;
    fn sys_thread_set_affinity(cpu: u32) -> c_int;
    fn sys_thread_cpu() -> u32;
}
const BASE: &str = "/tmp/rust-env-paths";

fn accounts() -> PathBuf {
    let uid = unsafe { getuid() };
    let text = fs::read_to_string("/etc/passwd").unwrap();
    let fields: Vec<_> = text.lines().filter_map(|line| {
        let fields: Vec<_> = line.splitn(5, ':').collect();
        if fields.len() == 5 && fields[1].parse::<u32>().ok() == Some(uid) { Some(fields) } else { None }
    }).next().unwrap();
    let expected = if fields[4].starts_with('/') { PathBuf::from(fields[4]) } else { PathBuf::from(format!("/{}", fields[4])) };
    let mut bytes = vec![0u8; 128 * 1024];
    let mut entry = Box::new(Passwd { name: ptr::null_mut(), password: ptr::null_mut(), uid: 0, gid: 0,
        gecos: ptr::null_mut(), directory: ptr::null_mut(), shell: ptr::null_mut() });
    let mut result = Box::new(ptr::null_mut());
    assert_eq!(unsafe { getpwuid_r(uid, &mut *entry, bytes.as_mut_ptr().cast(), bytes.len(), &mut *result) }, 0);
    assert_eq!(*result, &mut *entry as *mut Passwd);
    assert_eq!(entry.uid, uid);
    assert_eq!(entry.gid, fields[2].parse::<u32>().unwrap());
    for pointer in [entry.name, entry.password, entry.gecos, entry.directory, entry.shell] {
        assert!((pointer as usize) >= bytes.as_ptr() as usize && (pointer as usize) < bytes.as_ptr() as usize + bytes.len());
    }
    assert_eq!(unsafe { CStr::from_ptr(entry.name) }.to_bytes(), fields[0].as_bytes());
    assert_eq!(unsafe { CStr::from_ptr(entry.directory) }.to_bytes(), expected.as_os_str().as_bytes());
    assert!(unsafe { CStr::from_ptr(entry.password) }.is_empty());
    assert!(unsafe { CStr::from_ptr(entry.shell) }.is_empty());
    let name = CString::new(fields[0]).unwrap();
    assert_eq!(unsafe { getpwnam_r(name.as_ptr(), &mut *entry, bytes.as_mut_ptr().cast(), bytes.len(), &mut *result) }, 0);
    assert_eq!(*result, &mut *entry as *mut Passwd);
    assert_eq!(unsafe { getpwuid_r(uid, &mut *entry, bytes.as_mut_ptr().cast(), 1, &mut *result) }, 34);
    assert!(result.is_null());
    let unknown = (0..u32::MAX).rev().find(|candidate| !text.lines().any(|line| line.split(':').nth(1).and_then(|v| v.parse::<u32>().ok()) == Some(*candidate))).unwrap();
    assert_eq!(unsafe { getpwuid_r(unknown, &mut *entry, bytes.as_mut_ptr().cast(), bytes.len(), &mut *result) }, 0);
    assert!(result.is_null());
    expected
}

pub fn run() {
    let home = env::var_os("HOME"); let temp = env::var_os("TMPDIR");
    let account_home = accounts();
    unsafe { env::remove_var("HOME"); }
    assert_eq!(env::home_dir(), Some(account_home.clone()));
    unsafe { env::set_var("HOME", ""); }
    assert_eq!(env::home_dir(), Some(account_home));
    unsafe { env::set_var("HOME", "/tmp/native-home"); }
    assert_eq!(env::home_dir(), Some(PathBuf::from("/tmp/native-home")));
    unsafe { env::remove_var("TMPDIR"); }
    assert_eq!(env::temp_dir(), PathBuf::from("/tmp"));
    unsafe { env::set_var("TMPDIR", "/tmp/native-temp"); }
    assert_eq!(env::temp_dir(), PathBuf::from("/tmp/native-temp"));
    unsafe { env::set_var("TMPDIR", ""); }
    assert_eq!(env::temp_dir(), PathBuf::new());

    assert!(env::var_os("").is_none()); assert!(env::var_os("bad=key").is_none()); assert!(env::var_os("nul\0key").is_none());
    let name = OsString::from_vec(b"ALIX_RUST_ENV_\xff".to_vec());
    let value = OsString::from_vec(b"raw=\xfe-value".to_vec());
    unsafe { env::set_var(&name, &value); }
    assert_eq!(env::var_os(&name), Some(value.clone()));
    assert!(matches!(env::var(&name), Err(env::VarError::NotUnicode(ref bytes)) if bytes == &value));
    assert!(env::vars_os().any(|(key, bytes)| key == name && bytes == value));
    unsafe { env::remove_var(&name); }
    let mut borrowed = b"ALIX_RUST_ENV_BORROWED=first\0".to_vec().into_boxed_slice();
    assert_eq!(unsafe { putenv(borrowed.as_mut_ptr().cast()) }, 0);
    let snapshot = env::vars_os();
    let offset = b"ALIX_RUST_ENV_BORROWED=".len(); borrowed[offset..offset + 5].copy_from_slice(b"later");
    assert_eq!(env::var("ALIX_RUST_ENV_BORROWED").unwrap(), "later");
    assert_eq!(snapshot.into_iter().find(|(key, _)| key == "ALIX_RUST_ENV_BORROWED").unwrap().1, "first");
    unsafe { env::remove_var("ALIX_RUST_ENV_BORROWED"); } drop(borrowed);

    let candidates = Arc::new((0..8).map(|cpu| format!("cpu-{cpu}:{}", char::from(b'A' + cpu).to_string().repeat(512))).collect::<Vec<_>>());
    let start = Arc::new(Barrier::new(8)); let mut workers = Vec::new();
    for cpu in 0..8usize {
        let start = Arc::clone(&start); let candidates = Arc::clone(&candidates);
        workers.push(thread::spawn(move || {
            assert_eq!(unsafe { sys_thread_set_affinity(cpu as u32) }, 0); assert_eq!(unsafe { sys_thread_cpu() }, cpu as u32);
            let key = format!("ALIX_RUST_ENV_CPU_{cpu}"); let c_key = CString::new(key.as_str()).unwrap();
            start.wait();
            for sequence in 0..64 {
                let first = format!("first-{cpu}-{sequence}"); let second = format!("second-{cpu}-{sequence}");
                unsafe { env::set_var(&key, &first); }
                let owned = env::var_os(&key).unwrap();
                let second_c = CString::new(second.as_str()).unwrap();
                assert_eq!(unsafe { setenv(c_key.as_ptr(), second_c.as_ptr(), 1) }, 0);
                unsafe { env::set_var("ALIX_RUST_ENV_RACE", &candidates[cpu]); }
                thread::yield_now();
                assert_eq!(owned, first.as_str()); assert_eq!(env::var(&key).unwrap(), second);
                let current = env::var("ALIX_RUST_ENV_RACE").unwrap(); assert!(candidates.contains(&current));
                let snapshot = env::vars_os();
                assert_eq!(snapshot.into_iter().find(|(name, _)| name == key.as_str()).unwrap().1, second.as_str());
            }
            unsafe { env::remove_var(&key); }
        }));
    }
    for worker in workers { worker.join().unwrap(); }
    unsafe { env::remove_var("ALIX_RUST_ENV_RACE"); }

    let original = env::current_dir().unwrap();
    let executable = env::current_exe().unwrap();
    let mut native_executable = vec![0u8; 4096];
    let length = unsafe { alix_get_executable_path(native_executable.as_mut_ptr().cast(), native_executable.len()) };
    assert!(length > 0); native_executable.truncate(length as usize);
    assert_eq!(executable.as_os_str().as_bytes(), &native_executable); assert!(executable.is_absolute());
    fs::create_dir(BASE).unwrap(); fs::write(format!("{BASE}/file"), b"cwd fixture").unwrap();
    env::set_current_dir(BASE).unwrap(); assert_eq!(env::current_dir().unwrap(), PathBuf::from(BASE));
    assert_eq!(env::current_exe().unwrap(), executable);
    assert_eq!(std::path::absolute("a/../b").unwrap(), Path::new(BASE).join("a/../b"));
    assert_eq!(env::set_current_dir("file").unwrap_err().kind(), std::io::ErrorKind::NotADirectory);
    assert_eq!(env::set_current_dir("missing").unwrap_err().kind(), std::io::ErrorKind::NotFound);
    assert_eq!(env::set_current_dir("nul\0path").unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(env::current_dir().unwrap(), PathBuf::from(BASE));
    env::set_current_dir("/etc").unwrap(); assert_eq!(env::current_dir().unwrap(), PathBuf::from("/root/etc"));
    env::set_current_dir(original).unwrap(); fs::remove_file(format!("{BASE}/file")).unwrap(); fs::remove_dir(BASE).unwrap();
    let path = OsString::from_vec(b"/bin::/tmp/\xff:/usr/bin:".to_vec());
    let parts: Vec<_> = env::split_paths(&path).collect(); assert_eq!(parts.len(), 5);
    assert_eq!(parts[1], PathBuf::new()); assert_eq!(parts[4], PathBuf::new());
    assert_eq!(env::join_paths(parts).unwrap(), path);
    assert!(env::join_paths(["a:b"]).is_err());
    assert_eq!(env::split_paths("").collect::<Vec<_>>(), vec![PathBuf::new()]);
    unsafe {
        match home { Some(value) => env::set_var("HOME", value), None => env::remove_var("HOME") }
        match temp { Some(value) => env::set_var("TMPDIR", value), None => env::remove_var("TMPDIR") }
    }
    println!("RUST_ENVIRONMENT_TEST: PASS cpus=8 updates=1536 snapshots=512 bytes=1 owned=1 cwd=1 exe=1 paths=1 home=1 accounts=1");
}
