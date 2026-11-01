//! Execute the upstream File/OwnedFd APIs against real Alix descriptors.
use std::ffi::{c_char, c_void, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::alix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::UNIX_EPOCH;

unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn read(fd: i32, bytes: *mut c_void, count: usize) -> isize;
    fn write(fd: i32, bytes: *const c_void, count: usize) -> isize;
    fn pipe(pair: *mut i32) -> i32;
    fn chdir(path: *const c_char) -> i32;
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}
const BASE: &str = "/tmp/rust-native-fs";

pub fn run() {
    assert!(std::path::Path::new("/").is_absolute());
    assert!(std::path::Path::new("/tmp/file").is_absolute());
    assert!(!std::path::Path::new("relative/file").is_absolute());
    assert!(!std::path::Path::new("C:\\file").is_absolute());
    assert_eq!(std::path::absolute("/tmp/./file").unwrap(), PathBuf::from("/tmp/file"));
    assert_eq!(fs::create_dir("").unwrap_err().kind(), ErrorKind::NotFound);
    fs::create_dir(BASE).unwrap();
    assert_eq!(fs::create_dir(BASE).unwrap_err().kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::create_dir("/").unwrap_err().kind(), ErrorKind::AlreadyExists);
    assert!(fs::metadata(BASE).unwrap().is_dir());
    assert_eq!(fs::canonicalize("/etc/..").unwrap(), PathBuf::from("/root"));
    assert_eq!(fs::read_link("/etc").unwrap(), PathBuf::from("/root/etc"));
    assert!(fs::symlink_metadata("/etc").unwrap().file_type().is_symlink());
    assert!(File::open(format!("{BASE}/missing")).unwrap_err().kind() == ErrorKind::NotFound);
    assert_eq!(OpenOptions::new().open(BASE).unwrap_err().kind(), ErrorKind::InvalidInput);
    assert_eq!(File::open("/tmp/rust\0invalid").unwrap_err().kind(), ErrorKind::InvalidInput);

    let mut file = OpenOptions::new().read(true).write(true).create_new(true).open(format!("{BASE}/owned")).unwrap();
    assert_eq!(fs::create_dir(format!("{BASE}/owned")).unwrap_err().kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::create_dir(format!("{BASE}/owned/child")).unwrap_err().kind(), ErrorKind::NotADirectory);
    assert_eq!(fs::create_dir(format!("{BASE}/missing/child")).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(unsafe { fcntl(file.as_raw_fd(), 1) }, 1); // F_GETFD / FD_CLOEXEC
    file.write_all(b"abcdef").unwrap();
    file.seek(SeekFrom::Start(2)).unwrap();
    let mut alias = file.try_clone().unwrap();
    let mut first = vec![0u8; 1]; alias.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"c"); assert_eq!(file.stream_position().unwrap(), 3);
    file.set_len(2).unwrap(); assert_eq!(alias.stream_position().unwrap(), 3);
    file.set_len(8192).unwrap(); assert_eq!(file.metadata().unwrap().len(), 8192);
    file.seek(SeekFrom::Start(0)).unwrap(); let mut bytes = Vec::new(); file.read_to_end(&mut bytes).unwrap();
    assert_eq!(&bytes[..2], b"ab"); assert!(bytes[2..].iter().all(|byte| *byte == 0));
    let far = (1u64 << 33) + 7; file.seek(SeekFrom::Start(far)).unwrap();
    assert_eq!(alias.stream_position().unwrap(), far);
    assert_eq!(file.seek(SeekFrom::Start(u64::MAX)).unwrap_err().kind(), ErrorKind::InvalidInput);
    file.sync_all().unwrap(); file.sync_data().unwrap();
    assert!(file.metadata().unwrap().modified().unwrap() >= UNIX_EPOCH);
    assert_eq!(file.metadata().unwrap().created().unwrap_err().kind(), ErrorKind::Unsupported);
    let mut permission = file.metadata().unwrap().permissions(); permission.set_readonly(true);
    assert_eq!(file.set_permissions(permission).unwrap_err().kind(), ErrorKind::Unsupported);

    let borrowed = file.as_fd(); let owned = borrowed.try_clone_to_owned().unwrap();
    assert_eq!(unsafe { fcntl(owned.as_raw_fd(), 1) }, 1);
    let raw = owned.into_raw_fd(); assert!(unsafe { fcntl(raw, 1) } >= 0);
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let converted = File::from(owned); assert_eq!(converted.metadata().unwrap().len(), 8192);
    let owned = OwnedFd::from(converted); let raw = owned.as_raw_fd(); drop(owned);
    assert_eq!(unsafe { fcntl(raw, 1) }, -1);
    let raw = file.into_raw_fd(); assert!(unsafe { fcntl(raw, 1) } >= 0);
    let file = unsafe { File::from_raw_fd(raw) }; drop(file); drop(alias);
    assert_eq!(unsafe { fcntl(raw, 1) }, -1);
    let readonly = File::open(format!("{BASE}/owned")).unwrap();
    assert_eq!(readonly.set_len(0).unwrap_err().raw_os_error(), Some(9)); drop(readonly);

    let mut pair = Box::new([0i32; 2]); assert_eq!(unsafe { pipe(pair.as_mut_ptr()) }, 0);
    let reader = unsafe { OwnedFd::from_raw_fd(pair[0]) };
    let writer = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    let extra = reader.try_clone().unwrap(); drop(reader);
    assert_eq!(unsafe { write(writer.as_raw_fd(), b"P".as_ptr().cast(), 1) }, 1);
    assert_eq!(unsafe { read(extra.as_raw_fd(), first.as_mut_ptr().cast(), 1) }, 1); assert_eq!(first[0], b'P');
    let reader_fd = extra.as_raw_fd(); drop(extra); assert_eq!(unsafe { fcntl(reader_fd, 1) }, -1); drop(writer);

    let (mut reader, writer) = std::io::pipe().unwrap();
    assert_eq!(unsafe { fcntl(reader.as_raw_fd(), 1) }, 1);
    assert_eq!(unsafe { fcntl(writer.as_raw_fd(), 1) }, 1);
    let mut writer_copy = writer.try_clone().unwrap();
    let reader_copy = reader.try_clone().unwrap();
    let reader_copy_fd = reader_copy.as_raw_fd();
    let owned = OwnedFd::from(reader_copy);
    let reader_copy = std::io::PipeReader::from(owned);
    drop(reader_copy); assert_eq!(unsafe { fcntl(reader_copy_fd, 1) }, -1);
    writer_copy.write_all(b"upstream pipe").unwrap(); drop(writer_copy);
    let writer_fd = writer.as_raw_fd();
    let stdio = std::process::Stdio::from(writer);
    assert!(unsafe { fcntl(writer_fd, 1) } >= 0);
    drop(stdio); assert_eq!(unsafe { fcntl(writer_fd, 1) }, -1);
    let mut pipe_bytes = Vec::new(); reader.read_to_end(&mut pipe_bytes).unwrap();
    assert_eq!(&pipe_bytes, b"upstream pipe");

    let mut vector = OpenOptions::new().create_new(true).read(true).write(true).open(format!("{BASE}/vector")).unwrap();
    assert_eq!(vector.write_vectored(&[IoSlice::new(b""), IoSlice::new(b"abc"), IoSlice::new(b"def")]).unwrap(), 3);
    vector.seek(SeekFrom::Start(0)).unwrap(); let mut head = vec![0u8; 2]; let mut tail = vec![0u8; 1];
    assert_eq!(vector.read_vectored(&mut [IoSliceMut::new(&mut head), IoSliceMut::new(&mut tail)]).unwrap(), 2);
    assert_eq!(&head, b"ab"); vector.read_exact(&mut tail).unwrap(); assert_eq!(&tail, b"c"); drop(vector);

    let wins = Arc::new(AtomicUsize::new(0)); let dir_wins = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for cpu in 0..8u32 {
        let wins = Arc::clone(&wins); let dir_wins = Arc::clone(&dir_wins);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            assert_eq!(unsafe { sys_thread_set_affinity(cpu) }, 0); assert_eq!(unsafe { sys_thread_cpu() }, cpu);
            start.wait();
            match File::create_new(format!("{BASE}/exclusive")) {
                Ok(_) => { wins.fetch_add(1, Ordering::SeqCst); }
                Err(error) => assert_eq!(error.kind(), ErrorKind::AlreadyExists),
            }
            match fs::create_dir(format!("{BASE}/exclusive-dir")) {
                Ok(_) => { dir_wins.fetch_add(1, Ordering::SeqCst); }
                Err(error) => assert_eq!(error.kind(), ErrorKind::AlreadyExists),
            }
            let path = format!("{BASE}/cpu-{cpu}");
            let expected: Vec<u8> = (0..32768).map(|i| ((i + cpu) % 251) as u8).collect();
            fs::write(&path, &expected).unwrap(); assert_eq!(fs::read(&path).unwrap(), expected);
            let mut append = OpenOptions::new().append(true).open(&path).unwrap();
            append.seek(SeekFrom::Start(0)).unwrap(); append.write_all(b"tail").unwrap(); drop(append);
            assert_eq!(&fs::read(&path).unwrap()[32768..], b"tail");
            fs::rename(&path, format!("{path}-renamed")).unwrap();
            fs::remove_file(format!("{path}-renamed")).unwrap();
        }));
    }
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(wins.load(Ordering::SeqCst), 1); assert_eq!(dir_wins.load(Ordering::SeqCst), 1);

    let every_byte: Vec<u8> = (0..=255).collect();
    let native_string = OsString::from_vec(every_byte.clone());
    assert_eq!(native_string.as_bytes(), &every_byte);
    assert_eq!(native_string.into_vec(), every_byte);
    let raw_path = OsString::from_vec(b"/tmp/rust-native-fs/\xff-byte".to_vec());
    fs::write(&raw_path, b"native bytes").unwrap(); assert_eq!(fs::read(&raw_path).unwrap(), b"native bytes");
    let entries: Vec<_> = fs::read_dir(BASE).unwrap().map(Result::unwrap).collect();
    assert!(entries.iter().any(|entry| entry.file_name().as_encoded_bytes() == b"\xff-byte"));
    assert!(entries.iter().any(|entry| entry.file_name() == "exclusive-dir" && entry.file_type().unwrap().is_dir()));
    assert!(entries.iter().any(|entry| entry.file_name() == "owned" && entry.metadata().unwrap().len() == 8192));
    assert_eq!(fs::remove_dir_all(BASE).unwrap_err().kind(), ErrorKind::Unsupported);
    assert!(fs::metadata(BASE).unwrap().is_dir());
    assert_eq!(unsafe { chdir(c"/tmp/rust-native-fs".as_ptr()) }, 0);
    assert_eq!(fs::canonicalize("owned").unwrap(), PathBuf::from(format!("{BASE}/owned")));
    assert_eq!(unsafe { chdir(c"/".as_ptr()) }, 0);
    for entry in entries {
        if entry.file_type().unwrap().is_dir() { fs::remove_dir(entry.path()).unwrap(); }
        else { fs::remove_file(entry.path()).unwrap(); }
    }
    fs::remove_dir(BASE).unwrap();
    println!("RUST_FILESYSTEM_TEST: PASS cpus=8 owned_fd=1 clone_offset=1 cloexec=1 resize=1 metadata=1 paths=1 dirs=1 exclusive=1 bytes=1 pipes=1");
}
