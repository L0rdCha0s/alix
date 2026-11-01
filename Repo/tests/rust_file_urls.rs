//! Exercise Gecko's actual vendored URL crate and native Alix filesystem.
use std::ffi::OsString;
use std::fs;
use std::os::alix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use url::Url;

unsafe extern "C" {
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}

fn main() {
    assert_eq!(std::env::consts::OS, "alix");
    let cases: Vec<(OsString, &str)> = vec![
        ("/".into(), "file:///"),
        ("/tmp/hello world#?%".into(), "file:///tmp/hello%20world%23%3F%25"),
        ("/tmp/\u{1f980}".into(), "file:///tmp/%F0%9F%A6%80"),
        (OsString::from_vec(b"/tmp/\xff\xfe".to_vec()), "file:///tmp/%FF%FE"),
    ];
    for (path, expected) in cases {
        let url = Url::from_file_path(&path).unwrap();
        assert_eq!(url.as_str(), expected);
        assert_eq!(url.to_file_path().unwrap(), PathBuf::from(path));
        assert_eq!(Url::parse(expected).unwrap().to_file_path().unwrap(), url.to_file_path().unwrap());
    }
    assert!(Url::from_file_path("relative/file").is_err());
    assert_eq!(Url::from_directory_path("/tmp/a b").unwrap().as_str(), "file:///tmp/a%20b/");
    assert_eq!(Url::parse("file://localhost/tmp/local").unwrap().to_file_path().unwrap(), PathBuf::from("/tmp/local"));
    assert!(Url::parse("file://remote.example/tmp/file").unwrap().to_file_path().is_err());
    assert!(Url::parse("data:text/plain,test").unwrap().to_file_path().is_err());
    let nul = Url::parse("file:///tmp/nul%00suffix").unwrap().to_file_path().unwrap();
    assert_eq!(fs::File::open(nul).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

    const BASE: &str = "/tmp/rust-file-urls";
    fs::create_dir(BASE).unwrap();
    let start = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for cpu in 0..8u32 {
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            assert_eq!(unsafe { sys_thread_set_affinity(cpu) }, 0);
            assert_eq!(unsafe { sys_thread_cpu() }, cpu);
            let mut bytes = format!("{BASE}/cpu-{cpu} #?% \u{1f980} ").into_bytes();
            bytes.push(0xff);
            let path = PathBuf::from(OsString::from_vec(bytes));
            let payload: Vec<u8> = (0..8192).map(|index| ((index + cpu) % 251) as u8).collect();
            start.wait();
            fs::write(&path, &payload).unwrap();
            let canonical = fs::canonicalize(&path).unwrap();
            let url = Url::from_file_path(&canonical).unwrap();
            let decoded = Url::parse(url.as_str()).unwrap().to_file_path().unwrap();
            assert_eq!(decoded, canonical);
            assert_eq!(fs::read(&decoded).unwrap(), payload);
            fs::remove_file(decoded).unwrap();
        }));
    }
    for worker in workers { worker.join().unwrap(); }
    fs::remove_dir(BASE).unwrap();
    println!("RUST_FILE_URLS_TEST: PASS cpus=8 actual_url=1 percent=1 unicode=1 raw_bytes=1 local=1 remote_reject=1 nul_reject=1 file_readback=1");
}
