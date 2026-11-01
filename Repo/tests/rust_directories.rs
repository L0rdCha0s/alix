//! Actual Gecko dirs/dirs-sys crates, native account ABI and XDG file parsing.
#![allow(deprecated)]
use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::io::Write;
use std::os::alix::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::{Arc, Barrier};
use std::thread;

unsafe extern "C" {
    fn alix_rust_passwd_size() -> usize;
    fn alix_rust_passwd_directory_offset() -> usize;
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}
const BASE: &str = "/tmp/rust-directories";
const KEYS: &[&str] = &["HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
    "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "XDG_BIN_HOME"];

fn main() {
    assert_eq!(std::env::consts::OS, "alix");
    assert_eq!(std::mem::size_of::<libc::passwd>(), unsafe { alix_rust_passwd_size() });
    assert_eq!(std::mem::offset_of!(libc::passwd, pw_dir), unsafe { alix_rust_passwd_directory_offset() });
    let saved: Vec<_> = KEYS.iter().map(|key| env::var_os(key)).collect();
    for key in KEYS { unsafe { env::remove_var(key); } }
    let mut entry = Box::new(unsafe { std::mem::zeroed::<libc::passwd>() });
    let mut bytes = vec![0u8; 128 * 1024]; let mut result = Box::new(ptr::null_mut());
    assert_eq!(unsafe { libc::getpwuid_r(libc::getuid(), &mut *entry, bytes.as_mut_ptr().cast(), bytes.len(), &mut *result) }, 0);
    assert!(!result.is_null());
    let account_home = PathBuf::from(OsString::from_vec(unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes().to_vec()));
    assert_eq!(dirs::home_dir(), Some(account_home.clone()));
    assert_eq!(dirs_sys::home_dir(), Some(account_home));
    let default_config = dirs::config_dir().unwrap();
    let config_existed = default_config.exists();
    let profile = default_config.join("zen-native-port-contract");
    fs::create_dir_all(&profile).unwrap();
    let preferences = profile.join("prefs.js");
    let mut file = fs::File::create(&preferences).unwrap();
    file.write_all(b"user_pref(\"alix.native.directory.test\", true);\n").unwrap();
    file.sync_all().unwrap(); drop(file);
    assert_eq!(fs::read_to_string(&preferences).unwrap(), "user_pref(\"alix.native.directory.test\", true);\n");
    fs::remove_file(preferences).unwrap(); fs::remove_dir(profile).unwrap();
    if !config_existed { fs::remove_dir(&default_config).unwrap(); }
    let name = CString::new(unsafe { CStr::from_ptr(entry.pw_name) }.to_bytes()).unwrap();
    assert_eq!(unsafe { libc::getpwnam_r(name.as_ptr(), &mut *entry, bytes.as_mut_ptr().cast(), bytes.len(), &mut *result) }, 0);
    assert!(!result.is_null());

    fs::create_dir(BASE).unwrap();
    let home = PathBuf::from(format!("{BASE}/home")); fs::create_dir(&home).unwrap();
    unsafe { env::set_var("HOME", &home); }
    assert_eq!(dirs::home_dir(), Some(home.clone()));
    assert_eq!(dirs::config_dir(), Some(home.join(".config")));
    assert_eq!(dirs::preference_dir(), Some(home.join(".config")));
    assert_eq!(dirs::cache_dir(), Some(home.join(".cache")));
    assert_eq!(dirs::data_dir(), Some(home.join(".local/share")));
    assert_eq!(dirs::data_local_dir(), dirs::data_dir());
    assert_eq!(dirs::state_dir(), Some(home.join(".local/state")));
    assert_eq!(dirs::executable_dir(), Some(home.join(".local/bin")));
    assert_eq!(dirs::font_dir(), Some(home.join(".local/share/fonts")));
    assert_eq!(dirs::runtime_dir(), None);
    unsafe { env::set_var("XDG_CONFIG_HOME", "relative"); env::set_var("XDG_CACHE_HOME", ""); }
    assert_eq!(dirs::config_dir(), Some(home.join(".config")));
    assert_eq!(dirs::cache_dir(), Some(home.join(".cache")));
    for (key, suffix) in [("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"), ("XDG_STATE_HOME", "state"),
        ("XDG_RUNTIME_DIR", "runtime"), ("XDG_BIN_HOME", "bin")] {
        unsafe { env::set_var(key, format!("{BASE}/{suffix}")); }
    }
    assert_eq!(dirs::config_dir(), Some(PathBuf::from(format!("{BASE}/config"))));
    assert_eq!(dirs::cache_dir(), Some(PathBuf::from(format!("{BASE}/cache"))));
    assert_eq!(dirs::data_dir(), Some(PathBuf::from(format!("{BASE}/data"))));
    assert_eq!(dirs::state_dir(), Some(PathBuf::from(format!("{BASE}/state"))));
    assert_eq!(dirs::runtime_dir(), Some(PathBuf::from(format!("{BASE}/runtime"))));
    assert_eq!(dirs::executable_dir(), Some(PathBuf::from(format!("{BASE}/bin"))));
    assert!(!PathBuf::from(format!("{BASE}/runtime")).exists());
    fs::create_dir(format!("{BASE}/config")).unwrap();
    let mut config = format!("XDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DOWNLOAD_DIR=\"{BASE}/Download\\\"Quote\"\nXDG_MUSIC_DIR=\"$HOME/\"\nXDG_DOCUMENTS_DIR=\"relative\"\nXDG_PICTURES_DIR=\"$HOME/Pic\\\\tures\\$Raw\"\nXDG_TEMPLATES_DIR=\"$HOME/Templates\"\nXDG_VIDEOS_DIR=\"{BASE}/Vídeos\"\nXDG_INVALID_DIR=unquoted\n").into_bytes();
    config.extend_from_slice(b"XDG_PUBLICSHARE_DIR=\"$HOME/\xff\"\n");
    fs::write(format!("{BASE}/config/user-dirs.dirs"), &config).unwrap();
    let start = Arc::new(Barrier::new(8)); let mut workers = Vec::new();
    for cpu in 0..8u32 {
        let start = Arc::clone(&start); let home = home.clone();
        workers.push(thread::spawn(move || {
            assert_eq!(unsafe { sys_thread_set_affinity(cpu) }, 0); assert_eq!(unsafe { sys_thread_cpu() }, cpu);
            start.wait();
            assert_eq!(dirs::desktop_dir(), Some(home.join("Desktop")));
            assert_eq!(dirs::download_dir(), Some(PathBuf::from(format!("{BASE}/Download\"Quote"))));
            assert_eq!(dirs::audio_dir(), None); assert_eq!(dirs::document_dir(), None);
            assert_eq!(dirs::picture_dir(), Some(home.join("Pic\\tures$Raw")));
            assert_eq!(dirs::public_dir(), Some(home.join(OsString::from_vec(vec![0xff]))));
            assert_eq!(dirs::template_dir(), Some(home.join("Templates")));
            assert_eq!(dirs::video_dir(), Some(PathBuf::from(format!("{BASE}/Vídeos"))));
            let all = dirs_sys::user_dirs(&home); assert_eq!(all.len(), 6);
            assert_eq!(all["PUBLICSHARE"], home.join(OsString::from_vec(vec![0xff])));
            assert_eq!(all["DESKTOP"], home.join("Desktop"));
        }));
    }
    for worker in workers { worker.join().unwrap(); }
    fs::remove_file(format!("{BASE}/config/user-dirs.dirs")).unwrap();
    fs::remove_dir(format!("{BASE}/config")).unwrap(); fs::remove_dir(home).unwrap(); fs::remove_dir(BASE).unwrap();
    for (key, value) in KEYS.iter().zip(saved) {
        unsafe { match value { Some(value) => env::set_var(key, value), None => env::remove_var(key) } }
    }
    println!("RUST_DIRECTORIES_TEST: PASS cpus=8 actual_dirs=1 xdg=1 defaults=1 overrides=1 user_dirs=1 bytes=1 account=1 profile_io=1");
}
