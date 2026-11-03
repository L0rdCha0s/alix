//! Exercise the actual Gecko-vendored libc declarations against native Alix.
#![no_std]

extern crate libc;
use libc::{c_char, c_double, c_float, c_int, c_long, c_ulong, c_ushort, c_void, size_t};

const _: [(); 8] = [(); core::mem::size_of::<c_long>()];
const _: [(); 8] = [(); core::mem::size_of::<size_t>()];
const _: [(); 2] = [(); core::mem::size_of::<libc::wchar_t>()];
const _: () = assert!(c_char::MIN == -128);
const _: [(); 16] = [(); core::mem::size_of::<libc::sockaddr_in>()];
const _: [(); 4] = [(); core::mem::size_of::<libc::socklen_t>()];
const _: () = assert!(core::mem::offset_of!(libc::sockaddr_in, sin_addr) == 4);
const _: [(); 48] = [(); core::mem::size_of::<libc::addrinfo>()];
const _: () = assert!(core::mem::offset_of!(libc::addrinfo, ai_addr) == 24);
const _: [(); 32] = [(); core::mem::size_of::<libc::fd_set>()];
const _: [(); 16] = [(); core::mem::size_of::<libc::timeval>()];
const _: () = assert!(libc::FD_SETSIZE == 256);
const _: [(); 325] = [(); core::mem::size_of::<libc::utsname>()];
const _: [(); 4] = [(); core::mem::size_of::<libc::uid_t>()];
const _: [(); 4] = [(); core::mem::size_of::<libc::gid_t>()];
const _: [(); 16] = [(); core::mem::size_of::<libc::rlimit>()];
const _: [(); 8] = [(); core::mem::size_of::<libc::ip_mreq>()];
const _: [(); 8] = [(); core::mem::size_of::<libc::sigset_t>()];
const _: [(); 88] = [(); core::mem::size_of::<libc::stat>()];
const _: [(); 24] = [(); core::mem::size_of::<libc::flock>()];
const _: () = assert!(core::mem::offset_of!(libc::flock,l_type)==20 && core::mem::offset_of!(libc::flock,l_whence)==22);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { unsafe { libc::abort() } }
unsafe extern "C" {
    fn alix_rust_stat_abi(bytes:size_t,inode:size_t,owner:size_t,blocks:size_t)->c_int;
    fn alix_rust_ioctl_abi(readable:c_ulong,nonblock:c_ulong,set_close:c_ulong,clear_close:c_ulong,win_size:size_t)->c_int;
    fn alix_rust_identity_abi(size:size_t,machine_offset:size_t,uid:libc::uid_t,gid:libc::gid_t)->c_int;
    fn alix_rust_sync_abi(flags:u64)->c_int;
    fn alix_rust_limit_abi(bytes:size_t,nofile:c_int,address:c_int,infinity:libc::rlim_t,multicast:size_t)->c_int;
    fn alix_rust_signal_abi(bytes:size_t,block:c_int,unblock:c_int,setmask:c_int)->c_int;
    fn alix_rust_mapping_abi(shared:c_int,private:c_int,sync:c_int,asynchronous:c_int,invalidate:c_int)->c_int;
}

struct Memory(*mut c_void);
impl Drop for Memory { fn drop(&mut self) { unsafe { libc::free(self.0) } } }
struct Stream(*mut libc::FILE);
impl Drop for Stream { fn drop(&mut self) { if !self.0.is_null() { unsafe { libc::fclose(self.0); } } } }

#[no_mangle]
pub unsafe extern "C" fn alix_rust_libc_ffi_test(
    byte: c_char, signed: c_long, unsigned: c_ulong, single: c_float,
    double: c_double, wide: c_ushort, length: size_t,
) -> c_int {
    if alix_rust_ioctl_abi(libc::FIONREAD,libc::FIONBIO,libc::FIOCLEX,libc::FIONCLEX,core::mem::size_of::<libc::winsize>())!=1 {return 33;}
    if byte != -7 || signed != (1 << 42) + 99 || unsigned != (1 << 63) + 17 ||
        single != 1.25 || double != -2.5 || wide != 0xd83d || length != 0x100000007 { return 1; }
    let mut memory = Memory(libc::calloc(2, 4096));
    if memory.0.is_null() { return 2; }
    let replacement = libc::realloc(memory.0, 16384);
    if replacement.is_null() { return 3; }
    memory.0 = replacement;
    let bytes = memory.0.cast::<u8>();
    if alix_rust_stat_abi(core::mem::size_of::<libc::stat>(), core::mem::offset_of!(libc::stat,st_ino),
        core::mem::offset_of!(libc::stat,st_uid), core::mem::offset_of!(libc::stat,st_blocks)) != 1 {return 60;}
    if alix_rust_signal_abi(core::mem::size_of::<libc::sigset_t>(),libc::SIG_BLOCK,
        libc::SIG_UNBLOCK,libc::SIG_SETMASK)!=1 {return 43;}
    let signal_set=bytes.add(13000).cast::<libc::sigset_t>();
    let old_mask=signal_set.add(1);
    let signal_number=old_mask.add(1).cast::<c_int>();
    *signal_set=1u64 << (libc::SIGUSR1-1);
    if libc::sigprocmask(libc::SIG_BLOCK,signal_set,old_mask)!=0 ||
        libc::raise(libc::SIGUSR1)!=0 {return 44;}
    *libc::__errno_location()=libc::EDOM;
    if libc::sigwait(signal_set,signal_number)!=0 || *signal_number!=libc::SIGUSR1 ||
        *libc::__errno_location()!=libc::EDOM ||
        libc::sigprocmask(libc::SIG_SETMASK,old_mask,core::ptr::null_mut())!=0 {return 45;}
    for index in 0..8192 { *bytes.add(index) = (index % 251) as u8; }
    libc::memset(bytes.add(8192).cast(), 0, 8192);
    if alix_rust_identity_abi(core::mem::size_of::<libc::utsname>(),
        core::mem::offset_of!(libc::utsname,machine),libc::getuid(),libc::getgid())!=1 ||
        libc::geteuid()!=libc::getuid() || libc::getegid()!=libc::getgid() {return 37;}
    let identity=bytes.add(12288).cast::<libc::utsname>();
    let hostname=bytes.add(13000).cast::<c_char>();
    *hostname.add(65)=0x5a;
    if libc::uname(identity)!=0 || libc::gethostname(hostname,65)!=0 || *hostname.add(65)!=0x5a ||
        libc::strcmp((*identity).sysname.as_ptr(),b"Alix\0".as_ptr().cast())!=0 ||
        libc::strcmp((*identity).machine.as_ptr(),b"x86_64\0".as_ptr().cast())!=0 ||
        libc::strcmp((*identity).nodename.as_ptr(),hostname)!=0 ||
        libc::strncmp((*identity).version.as_ptr(),b"build:".as_ptr().cast(),6)!=0 ||
        libc::strlen((*identity).version.as_ptr())!=46 {return 38;}
    *hostname=0x5a;
    if libc::gethostname(hostname,1)!=-1 || *libc::__errno_location()!=libc::ENAMETOOLONG ||
        *hostname!=0x5a || libc::gethostname(core::ptr::null_mut(),65)!=-1 ||
        *libc::__errno_location()!=libc::EFAULT || libc::uname(core::ptr::null_mut())!=-1 ||
        *libc::__errno_location()!=libc::EFAULT {return 39;}
    if libc::strlen(b"Alix\0".as_ptr().cast()) != 4 || libc::getpid() <= 0 { return 4; }
    let name = b"ALIX_RUST_FFI\0".as_ptr().cast();
    if libc::setenv(name, b"native\0".as_ptr().cast(), 1) != 0 { return 5; }
    let value = libc::getenv(name);
    if value.is_null() || libc::strcmp(value, b"native\0".as_ptr().cast()) != 0 || libc::unsetenv(name) != 0 { return 6; }
    let pages = libc::sysconf(libc::_SC_PHYS_PAGES);
    let available = libc::sysconf(libc::_SC_AVPHYS_PAGES);
    if pages <= 0 || available <= 0 || available > pages { return 24; }
    let path = b"/tmp/rust-libc-ffi\0".as_ptr().cast();
    let mut stream = Stream(libc::fopen(path, b"w+b\0".as_ptr().cast()));
    if stream.0.is_null() { return 7; }
    if libc::fwrite(bytes.cast(), 1, 8192, stream.0) != 8192 || libc::fflush(stream.0) != 0 ||
        libc::fsync(libc::fileno(stream.0)) != 0 ||
        libc::ftello(stream.0) != 8192 || libc::fseeko(stream.0, 0, libc::SEEK_SET) != 0 ||
        libc::fread(bytes.add(8192).cast(), 1, 8192, stream.0) != 8192 ||
        libc::memcmp(bytes.cast(), bytes.add(8192).cast(), 8192) != 0 { return 8; }
    if alix_rust_mapping_abi(libc::MAP_SHARED,libc::MAP_PRIVATE,libc::MS_SYNC,
        libc::MS_ASYNC,libc::MS_INVALIDATE)!=1 {return 46;}
    let mapped=libc::mmap(core::ptr::null_mut(),8192,libc::PROT_READ|libc::PROT_WRITE,
        libc::MAP_SHARED,libc::fileno(stream.0),0);
    let peer=libc::mmap(core::ptr::null_mut(),4096,libc::PROT_READ,
        libc::MAP_SHARED,libc::fileno(stream.0),4096);
    if mapped==libc::MAP_FAILED || peer==libc::MAP_FAILED {return 47;}
    *mapped.cast::<u8>().add(4096+123)=0x5b;
    if *peer.cast::<u8>().add(123)!=0x5b || libc::msync(mapped,8192,libc::MS_SYNC)!=0 ||
        libc::mprotect(mapped,4096,libc::PROT_READ)!=0 ||
        libc::munmap(mapped,8192)!=0 || libc::munmap(peer,4096)!=0 {return 48;}
    let far = (1 << 33) + 7;
    if libc::fseeko(stream.0, far, libc::SEEK_SET) != 0 || libc::ftello(stream.0) != far ||
        libc::fileno(stream.0) < 0 { return 9; }
    let read_set = bytes.add(12288).cast::<libc::fd_set>();
    let write_set = read_set.add(1);
    let timeout = write_set.add(1).cast::<libc::timeval>();
    *timeout = libc::timeval { tv_sec: 0, tv_usec: 0 };
    libc::FD_ZERO(read_set); libc::FD_ZERO(write_set);
    let fd = libc::fileno(stream.0);
    libc::FD_SET(fd, read_set); libc::FD_SET(fd, write_set);
    if libc::select(fd + 1, read_set, write_set, core::ptr::null_mut(), timeout) != 2 ||
        !libc::FD_ISSET(fd, read_set) || !libc::FD_ISSET(fd, write_set) { return 25; }
    libc::FD_CLR(fd, read_set);
    if libc::FD_ISSET(fd, read_set) { return 26; }
    if libc::ftruncate(fd, 9216) != 0 || libc::ftello(stream.0) != far ||
        libc::pread(fd, bytes.add(8192).cast(), 1024, 8192) != 1024 { return 27; }
    for index in 8192..9216 { if *bytes.add(index) != 0 { return 28; } }
    if libc::ftruncate(fd, 3) != 0 { return 29; }
    let info = bytes.add(10000).cast::<libc::stat>();
    let peer_info = info.add(1);
    if libc::fstat(fd, info) != 0 || libc::stat(path, peer_info) != 0 ||
        (*info).st_ino == 0 || (*info).st_dev == 0 || (*info).st_nlink != 1 || (*info).st_size != 3 ||
        (*peer_info).st_ino != (*info).st_ino || (*peer_info).st_dev != (*info).st_dev ||
        (*info).st_blksize != 4096 || (*info).st_blocks != 1 {return 61;}
    if libc::fchown(fd, u32::MAX, u32::MAX) != 0 || libc::lstat(path, peer_info) != 0 ||
        (*peer_info).st_uid != (*info).st_uid || (*peer_info).st_gid != (*info).st_gid {return 62;}
    if libc::fchmod(fd, libc::S_IRUSR|libc::S_IWUSR|libc::S_IRGRP) != 0 || libc::fstat(fd,info) != 0 ||
        (*info).st_mode & 0o777 != 0o640 {return 63;}
    let record=bytes.add(10400).cast::<libc::flock>();
    *record=libc::flock{l_start:1,l_len:2,l_pid:123,l_type:libc::F_WRLCK as i16,l_whence:libc::SEEK_SET as i16};
    if libc::fcntl(fd,libc::F_SETLK,record)!=0 || libc::fcntl(fd,libc::F_GETLK,record)!=0 ||
        (*record).l_type!=libc::F_UNLCK as i16 || (*record).l_pid!=123 {return 64;}
    (*record).l_start=0;(*record).l_len=0;
    if libc::fcntl(fd,libc::F_SETLK,record)!=0 {return 65;}
    let times=bytes.add(10200).cast::<libc::timeval>();
    *times=libc::timeval{tv_sec:123456789,tv_usec:0};*times.add(1)=libc::timeval{tv_sec:123456790,tv_usec:0};
    if libc::utimes(path,times)!=0 || libc::stat(path,peer_info)!=0 ||
        (*peer_info).st_atime!=123456789 || (*peer_info).st_mtime!=123456790 {return 66;}
    let readable=bytes.add(8192).cast::<c_int>();let nonblock=readable.add(1);*nonblock=1;
    if libc::ioctl(fd,libc::FIONREAD,readable)!=0 || *readable!=0 ||
        libc::ioctl(fd,libc::FIONBIO,nonblock)!=0 || libc::fcntl(fd,libc::F_GETFL)&libc::O_NONBLOCK==0 {return 34;}
    *nonblock=0;
    if libc::ioctl(fd,libc::FIONBIO,nonblock)!=0 || libc::fcntl(fd,libc::F_GETFL)&libc::O_NONBLOCK!=0 ||
        libc::ioctl(fd,libc::FIOCLEX)!=0 || libc::fcntl(fd,libc::F_GETFD)!=libc::FD_CLOEXEC ||
        libc::ioctl(fd,libc::FIONCLEX)!=0 || libc::fcntl(fd,libc::F_GETFD)!=0 {return 35;}
    if libc::ioctl(fd,libc::TIOCGWINSZ,readable)!=-1 || *libc::__errno_location()!=libc::ENOTTY {return 36;}
    let resolved = libc::realpath(path, core::ptr::null_mut());
    if resolved.is_null() { return 30; }
    let correct = libc::strcmp(path, resolved) == 0;
    libc::free(resolved.cast());
    if !correct || libc::rmdir(path) != -1 { return 31; }
    let directory = b"/tmp/rust-libc-ffi-dir\0".as_ptr().cast();
    if libc::mkdir(directory, 0o777) != 0 || libc::rmdir(directory) != 0 { return 32; }
    if libc::fclose(stream.0) != 0 { stream.0 = core::ptr::null_mut(); return 10; }
    stream.0 = core::ptr::null_mut();
    if libc::unlink(path) != 0 { return 11; }
    let absent = Stream(libc::fopen(path, b"rb\0".as_ptr().cast()));
    if !absent.0.is_null() { return 12; }
    let descriptors = bytes.cast::<c_int>();
    if libc::pipe(descriptors) != 0 { return 13; }
    let reader = *descriptors;
    let writer = *descriptors.add(1);
    let result = libc::write(writer, b"ffi".as_ptr().cast(), 3) == 3 &&
        libc::ioctl(reader,libc::FIONREAD,readable)==0 && *readable==3 &&
        libc::read(reader, bytes.add(16).cast(), 3) == 3 &&
        libc::memcmp(bytes.add(16).cast(), b"ffi".as_ptr().cast(), 3) == 0;
    let closed = libc::close(reader) == 0 && libc::close(writer) == 0;
    if !result || !closed { return 14; }
    let descriptor = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0);
    if descriptor < 0 { return 15; }
    let mut kind: c_int = 0;
    let mut option_length = core::mem::size_of::<c_int>() as libc::socklen_t;
    let mut endpoint: libc::sockaddr_in = core::mem::zeroed();
    let mut address_length = core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let result = libc::getsockopt(descriptor, libc::SOL_SOCKET, libc::SO_TYPE,
            (&mut kind as *mut c_int).cast(), &mut option_length) == 0 &&
        kind == libc::SOCK_STREAM && option_length == 4 &&
        libc::getsockname(descriptor, (&mut endpoint as *mut libc::sockaddr_in).cast(), &mut address_length) == 0 &&
        address_length == 16 && endpoint.sin_family == libc::AF_INET as libc::sa_family_t &&
        endpoint.sin_port == 0 && endpoint.sin_addr.s_addr == 0 &&
        libc::ntohs(libc::htons(0x1234)) == 0x1234;
    let closed = libc::close(descriptor) == 0;
    if !result || !closed { return 16; }
    let hints = libc::addrinfo { ai_family: libc::AF_INET, ai_socktype: libc::SOCK_STREAM,
        ai_flags: libc::AI_NUMERICHOST | libc::AI_CANONNAME, ..core::mem::zeroed() };
    let mut addresses: *mut libc::addrinfo = core::ptr::null_mut();
    if libc::getaddrinfo(b"127.0.0.1\0".as_ptr().cast(), b"443\0".as_ptr().cast(), &hints, &mut addresses) != 0 || addresses.is_null() { return 17; }
    let result = (*addresses).ai_family == libc::AF_INET && (*addresses).ai_addrlen == 16 &&
        !(*addresses).ai_addr.is_null() && (*addresses).ai_next.is_null() && !(*addresses).ai_canonname.is_null() &&
        libc::strcmp((*addresses).ai_canonname, b"127.0.0.1\0".as_ptr().cast()) == 0 &&
        libc::getnameinfo((*addresses).ai_addr, (*addresses).ai_addrlen, bytes.add(32).cast(), 64,
            bytes.add(96).cast(), 16, libc::NI_NUMERICHOST | libc::NI_NUMERICSERV) == 0 &&
        libc::strcmp(bytes.add(32).cast(), b"127.0.0.1\0".as_ptr().cast()) == 0 &&
        libc::strcmp(bytes.add(96).cast(), b"443\0".as_ptr().cast()) == 0;
    libc::freeaddrinfo(addresses);
    if !result { return 18; }
    let sync_flags=(libc::O_RDWR|libc::O_CREAT|libc::O_TRUNC|libc::O_SYNC) as u64;
    if alix_rust_sync_abi(sync_flags)!=1 {return 40;}
    let sync_path=b"/tmp/rust-libc-sync\0".as_ptr().cast();
    let sync_fd=libc::open(sync_path,sync_flags,0o600 as libc::c_uint);
    if sync_fd<0 || libc::write(sync_fd,b"sync".as_ptr().cast(),4)!=4 ||
        libc::fcntl(sync_fd,libc::F_GETFL)&libc::O_SYNC==0 ||
        libc::fcntl(sync_fd,libc::F_SETFL,libc::O_NONBLOCK)!=0 ||
        libc::fcntl(sync_fd,libc::F_GETFL)&libc::O_SYNC==0 || libc::close(sync_fd)!=0 ||
        libc::unlink(sync_path)!=0 {return 41;}
    let host = libc::gethostbyname(b"localhost\0".as_ptr().cast());
    if host.is_null() || (*host).h_addrtype != libc::AF_INET || (*host).h_length != 4 { return 19; }
    if alix_rust_limit_abi(core::mem::size_of::<libc::rlimit>(),libc::RLIMIT_NOFILE,
        libc::RLIMIT_AS,libc::RLIM_INFINITY,core::mem::size_of::<libc::ip_mreq>())!=1 {return 42;}
    let limits=bytes.add(14336).cast::<libc::rlimit>();let quota=limits.add(1);
    if libc::getrlimit(libc::RLIMIT_NOFILE,limits)!=0 || (*limits).rlim_cur!=256 || (*limits).rlim_max!=256 {return 43;}
    *quota=*limits;(*quota).rlim_cur=3;
    if libc::setrlimit(libc::RLIMIT_NOFILE,quota)!=0 ||
        libc::open(sync_path,(libc::O_CREAT|libc::O_RDWR) as u64,0o600 as libc::c_uint)!=-1 ||
        *libc::__errno_location()!=libc::EMFILE || libc::setrlimit(libc::RLIMIT_NOFILE,limits)!=0 {return 44;}
    0
}
