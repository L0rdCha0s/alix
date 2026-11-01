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

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { unsafe { libc::abort() } }

struct Memory(*mut c_void);
impl Drop for Memory { fn drop(&mut self) { unsafe { libc::free(self.0) } } }
struct Stream(*mut libc::FILE);
impl Drop for Stream { fn drop(&mut self) { if !self.0.is_null() { unsafe { libc::fclose(self.0); } } } }

#[no_mangle]
pub unsafe extern "C" fn alix_rust_libc_ffi_test(
    byte: c_char, signed: c_long, unsigned: c_ulong, single: c_float,
    double: c_double, wide: c_ushort, length: size_t,
) -> c_int {
    if byte != -7 || signed != (1 << 42) + 99 || unsigned != (1 << 63) + 17 ||
        single != 1.25 || double != -2.5 || wide != 0xd83d || length != 0x100000007 { return 1; }
    let mut memory = Memory(libc::calloc(2, 4096));
    if memory.0.is_null() { return 2; }
    let replacement = libc::realloc(memory.0, 16384);
    if replacement.is_null() { return 3; }
    memory.0 = replacement;
    let bytes = memory.0.cast::<u8>();
    for index in 0..8192 { *bytes.add(index) = (index % 251) as u8; }
    libc::memset(bytes.add(8192).cast(), 0, 8192);
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
    let host = libc::gethostbyname(b"localhost\0".as_ptr().cast());
    if host.is_null() || (*host).h_addrtype != libc::AF_INET || (*host).h_length != 4 { return 19; }
    0
}
