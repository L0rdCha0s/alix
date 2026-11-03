//! Socket layouts and values from Alix's own public C headers.
#![allow(dead_code)]
use super::ffi::{c_char,c_int,c_void};
pub const AF_INET:c_int=2;
pub const AF_INET6:c_int=10;
pub const SOCK_STREAM:c_int=1;
pub const SOCK_DGRAM:c_int=2;
pub const SOCK_CLOEXEC:c_int=1<<17;
pub const SOL_SOCKET:c_int=1;
pub const SO_ERROR:c_int=4;
pub const SO_KEEPALIVE:c_int=9;
pub const SO_BROADCAST:c_int=6;
pub const SO_LINGER:c_int=13;
pub const SO_RCVTIMEO:c_int=20;
pub const SO_SNDTIMEO:c_int=21;
pub const IPPROTO_IP:c_int=0;
pub const IPPROTO_TCP:c_int=6;
pub const IP_TTL:c_int=2;
pub const TCP_NODELAY:c_int=1;
pub const IPV6_V6ONLY:c_int=26;
pub const MSG_PEEK:c_int=2;
pub const MSG_NOSIGNAL:c_int=0x4000;
pub const FIONBIO:u64=0x5421;

#[repr(C)]
pub struct InAddr {pub s_addr:u32}
#[repr(C,align(4))]
pub struct In6Addr {pub bytes:[u8;16]}
#[repr(C)]
pub struct SockAddrIn {pub family:u16,pub port:u16,pub address:InAddr,pub zero:[u8;8]}
#[repr(C)]
pub struct SockAddrIn6 {pub family:u16,pub port:u16,pub flow:u32,pub address:In6Addr,pub scope:u32}
#[repr(C)]
pub struct SockAddrStorage {pub family:u16,pub padding:[u8;118],pub align:u64}
#[repr(C)]
pub struct PollFd {pub fd:c_int,pub events:i16,pub revents:i16}
#[repr(C)]
#[derive(Clone,Copy)]
pub struct TimeVal {pub seconds:i64,pub micros:i64}
#[repr(C)]
#[derive(Clone,Copy)]
pub struct Linger {pub enabled:c_int,pub seconds:c_int}
#[repr(C)]
pub struct AddrInfo {
    pub flags:c_int,pub family:c_int,pub socktype:c_int,pub protocol:c_int,
    pub length:u32,pub address:*mut c_void,pub canonical:*mut c_char,pub next:*mut AddrInfo,
}
const _:()=assert!(crate::mem::size_of::<SockAddrIn>()==16);
const _:()=assert!(crate::mem::size_of::<SockAddrIn6>()==28);
const _:()=assert!(crate::mem::size_of::<SockAddrStorage>()==128);
const _:()=assert!(crate::mem::size_of::<AddrInfo>()==48);
const _:()=assert!(crate::mem::offset_of!(AddrInfo,address)==24);
unsafe extern "C" {
    pub fn socket(family:c_int,kind:c_int,protocol:c_int)->c_int;
    pub fn connect(fd:c_int,address:*const c_void,length:u32)->c_int;
    pub fn bind(fd:c_int,address:*const c_void,length:u32)->c_int;
    pub fn listen(fd:c_int,backlog:c_int)->c_int;
    pub fn accept4(fd:c_int,address:*mut c_void,length:*mut u32,flags:c_int)->c_int;
    pub fn send(fd:c_int,data:*const u8,length:usize,flags:c_int)->isize;
    pub fn recv(fd:c_int,data:*mut u8,length:usize,flags:c_int)->isize;
    pub fn sendto(fd:c_int,data:*const u8,length:usize,flags:c_int,address:*const c_void,address_length:u32)->isize;
    pub fn recvfrom(fd:c_int,data:*mut u8,length:usize,flags:c_int,address:*mut c_void,address_length:*mut u32)->isize;
    pub fn shutdown(fd:c_int,direction:c_int)->c_int;
    pub fn getsockname(fd:c_int,address:*mut c_void,length:*mut u32)->c_int;
    pub fn getpeername(fd:c_int,address:*mut c_void,length:*mut u32)->c_int;
    pub fn getsockopt(fd:c_int,level:c_int,option:c_int,value:*mut c_void,length:*mut u32)->c_int;
    pub fn setsockopt(fd:c_int,level:c_int,option:c_int,value:*const c_void,length:u32)->c_int;
    pub fn ioctl(fd:c_int,request:u64,...)->c_int;
    pub fn poll(entries:*mut PollFd,count:usize,timeout:c_int)->c_int;
    pub fn getaddrinfo(host:*const c_char,service:*const c_char,hints:*const AddrInfo,result:*mut *mut AddrInfo)->c_int;
    pub fn freeaddrinfo(result:*mut AddrInfo);
    pub fn gai_strerror(error:c_int)->*const c_char;
    pub fn gethostname(buffer:*mut u8,size:usize)->c_int;
}
