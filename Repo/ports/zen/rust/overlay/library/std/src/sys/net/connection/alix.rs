//! Native socket ownership and TCP I/O. No foreign libc layout is selected.
use crate::ffi::{CStr,CString,c_void};
use crate::fmt;
use crate::io::{self,BorrowedCursor,IoSlice,IoSliceMut};
use crate::mem;
use crate::net::{Ipv4Addr,Ipv6Addr,Shutdown,SocketAddr,SocketAddrV4,SocketAddrV6,ToSocketAddrs};
use crate::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd,RawFd};
use crate::sys::{AsInner,FromInner,IntoInner,cvt,unsupported};
use crate::sys::fs::FileDesc;
use crate::sys::net_ffi as c;
use crate::time::{Duration,Instant};
use super::each_addr;

pub struct Socket(FileDesc);
impl AsInner<FileDesc> for Socket {fn as_inner(&self)->&FileDesc{&self.0}}
impl IntoInner<FileDesc> for Socket {fn into_inner(self)->FileDesc{self.0}}
impl FromInner<FileDesc> for Socket {fn from_inner(fd:FileDesc)->Self{Self(fd)}}
impl AsRawFd for Socket {fn as_raw_fd(&self)->RawFd{self.0.as_raw_fd()}}
impl AsFd for Socket {fn as_fd(&self)->BorrowedFd<'_>{self.0.as_fd()}}
impl fmt::Debug for Socket {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.debug_struct("Socket").field("fd",&self.as_raw_fd()).finish()}
}

fn with_address<T>(address:&SocketAddr,f:impl FnOnce(*const c_void,u32)->io::Result<T>)->io::Result<T>{
    match address {
        SocketAddr::V4(a)=>{
            let value=c::SockAddrIn{family:c::AF_INET as u16,port:a.port().to_be(),address:c::InAddr{s_addr:u32::from_ne_bytes(a.ip().octets())},zero:[0;8]};
            f((&value as *const c::SockAddrIn).cast(),mem::size_of_val(&value) as u32)
        }
        SocketAddr::V6(a)=>{
            let value=c::SockAddrIn6{family:c::AF_INET6 as u16,port:a.port().to_be(),flow:a.flowinfo(),address:c::In6Addr{bytes:a.ip().octets()},scope:a.scope_id()};
            f((&value as *const c::SockAddrIn6).cast(),mem::size_of_val(&value) as u32)
        }
    }
}
unsafe fn decode_address(address:*const c_void,length:u32)->io::Result<SocketAddr>{
    if length>=mem::size_of::<c::SockAddrIn>() as u32 && unsafe{*(address as *const u16)}==c::AF_INET as u16 {
        let a=unsafe{&*(address as *const c::SockAddrIn)};
        Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(a.address.s_addr.to_ne_bytes()),u16::from_be(a.port))))
    }else if length>=mem::size_of::<c::SockAddrIn6>() as u32 && unsafe{*(address as *const u16)}==c::AF_INET6 as u16 {
        let a=unsafe{&*(address as *const c::SockAddrIn6)};
        Ok(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(a.address.bytes),u16::from_be(a.port),a.flow,a.scope)))
    }else{Err(io::const_error!(io::ErrorKind::InvalidData,"invalid native socket address"))}
}
impl Socket {
    fn new(address:&SocketAddr,kind:i32)->io::Result<Self>{
        let family=if address.is_ipv4(){c::AF_INET}else{c::AF_INET6};
        let fd=cvt(unsafe{c::socket(family,kind|c::SOCK_CLOEXEC,0)})?;
        Ok(Self(FileDesc::from_inner(unsafe{OwnedFd::from_raw_fd(fd)})))
    }
    fn duplicate(&self)->io::Result<Self>{Ok(Self(FileDesc::from_inner(self.as_fd().try_clone_to_owned()?)))}
    fn connect(&self,address:&SocketAddr)->io::Result<()>{with_address(address,|p,n|cvt(unsafe{c::connect(self.as_raw_fd(),p,n)}).map(|_|()))}
    fn bind(&self,address:&SocketAddr)->io::Result<()>{with_address(address,|p,n|cvt(unsafe{c::bind(self.as_raw_fd(),p,n)}).map(|_|()))}
    fn name(&self,peer:bool)->io::Result<SocketAddr>{
        let mut value:c::SockAddrStorage=unsafe{mem::zeroed()};let mut length=mem::size_of_val(&value) as u32;
        let p=(&mut value as *mut c::SockAddrStorage).cast();
        cvt(unsafe{if peer{c::getpeername(self.as_raw_fd(),p,&mut length)}else{c::getsockname(self.as_raw_fd(),p,&mut length)}})?;
        unsafe{decode_address((&value as *const c::SockAddrStorage).cast(),length)}
    }
    fn get<T:Copy>(&self,level:i32,option:i32)->io::Result<T>{
        let mut value=mem::MaybeUninit::<T>::uninit();let mut length=mem::size_of::<T>() as u32;
        cvt(unsafe{c::getsockopt(self.as_raw_fd(),level,option,value.as_mut_ptr().cast(),&mut length)})?;
        if length!=mem::size_of::<T>() as u32{return Err(io::const_error!(io::ErrorKind::InvalidData,"invalid socket option size"));}
        Ok(unsafe{value.assume_init()})
    }
    fn set<T>(&self,level:i32,option:i32,value:T)->io::Result<()>{
        cvt(unsafe{c::setsockopt(self.as_raw_fd(),level,option,(&value as *const T).cast(),mem::size_of::<T>() as u32)}).map(|_|())
    }
    fn set_nonblocking(&self,value:bool)->io::Result<()>{let value=i32::from(value);cvt(unsafe{c::ioctl(self.as_raw_fd(),c::FIONBIO,&value)}).map(|_|())}
    fn take_error(&self)->io::Result<Option<io::Error>>{let value=self.get::<i32>(c::SOL_SOCKET,c::SO_ERROR)?;Ok(if value==0{None}else{Some(io::Error::from_raw_os_error(value))})}
    fn recv(&self,buffer:&mut [u8],flags:i32)->io::Result<usize>{cvt(unsafe{c::recv(self.as_raw_fd(),buffer.as_mut_ptr(),buffer.len(),flags)}).map(|n|n as usize)}
    fn send(&self,buffer:&[u8])->io::Result<usize>{cvt(unsafe{c::send(self.as_raw_fd(),buffer.as_ptr(),buffer.len(),c::MSG_NOSIGNAL)}).map(|n|n as usize)}
    fn recv_from(&self,buffer:&mut [u8],flags:i32)->io::Result<(usize,SocketAddr)>{
        let mut address:c::SockAddrStorage=unsafe{mem::zeroed()};let mut length=mem::size_of_val(&address) as u32;
        let n=cvt(unsafe{c::recvfrom(self.as_raw_fd(),buffer.as_mut_ptr(),buffer.len(),flags,(&mut address as *mut c::SockAddrStorage).cast(),&mut length)})?;
        Ok((n as usize,unsafe{decode_address((&address as *const c::SockAddrStorage).cast(),length)}?))
    }
    fn set_timeout(&self,value:Option<Duration>,option:i32)->io::Result<()>{
        if value==Some(Duration::ZERO){return Err(io::const_error!(io::ErrorKind::InvalidInput,"zero socket timeout"));}
        let value=value.unwrap_or(Duration::ZERO);
        let time=c::TimeVal{seconds:value.as_secs().min(i64::MAX as u64) as i64,micros:if value.as_secs()==0 && value.subsec_nanos()>0{value.subsec_micros().max(1) as i64}else{value.subsec_micros() as i64}};
        self.set(c::SOL_SOCKET,option,time)
    }
    fn timeout(&self,option:i32)->io::Result<Option<Duration>>{
        let value=self.get::<c::TimeVal>(c::SOL_SOCKET,option)?;
        if value.seconds<0 || !(0..1_000_000).contains(&value.micros){return Err(io::const_error!(io::ErrorKind::InvalidData,"invalid socket timeout"));}
        Ok(if value.seconds==0 && value.micros==0{None}else{Some(Duration::new(value.seconds as u64,value.micros as u32*1000))})
    }
    fn set_ttl(&self,ttl:u32)->io::Result<()>{if ttl>255{return Err(io::const_error!(io::ErrorKind::InvalidInput,"invalid IP TTL"));}self.set(c::IPPROTO_IP,c::IP_TTL,ttl as i32)}
    fn ttl(&self)->io::Result<u32>{self.get::<i32>(c::IPPROTO_IP,c::IP_TTL).map(|n|n as u32)}
}

macro_rules! wrapper {
    ($name:ident)=>{
        pub struct $name(Socket);
        impl FromInner<Socket> for $name{fn from_inner(socket:Socket)->Self{Self(socket)}}
        impl AsInner<Socket> for $name{fn as_inner(&self)->&Socket{&self.0}}
        impl $name{pub fn socket(&self)->&Socket{&self.0}pub fn into_socket(self)->Socket{self.0}}
        impl fmt::Debug for $name{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.debug_struct(stringify!($name)).field("fd",&self.0.as_raw_fd()).finish()}}
    }
}
wrapper!(TcpStream);wrapper!(TcpListener);wrapper!(UdpSocket);
impl TcpStream {
    pub fn connect<A:ToSocketAddrs>(address:A)->io::Result<Self>{each_addr(address,|a|{let s=Socket::new(a,c::SOCK_STREAM)?;s.connect(a)?;Ok(Self(s))})}
    pub fn connect_timeout(address:&SocketAddr,timeout:Duration)->io::Result<Self>{
        if timeout.is_zero(){return Err(io::const_error!(io::ErrorKind::InvalidInput,"zero connect timeout"));}
        let s=Socket::new(address,c::SOCK_STREAM)?;s.set_nonblocking(true)?;
        let result=(||{
            match s.connect(address){Ok(())=>return Ok(()),Err(e) if matches!(e.raw_os_error(),Some(114|115))=>{},Err(e)=>return Err(e)}
            let start=Instant::now();
            loop{
                let elapsed=start.elapsed();if elapsed>=timeout{return Err(io::const_error!(io::ErrorKind::TimedOut,"connection timed out"));}
                let remaining=timeout-elapsed;let millis=remaining.as_millis().saturating_add(u128::from(remaining.subsec_nanos()%1_000_000!=0)).min(i32::MAX as u128) as i32;
                let mut entry=c::PollFd{fd:s.as_raw_fd(),events:4,revents:0};
                match cvt(unsafe{c::poll(&mut entry,1,millis)}){
                    Ok(0)=>continue,Ok(_)=>return match s.take_error()?{Some(e)=>Err(e),None=>Ok(())},
                    Err(e) if e.kind()==io::ErrorKind::Interrupted=>continue,Err(e)=>return Err(e)
                }
            }
        })();
        s.set_nonblocking(false)?;result?;Ok(Self(s))
    }
    pub fn set_read_timeout(&self,t:Option<Duration>)->io::Result<()>{self.0.set_timeout(t,c::SO_RCVTIMEO)}
    pub fn set_write_timeout(&self,t:Option<Duration>)->io::Result<()>{self.0.set_timeout(t,c::SO_SNDTIMEO)}
    pub fn read_timeout(&self)->io::Result<Option<Duration>>{self.0.timeout(c::SO_RCVTIMEO)}
    pub fn write_timeout(&self)->io::Result<Option<Duration>>{self.0.timeout(c::SO_SNDTIMEO)}
    pub fn read(&self,b:&mut [u8])->io::Result<usize>{self.0.recv(b,0)}
    pub fn peek(&self,b:&mut [u8])->io::Result<usize>{self.0.recv(b,c::MSG_PEEK)}
    pub fn read_buf(&self,cursor:BorrowedCursor<'_>)->io::Result<()>{crate::io::default_read_buf(|b|self.read(b),cursor)}
    pub fn read_vectored(&self,b:&mut [IoSliceMut<'_>])->io::Result<usize>{crate::io::default_read_vectored(|b|self.read(b),b)}
    pub fn is_read_vectored(&self)->bool{false}
    pub fn write(&self,b:&[u8])->io::Result<usize>{self.0.send(b)}
    pub fn write_vectored(&self,b:&[IoSlice<'_>])->io::Result<usize>{crate::io::default_write_vectored(|b|self.write(b),b)}
    pub fn is_write_vectored(&self)->bool{false}
    pub fn peer_addr(&self)->io::Result<SocketAddr>{self.0.name(true)}
    pub fn socket_addr(&self)->io::Result<SocketAddr>{self.0.name(false)}
    pub fn duplicate(&self)->io::Result<Self>{self.0.duplicate().map(Self)}
    pub fn shutdown(&self,how:Shutdown)->io::Result<()>{let how=match how{Shutdown::Read=>0,Shutdown::Write=>1,Shutdown::Both=>2};cvt(unsafe{c::shutdown(self.0.as_raw_fd(),how)}).map(|_|())}
    pub fn set_linger(&self,value:Option<Duration>)->io::Result<()>{self.0.set(c::SOL_SOCKET,c::SO_LINGER,c::Linger{enabled:i32::from(value.is_some()),seconds:value.unwrap_or(Duration::ZERO).as_secs().min(i32::MAX as u64) as i32})}
    pub fn linger(&self)->io::Result<Option<Duration>>{let v=self.0.get::<c::Linger>(c::SOL_SOCKET,c::SO_LINGER)?;Ok(if v.enabled==0{None}else{Some(Duration::from_secs(v.seconds.max(0) as u64))})}
    pub fn set_keepalive(&self,value:bool)->io::Result<()>{self.0.set(c::SOL_SOCKET,c::SO_KEEPALIVE,i32::from(value))}
    pub fn keepalive(&self)->io::Result<bool>{self.0.get::<i32>(c::SOL_SOCKET,c::SO_KEEPALIVE).map(|v|v!=0)}
    pub fn set_nodelay(&self,value:bool)->io::Result<()>{self.0.set(c::IPPROTO_TCP,c::TCP_NODELAY,i32::from(value))}
    pub fn nodelay(&self)->io::Result<bool>{self.0.get::<i32>(c::IPPROTO_TCP,c::TCP_NODELAY).map(|v|v!=0)}
    pub fn set_ttl(&self,value:u32)->io::Result<()>{self.0.set_ttl(value)}
    pub fn ttl(&self)->io::Result<u32>{self.0.ttl()}
    pub fn take_error(&self)->io::Result<Option<io::Error>>{self.0.take_error()}
    pub fn set_nonblocking(&self,value:bool)->io::Result<()>{self.0.set_nonblocking(value)}
}
impl TcpListener {
    pub fn bind<A:ToSocketAddrs>(address:A)->io::Result<Self>{each_addr(address,|a|{let s=Socket::new(a,c::SOCK_STREAM)?;s.bind(a)?;cvt(unsafe{c::listen(s.as_raw_fd(),128)})?;Ok(Self(s))})}
    pub fn socket_addr(&self)->io::Result<SocketAddr>{self.0.name(false)}
    pub fn accept(&self)->io::Result<(TcpStream,SocketAddr)>{
        let mut address:c::SockAddrStorage=unsafe{mem::zeroed()};let mut length=mem::size_of_val(&address) as u32;
        let fd=cvt(unsafe{c::accept4(self.0.as_raw_fd(),(&mut address as *mut c::SockAddrStorage).cast(),&mut length,c::SOCK_CLOEXEC)})?;
        let socket=Socket(FileDesc::from_inner(unsafe{OwnedFd::from_raw_fd(fd)}));
        Ok((TcpStream(socket),unsafe{decode_address((&address as *const c::SockAddrStorage).cast(),length)}?))
    }
    pub fn duplicate(&self)->io::Result<Self>{self.0.duplicate().map(Self)}
    pub fn set_ttl(&self,value:u32)->io::Result<()>{self.0.set_ttl(value)}
    pub fn ttl(&self)->io::Result<u32>{self.0.ttl()}
    pub fn set_only_v6(&self,v:bool)->io::Result<()>{self.0.set(41,c::IPV6_V6ONLY,i32::from(v))}
    pub fn only_v6(&self)->io::Result<bool>{self.0.get::<i32>(41,c::IPV6_V6ONLY).map(|v|v!=0)}
    pub fn take_error(&self)->io::Result<Option<io::Error>>{self.0.take_error()}
    pub fn set_nonblocking(&self,v:bool)->io::Result<()>{self.0.set_nonblocking(v)}
}
impl UdpSocket {
    pub fn bind<A:ToSocketAddrs>(address:A)->io::Result<Self>{each_addr(address,|a|{let s=Socket::new(a,c::SOCK_DGRAM)?;s.bind(a)?;Ok(Self(s))})}
    pub fn peer_addr(&self)->io::Result<SocketAddr>{self.0.name(true)}
    pub fn socket_addr(&self)->io::Result<SocketAddr>{self.0.name(false)}
    pub fn recv_from(&self,b:&mut [u8])->io::Result<(usize,SocketAddr)>{self.0.recv_from(b,0)}
    pub fn peek_from(&self,b:&mut [u8])->io::Result<(usize,SocketAddr)>{self.0.recv_from(b,c::MSG_PEEK)}
    pub fn send_to(&self,b:&[u8],a:&SocketAddr)->io::Result<usize>{with_address(a,|p,n|cvt(unsafe{c::sendto(self.0.as_raw_fd(),b.as_ptr(),b.len(),c::MSG_NOSIGNAL,p,n)}).map(|v|v as usize))}
    pub fn duplicate(&self)->io::Result<Self>{self.0.duplicate().map(Self)}
    pub fn set_read_timeout(&self,t:Option<Duration>)->io::Result<()>{self.0.set_timeout(t,c::SO_RCVTIMEO)}
    pub fn set_write_timeout(&self,t:Option<Duration>)->io::Result<()>{self.0.set_timeout(t,c::SO_SNDTIMEO)}
    pub fn read_timeout(&self)->io::Result<Option<Duration>>{self.0.timeout(c::SO_RCVTIMEO)}
    pub fn write_timeout(&self)->io::Result<Option<Duration>>{self.0.timeout(c::SO_SNDTIMEO)}
    pub fn set_broadcast(&self,v:bool)->io::Result<()>{self.0.set(c::SOL_SOCKET,c::SO_BROADCAST,i32::from(v))}
    pub fn broadcast(&self)->io::Result<bool>{self.0.get::<i32>(c::SOL_SOCKET,c::SO_BROADCAST).map(|v|v!=0)}
    pub fn set_multicast_loop_v4(&self,_:bool)->io::Result<()>{unsupported()}
    pub fn multicast_loop_v4(&self)->io::Result<bool>{unsupported()}
    pub fn set_multicast_ttl_v4(&self,_:u32)->io::Result<()>{unsupported()}
    pub fn multicast_ttl_v4(&self)->io::Result<u32>{unsupported()}
    pub fn set_multicast_loop_v6(&self,_:bool)->io::Result<()>{unsupported()}
    pub fn multicast_loop_v6(&self)->io::Result<bool>{unsupported()}
    pub fn join_multicast_v4(&self,_:&Ipv4Addr,_:&Ipv4Addr)->io::Result<()>{unsupported()}
    pub fn join_multicast_v6(&self,_:&Ipv6Addr,_:u32)->io::Result<()>{unsupported()}
    pub fn leave_multicast_v4(&self,_:&Ipv4Addr,_:&Ipv4Addr)->io::Result<()>{unsupported()}
    pub fn leave_multicast_v6(&self,_:&Ipv6Addr,_:u32)->io::Result<()>{unsupported()}
    pub fn set_ttl(&self,v:u32)->io::Result<()>{self.0.set_ttl(v)}
    pub fn ttl(&self)->io::Result<u32>{self.0.ttl()}
    pub fn take_error(&self)->io::Result<Option<io::Error>>{self.0.take_error()}
    pub fn set_nonblocking(&self,v:bool)->io::Result<()>{self.0.set_nonblocking(v)}
    pub fn recv(&self,b:&mut [u8])->io::Result<usize>{self.0.recv(b,0)}
    pub fn peek(&self,b:&mut [u8])->io::Result<usize>{self.0.recv(b,c::MSG_PEEK)}
    pub fn send(&self,b:&[u8])->io::Result<usize>{self.0.send(b)}
    pub fn connect<A:ToSocketAddrs>(&self,a:A)->io::Result<()>{each_addr(a,|a|self.0.connect(a))}
}

pub struct LookupHost(crate::vec::IntoIter<SocketAddr>);
impl Iterator for LookupHost{type Item=SocketAddr;fn next(&mut self)->Option<SocketAddr>{self.0.next()}}
pub fn lookup_host(host:&str,port:u16)->io::Result<LookupHost>{
    let host=CString::new(host).map_err(|_|io::const_error!(io::ErrorKind::InvalidInput,"NUL in hostname"))?;
    let service=CString::new(port.to_string()).unwrap();
    let mut hints:c::AddrInfo=unsafe{mem::zeroed()};hints.family=c::AF_INET;hints.socktype=c::SOCK_STREAM;
    let mut list=crate::ptr::null_mut();let error=unsafe{c::getaddrinfo(host.as_ptr(),service.as_ptr(),&hints,&mut list)};
    if error!=0{return Err(io::Error::other(unsafe{CStr::from_ptr(c::gai_strerror(error))}.to_string_lossy().into_owned()));}
    let mut addresses=crate::vec::Vec::new();let mut item=list;
    while !item.is_null(){
        let value=unsafe{&*item};
        if !value.address.is_null(){if let Ok(a)=unsafe{decode_address(value.address,value.length)}{addresses.push(a);}}
        item=value.next;
    }
    unsafe{c::freeaddrinfo(list)};
    if addresses.is_empty(){return Err(io::Error::NO_ADDRESSES);}
    Ok(LookupHost(addresses.into_iter()))
}
