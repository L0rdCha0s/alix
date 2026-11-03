#![feature(gethostname,tcp_keepalive)]
use std::{error::Error,io::{self,IoSlice,Read,Write},net::{IpAddr,Ipv4Addr,SocketAddr,TcpListener,TcpStream,ToSocketAddrs,UdpSocket},os::fd::{AsFd,AsRawFd,OwnedFd},thread,time::Duration};
type Result<T>=std::result::Result<T,Box<dyn Error+Send+Sync>>;
unsafe extern "C" {
    fn sys_thread_set_affinity(cpu:u32)->i32;
    fn sys_thread_cpu()->u32;
    fn alix_rust_net_flags(fd:i32)->i32;
}
fn require(value:bool,label:&str)->Result<()>{if value{Ok(())}else{Err(label.to_string().into())}}
fn exchange(cpu:u32,port:u16,solo:bool)->Result<()> {
    require(unsafe{sys_thread_set_affinity(cpu)}==0 && unsafe{sys_thread_cpu()}==cpu,"native CPU affinity")?;
    let endpoint=SocketAddr::from((Ipv4Addr::new(10,0,2,2),port));
    let stream=if cpu%2==1 {
        TcpStream::connect_timeout(&endpoint,Duration::from_secs(5))?
    }else{
        let candidates=["[::1]:1".parse::<SocketAddr>()?,endpoint];
        TcpStream::connect(&candidates[..])?
    };
    require(stream.peer_addr()?==endpoint && stream.local_addr()?.is_ipv4() && stream.local_addr()?.port()!=0,"native endpoint addresses")?;
    require(unsafe{alix_rust_net_flags(stream.as_raw_fd())}==1,"atomic close-on-exec")?;
    require(stream.nodelay()? && !stream.keepalive()? && stream.take_error()?.is_none(),"native option queries")?;
    stream.set_nodelay(true)?;stream.set_keepalive(false)?;
    let mut alias=stream.try_clone()?;
    stream.set_nonblocking(true)?;
    require(unsafe{alix_rust_net_flags(alias.as_fd().as_raw_fd())}==3,"clone shares nonblocking state")?;
    let mut first=vec![0u8;32];
    let error=alias.read(&mut first).expect_err("server waits for the gather request");
    require(error.kind()==io::ErrorKind::WouldBlock,"nonblocking receive classification")?;
    alias.set_nonblocking(false)?;
    require(unsafe{alix_rust_net_flags(stream.as_raw_fd())}==1,"reset through alias preserves close-on-exec")?;
    let original=stream.as_raw_fd();drop(stream);
    if solo{require(unsafe{alix_rust_net_flags(original)}==-9,"original descriptor closed while alias survives")?;}
    let owned:OwnedFd=alias.into();let mut alias=TcpStream::from(owned);
    require(alias.write_vectored(&[IoSlice::new(&[]),IoSlice::new(b"G")])?==1,"standard vectored fallback")?;
    require(alias.peek(&mut first)?==32,"native peek")?;
    let mut data=vec![0u8;32768];alias.read_exact(&mut data)?;
    require(first==data[..32],"peek does not consume")?;
    for (i,byte) in data.iter().enumerate(){require(*byte==(i%251) as u8,"TCP stream payload")?;}
    require(alias.read(&mut first[..1])?==0 && alias.peek(&mut first[..1])?==0,"EOF and peek after FIN")?;
    let raw=alias.as_raw_fd();drop(alias);
    if solo{require(unsafe{alix_rust_net_flags(raw)}==-9,"owned socket closes on drop")?;}
    Ok(())
}
fn run()->Result<()> {
    let args:Vec<_>=std::env::args().collect();require(args.len()==3,"network fixture arguments")?;
    let port=args[1].parse::<u16>()?;let refused=args[2].parse::<u16>()?;
    require(!std::net::hostname()?.is_empty(),"native hostname")?;
    require(("localhost",80).to_socket_addrs()?.any(|a|a==SocketAddr::from((Ipv4Addr::LOCALHOST,80))),"native address lookup")?;
    let endpoint=SocketAddr::from((Ipv4Addr::new(10,0,2,2),port));
    require(TcpStream::connect_timeout(&endpoint,Duration::ZERO).unwrap_err().kind()==io::ErrorKind::InvalidInput,"zero connect deadline rejected")?;
    let error=TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::new(10,0,2,2),refused)),Duration::from_secs(3)).unwrap_err();
    require(error.kind()==io::ErrorKind::ConnectionRefused,"refused native connect")?;
    require(TcpListener::bind((Ipv4Addr::UNSPECIFIED,0)).is_err() && UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)).is_err(),"unavailable transports return errors")?;
    require(TcpStream::connect(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),1)).is_err(),"IPv6 capability failure")?;
    exchange(0,port,true)?;
    let mut workers=Vec::new();
    for cpu in 0..8 {workers.push(thread::Builder::new().spawn(move||exchange(cpu,port,false))?);}
    for worker in workers{worker.join().map_err(|_|"native TCP worker panicked")??;}
    require(unsafe{sys_thread_set_affinity(u32::MAX)}==0,"clear main affinity")?;
    Ok(())
}
fn main(){
    match run(){Ok(())=>println!("RUST_STD_NET_TEST: PASS cpus=8 connections=9 bytes=294912 tcp=1 deadlines=1 fd_ownership=1 clone=1 cloexec=1 nonblock=1 peek=1 eof=1 lookup=1 hostname=1 capability_errors=1"),
        Err(error)=>{eprintln!("RUST_STD_NET_TEST: FAIL {error}");std::process::exit(1);}}
}
