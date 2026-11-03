use std::{io::{Read, IoSlice}, mem::{align_of, offset_of, size_of, MaybeUninit},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream},
    os::fd::{AsRawFd, OwnedFd}, thread, time::Duration};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type, MaybeUninitSlice};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
unsafe extern "C" {
    fn alix_socket2_layout(values: *const usize, count: usize) -> i32;
    fn alix_socket2_flags(fd: i32) -> i32;
    fn alix_socket2_send_flags() -> i32;
    fn alix_socket2_message_faults(fd: i32) -> i32;
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(message.into()) }
}
fn exchange(cpu: u32, port: u16, solo: bool) -> Result<()> {
    require(unsafe { sys_thread_set_affinity(cpu) } == 0 &&
            unsafe { sys_thread_cpu() } == cpu, "native Socket2 CPU")?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    require(socket.r#type()? == Type::STREAM && unsafe { alix_socket2_flags(socket.as_raw_fd()) } == 1,
            "native type and CLOEXEC")?;
    let endpoint = SocketAddr::from((Ipv4Addr::new(10, 0, 2, 2), port));
    socket.connect_timeout(&SockAddr::from(endpoint), Duration::from_secs(10))?;
    require(socket.peer_addr()?.as_socket() == Some(endpoint) && !socket.nonblocking()?,
            "Socket2 connection/name/deadline")?;
    socket.set_tcp_nodelay(true)?;
    require(socket.tcp_nodelay()?, "native TCP_NODELAY")?;
    socket.set_keepalive(false)?;
    require(!socket.keepalive()? && socket.set_keepalive(true).is_err(), "keepalive capability error")?;
    let faults = unsafe { alix_socket2_message_faults(socket.as_raw_fd()) };
    require(faults == 0, &format!("message capture/capability checks at C line {faults}"))?;
    let alias = socket.try_clone()?;
    alias.set_nonblocking(true)?;
    require(socket.nonblocking()? && unsafe { alix_socket2_flags(alias.as_raw_fd()) } == 3,
            "shared nonblocking state and cloned CLOEXEC")?;
    let mut peek = [MaybeUninit::<u8>::uninit(); 32];
    require(socket.recv(&mut peek).unwrap_err().kind() == std::io::ErrorKind::WouldBlock,
            "native nonblocking empty receive")?;
    socket.set_nonblocking(false)?;
    let original = socket.as_raw_fd(); drop(socket);
    if solo { require(unsafe { alix_socket2_flags(original) } == -9, "original Socket2 FD closes")?; }
    require(alias.send_vectored_with_flags(&[IoSlice::new(b"G"), IoSlice::new(b""),
        IoSlice::new(b"E"), IoSlice::new(b"T")], unsafe { alix_socket2_send_flags() })? == 3,
        "Socket2 gather send")?;
    require(alias.peek(&mut peek)? == peek.len(), "Socket2 peek")?;
    let first: Vec<_> = peek.into_iter().map(|byte| unsafe { byte.assume_init() }).collect();
    let mut prefix = vec![MaybeUninit::<u8>::uninit(); 31];
    let mut chunk = vec![MaybeUninit::<u8>::uninit(); 4096];
    let mut bytes = Vec::with_capacity(32768);
    while bytes.len() < 32768 {
        let count = {
            let mut empty = [];
            let mut vectors = [MaybeUninitSlice::new(&mut prefix), MaybeUninitSlice::new(&mut empty),
                MaybeUninitSlice::new(&mut chunk)];
            alias.recv_vectored(&mut vectors)?.0
        };
        require(count != 0, "unexpected early Socket2 EOF")?;
        let first_count = count.min(prefix.len());
        bytes.extend(prefix[..first_count].iter().map(|byte| unsafe { byte.assume_init() }));
        bytes.extend(chunk[..count - first_count].iter().map(|byte| unsafe { byte.assume_init() }));
    }
    require(first == bytes[..32], "Socket2 peek preserves bytes")?;
    for (i, &byte) in bytes.iter().enumerate() { require(byte == (i % 251) as u8, "Socket2 payload")?; }
    let fd: OwnedFd = alias.into();
    let socket = Socket::from(fd);
    let mut stream: TcpStream = socket.into();
    let reference = SockRef::from(&stream);
    require(reference.peer_addr()?.as_socket() == Some(endpoint), "borrowed native TCP socket")?;
    let mut eof = [MaybeUninit::<u8>::uninit(); 1];
    let mut vectors = [MaybeUninitSlice::new(&mut eof)];
    require(reference.recv_vectored(&mut vectors)?.0 == 0, "message scatter EOF")?;
    require(reference.send_vectored_with_flags(&[IoSlice::new(b"X")],
        unsafe { alix_socket2_send_flags() }).unwrap_err().kind() == std::io::ErrorKind::BrokenPipe,
        "message SIGPIPE suppression after EOF")?;
    drop(reference);
    require(stream.read(&mut [0u8; 1])? == 0, "Socket2/std EOF ownership")?;
    Ok(())
}
fn run() -> Result<()> {
    let values = [size_of::<libc::sockaddr_storage>(), size_of::<libc::sockaddr_in6>(),
        size_of::<libc::in6_addr>(), align_of::<libc::in6_addr>(), size_of::<libc::sockaddr_un>(),
        size_of::<libc::ipv6_mreq>(), size_of::<libc::ip_mreqn>(), size_of::<libc::msghdr>(),
        offset_of!(libc::msghdr, msg_iovlen), size_of::<libc::pollfd>(), offset_of!(libc::pollfd, revents)];
    require(unsafe { alix_socket2_layout(values.as_ptr(), values.len()) } == 1, "native C/Rust socket layouts")?;
    let ipv6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 11, 12));
    require(SockAddr::from(ipv6).as_socket() == Some(ipv6), "IPv6 address flow/scope metadata")?;
    require(Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).is_err(), "IPv6 transport capability error")?;
    let atomic = Socket::new_raw(Domain::IPV4, Type::STREAM.nonblocking().cloexec(), Some(Protocol::TCP))?;
    require(unsafe { alix_socket2_flags(atomic.as_raw_fd()) } == 3, "atomic native creation flags")?;
    drop(atomic);
    let args: Vec<_> = std::env::args().collect();
    require(args.len() == 3, "Socket2 test arguments")?;
    let port = args[1].parse::<u16>()?; let refused = args[2].parse::<u16>()?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    let endpoint = SockAddr::from(SocketAddr::from((Ipv4Addr::new(10, 0, 2, 2), refused)));
    require(socket.connect_timeout(&endpoint, Duration::from_secs(3)).unwrap_err().kind() ==
        std::io::ErrorKind::ConnectionRefused, "Socket2 refused connect")?;
    drop(socket);
    exchange(0, port, true)?;
    let mut workers = Vec::new();
    for cpu in 0..8 { workers.push(thread::Builder::new().spawn(move || exchange(cpu, port, false))?); }
    for worker in workers { worker.join().map_err(|_| "Socket2 worker panicked")??; }
    Ok(())
}
fn main() {
    match run() {
        Ok(()) => println!("RUST_SOCKET2_TEST: PASS cpus=8 connections=9 bytes=294912 all_feature=1 tcp=1 deadlines=1 clone=1 fd_ownership=1 cloexec=1 nonblock=1 peek=1 eof=1 c_abi=1 gather=1 scatter=1 message_faults=1 capability_errors=1"),
        Err(error) => { eprintln!("RUST_SOCKET2_TEST: FAIL {error}"); std::process::exit(1); }
    }
}
