use std::{io::{self, IoSliceMut}, net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket}, thread, time::{Duration, Instant}};
use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
unsafe extern "C" {
    fn alix_udp_socket_api_test(port: u32) -> i32;
    fn alix_udp_cancel_child() -> i32;
    fn alix_udp_cancel_test(port: u32) -> i32;
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}
fn require(value: bool, message: &str) -> Result<()> { if value { Ok(()) } else { Err(message.into()) } }
fn retry<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let start = Instant::now();
    loop { match operation() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock && start.elapsed() < Duration::from_secs(5) => thread::sleep(Duration::from_millis(1)),
        result => return result,
    } }
}
fn worker(cpu: u32, destination: SocketAddr) -> Result<()> {
    require(unsafe { sys_thread_set_affinity(cpu) } == 0 && unsafe { sys_thread_cpu() } == cpu, "native UDP CPU")?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let local = socket.local_addr()?;
    let alias = socket.try_clone()?; drop(socket);
    let state = UdpSocketState::new((&alias).into())?;
    require(state.max_gso_segments() == 1 && state.gro_segments() == 1 && !state.may_fragment(), "native UDP capabilities")?;
    state.set_recv_buffer_size((&alias).into(), 16384)?;
    state.set_send_buffer_size((&alias).into(), 16384)?;
    require(state.recv_buffer_size((&alias).into())? == 16384 && state.send_buffer_size((&alias).into())? == 16384, "real buffer budgets")?;
    println!("QUINN_UDP_ENDPOINT: cpu={cpu} port={}", local.port());
    let mut bytes = vec![0u8; 1473]; let mut output = vec![0u8; 2048];
    let mut meta = [RecvMeta::default()];
    for n in 0..32usize {
        let length = [0, 1, 17, 1200, 1472][n % 5];
        for i in 0..length { bytes[i] = (cpu as usize * 31 + n + i) as u8; }
        let transmit = Transmit { destination, ecn: EcnCodepoint::from_bits(cpu as u8), contents: &bytes[..length],
            segment_size: None, src_ip: Some(IpAddr::V4(Ipv4Addr::new(10,0,2,15))) };
        retry(|| state.try_send((&alias).into(), &transmit))?;
        let count = retry(|| { let mut buffers = [IoSliceMut::new(&mut output)]; state.recv((&alias).into(), &mut buffers, &mut meta) })?;
        require(count == 1 && meta[0].addr == destination && meta[0].len == length && meta[0].stride == length &&
            meta[0].dst_ip == Some(Ipv4Addr::new(10,0,2,15).into()) && meta[0].interface_index.is_some() &&
            output[..length] == bytes[..length], "actual Quinn datagram/endpoint metadata")?;
        if n == 0 { println!("QUINN_UDP_META: cpu={cpu} ecn={}", meta[0].ecn.map_or(0, |v| v as u8)); }
    }
    let oversized = Transmit { destination, ecn: None, contents: &bytes, segment_size: None, src_ip: None };
    let error = state.try_send((&alias).into(), &oversized).unwrap_err();
    require(quinn_udp::is_msg_size_err(&error), "native EMSGSIZE recognition")?;
    let segmentation = Transmit { destination, ecn: None, contents: &bytes[..32], segment_size: Some(16), src_ip: None };
    require(state.try_send((&alias).into(), &segmentation).unwrap_err().kind() == io::ErrorKind::Unsupported, "no ignored segmentation metadata")?;
    Ok(())
}
fn run() -> Result<()> {
    let port = std::env::args().nth(1).ok_or("host UDP port")?.parse::<u16>()?;
    let result = unsafe { alix_udp_socket_api_test(port as u32) };
    require(result == 0, &format!("native UDP C API failed at line {result}"))?;
    let destination = SocketAddr::from((Ipv4Addr::new(10,0,2,2), port));
    let mut workers = Vec::new();
    for cpu in 0..8 { workers.push(thread::Builder::new().spawn(move || worker(cpu, destination))?); }
    for worker in workers { worker.join().map_err(|_| "Quinn UDP worker panicked")??; }
    let result = unsafe { alix_udp_cancel_test(port as u32) };
    require(result == 0, &format!("UDP blocked-caller lifetime failed at C line {result}"))?;
    require(UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_err(), "IPv6 capability error")?;
    Ok(())
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("udp-cancel-child") {
        std::process::exit(unsafe { alix_udp_cancel_child() });
    }
    match run() {
    Ok(()) => println!("QUINN_UDP_TEST: PASS cpus=8 datagrams=256 std_udp=1 socket_api=1 quinn=1 ecn=1 source_override=1 endpoints=1 clone=1 nonblock=1 zero=1 mtu=1 gso_errors=1 killed_caller=1 fresh_progress=1 port_release=1"),
    Err(error) => { eprintln!("QUINN_UDP_TEST: FAIL {error}"); std::process::exit(1); }
} }
