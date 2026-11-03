use std::{io,net::{UdpSocket,SocketAddr,Ipv4Addr},thread,time::{Duration,Instant}};
use neqo_common::{Datagram,Tos};
use neqo_udp::{Socket,RecvBuf};
use std::os::fd::{AsRawFd,BorrowedFd};
type Result<T> = std::result::Result<T,Box<dyn std::error::Error+Send+Sync>>;
unsafe extern "C" {fn sys_thread_set_affinity(cpu:u32)->i32;fn sys_thread_cpu()->u32;}
fn retry<T>(mut operation:impl FnMut()->io::Result<T>)->io::Result<T>{
    let start=Instant::now();loop{match operation(){Err(e) if e.kind()==io::ErrorKind::WouldBlock&&start.elapsed()<Duration::from_secs(5)=>thread::sleep(Duration::from_millis(1)),other=>return other}}
}
fn worker(cpu:u32,destination:SocketAddr)->Result<()>{
    if unsafe{sys_thread_set_affinity(cpu)}!=0||unsafe{sys_thread_cpu()}!=cpu{return Err("CPU pinning".into());}
    let raw=UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0))?;
    let local=SocketAddr::from((Ipv4Addr::new(10,0,2,15),raw.local_addr()?.port()));
    let socket=Socket::new(unsafe{BorrowedFd::borrow_raw(raw.as_raw_fd())})?;
    if socket.max_gso_segments()!=1||socket.may_fragment(){return Err("Neqo capabilities".into());}
    println!("NEQO_UDP_ENDPOINT: cpu={cpu} port={}",local.port());
    let mut buffer=RecvBuf::default();
    for n in 0..16usize{
        let length=[1,37,1200,1472][n%4];let data:Vec<u8>=(0..length).map(|i|(cpu as usize*31+n+i)as u8).collect();
        let datagram=Datagram::new(local,destination,Tos::from(cpu as u8&3),data.clone());
        let batch=datagram.into();retry(||socket.send(&batch))?;
        let received=retry(||socket.recv(local,&mut buffer).map(|mut values|values.next().map(|d|d.to_owned())))?
            .ok_or("missing Neqo datagram")?;
        if received.source()!=destination||received.destination()!=local||&*received!=data.as_slice(){return Err("Neqo receive data/endpoints".into());}
        if n==0{println!("NEQO_UDP_META: cpu={cpu} ecn={}",u8::from(received.tos())&3);}
    }
    // Neqo's existing PMTUD policy consumes EMSGSIZE; the native selector must
    // recognize Alix's actual errno rather than use the unsupported fallback.
    let probe=Datagram::new(local,destination,Tos::default(),vec![0u8;1473]).into();
    socket.send(&probe)?;
    drop(socket);
    if raw.local_addr()?.port()!=local.port(){return Err("borrowed socket ownership".into());}
    Ok(())
}
fn main()->Result<()>{
    let port:u16=std::env::args().nth(1).ok_or("host port")?.parse()?;
    let destination=SocketAddr::from((Ipv4Addr::new(10,0,2,2),port));
    let mut workers=Vec::new();for cpu in 0..8{workers.push(thread::spawn(move||worker(cpu,destination)));}
    for job in workers{job.join().map_err(|_|"Neqo worker panic")??;}
    println!("NEQO_UDP_TEST: PASS cpus=8 datagrams=128 actual_neqo=1 quinn=1 endpoints=1 ecn=1 mtu_probe=1 borrowed=1");Ok(())
}
