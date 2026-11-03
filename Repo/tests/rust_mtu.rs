use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, thread};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
unsafe extern "C" {
    fn alix_route_api_test() -> i32;
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(message.into()) }
}
fn run() -> Result<()> {
    let c_result = unsafe { alix_route_api_test() };
    require(c_result == 0, &format!("native C route contract failed at line {c_result}"))?;
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let baseline = mtu::interface_and_mtu(local)?;
    require(!baseline.0.is_empty() && baseline.1 == 1500, "native route MTU/name")?;
    require(mtu::interface_and_mtu(remote)? == baseline, "native default-route interface")?;
    require(mtu::interface_and_mtu(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_err(), "no invented loopback route")?;
    require(mtu::interface_and_mtu(IpAddr::V6(Ipv6Addr::LOCALHOST)).unwrap_err().kind() ==
        std::io::ErrorKind::Unsupported, "IPv6 capability error")?;
    let mut workers = Vec::new();
    for cpu in 0..8u32 {
        let baseline = baseline.clone();
        workers.push(thread::Builder::new().spawn(move || -> Result<()> {
            require(unsafe { sys_thread_set_affinity(cpu) } == 0 &&
                    unsafe { sys_thread_cpu() } == cpu, "native route worker CPU")?;
            for i in 0..64 {
                require(mtu::interface_and_mtu(if i % 2 == 0 { local } else { remote })? == baseline,
                        "concurrent interface/MTU snapshot")?;
            }
            Ok(())
        })?);
    }
    for worker in workers { worker.join().map_err(|_| "route worker panicked")??; }
    Ok(())
}
fn main() {
    match run() {
        Ok(()) => println!("RUST_MTU_TEST: PASS cpus=8 snapshots=512 native_route=1 local=1 default=1 c_abi=1 copy_checks=1 capability_errors=1"),
        Err(error) => { eprintln!("RUST_MTU_TEST: FAIL {error}"); std::process::exit(1); }
    }
}
