//! Exercise the actual vendored libloading/ash crates against native ELF DSOs.
use libloading::{Library,Symbol};
use std::{ffi::{c_void,OsStr},sync::Arc,thread};
unsafe extern "C" {
    fn alix_rust_loader_event_count(kind:i32)->i32;
    fn sys_thread_set_affinity(cpu:u32)->i32;
    fn sys_thread_cpu()->u32;
}
#[no_mangle]
pub unsafe extern "C" fn alix_rust_dynamic_loading_test()->i32 {
    if libloading::library_filename("alix-rust-loader")!=OsStr::new("libalix-rust-loader.so") {return 1;}
    if unsafe{Library::new("/tmp/missing-rust-loader.so")}.is_ok(){return 2;}
    let library=match unsafe{Library::new("/tmp/libalix-rust-loader.so")} {Ok(value)=>Arc::new(value),Err(_)=>return 3};
    if unsafe{alix_rust_loader_event_count(0)}!=1 || unsafe{alix_rust_loader_event_count(1)}!=0{return 4;}
    {
        let answer:Symbol<unsafe extern "C" fn()->i32>=match unsafe{library.get(b"rust_loader_answer")} {Ok(value)=>value,Err(_)=>return 5};
        if unsafe{answer()}!=42{return 6;}
        let null:Symbol<*mut c_void>=match unsafe{library.get(b"rust_loader_null")} {Ok(value)=>value,Err(_)=>return 7};
        if !(*null).is_null(){return 8;}
    }
    let mut workers=Vec::new();
    for cpu in 0..8u32 {
        let owner=Arc::clone(&library);
        let worker=thread::Builder::new().spawn(move ||->Result<(),u32>{
            if unsafe{sys_thread_set_affinity(cpu)}!=0 || unsafe{sys_thread_cpu()}!=cpu{return Err(1);}
            let increment:Symbol<unsafe extern "C" fn()->u32>=unsafe{owner.get(b"rust_loader_increment")}.map_err(|_|2u32)?;
            for round in 0..64u32 {if unsafe{increment()}!=round+4{return Err(3);}}
            if unsafe{owner.get::<unsafe extern "C" fn()>(b"rust_loader_missing")}.is_ok(){return Err(4);}
            let answer:Symbol<unsafe extern "C" fn()->i32>=unsafe{owner.get(b"rust_loader_answer")}.map_err(|_|5u32)?;
            if unsafe{answer()}!=42{return Err(6);}
            Ok(())
        });
        match worker {Ok(value)=>workers.push(value),Err(_)=>return 9}
    }
    for worker in workers {match worker.join(){Ok(Ok(()))=>{},_=>return 10}}
    drop(library);
    if unsafe{alix_rust_loader_event_count(1)}!=1{return 11;}
    let process=libloading::os::alix::Library::this();
    let count:libloading::os::alix::Symbol<unsafe extern "C" fn(i32)->i32>=match unsafe{process.get(b"alix_rust_loader_event_count")} {Ok(value)=>value,Err(_)=>return 12};
    if unsafe{count(0)}!=1{return 13;}
    // The native library loader must report absent Vulkan support normally.
    // This exercises ash's Alix ELF path without fabricating a GPU backend.
    if unsafe{ash::Entry::load()}.is_ok(){return 14;}
    0
}
