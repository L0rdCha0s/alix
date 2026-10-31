#!/usr/bin/env python3
"""Execute the real vendored Alix Rust entropy backend against syscall models."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ports/zen/upstream/firefox-159.0/third_party/rust/getrandom/src"


def main():
    backend = (SOURCE / "backends/alix.rs").read_text()
    # Rename only the FFI names, so the host Rust runtime keeps its own RNG.
    backend = backend.replace("fn getrandom(", "fn alix_model_getrandom(")
    backend = backend.replace("getrandom(dest.", "alix_model_getrandom(dest.")
    backend = backend.replace("__errno_location", "alix_model_errno")
    program = r'''
#![allow(dead_code, unused_imports)]
use std::{cell::UnsafeCell, mem::MaybeUninit, sync::Mutex};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Error(i32);
impl Error {
    const ERRNO_NOT_POSITIVE: Self = Self(1);
    const UNEXPECTED: Self = Self(2);
    fn from_neg_error_code(code: i32) -> Self { assert!(code < 0); Self(code) }
}
#[path = "UTIL_PATH"] mod util;
mod backends { BACKEND_SOURCE }
fn fill_uninit(dest: &mut [MaybeUninit<u8>]) -> Result<&mut [u8], Error> {
    backends::fill_inner(dest)?;
    Ok(unsafe { util::slice_assume_init_mut(dest) })
}
#[derive(Clone, Copy)]
struct Step { count: isize, error: i32 }
struct Model { steps: Vec<Step>, index: usize, base: usize, total: usize,
               calls: Vec<(usize, usize)> }
static MODEL: Mutex<Option<Model>> = Mutex::new(None);
thread_local! { static ERRNO: UnsafeCell<i32> = const { UnsafeCell::new(0) }; }
#[no_mangle]
extern "C" fn alix_model_errno() -> *mut i32 { ERRNO.with(|slot| slot.get()) }
#[no_mangle]
extern "C" fn alix_model_getrandom(buffer: *mut std::ffi::c_void, length: usize, flags: u32) -> isize {
    assert_eq!(flags, 0);
    let mut state = MODEL.lock().unwrap();
    let model = state.as_mut().unwrap();
    assert!(model.index < model.steps.len(), "unexpected entropy/fallback call");
    let offset = buffer as usize - model.base;
    assert_eq!(length, model.total - offset);
    model.calls.push((offset, length));
    let step = model.steps[model.index];
    model.index += 1;
    ERRNO.with(|slot| unsafe { *slot.get() = step.error });
    if step.count > 0 && step.count as usize <= length {
        for index in 0..step.count as usize {
            unsafe { buffer.cast::<u8>().add(index).write((offset + index).wrapping_mul(17).wrapping_add(3) as u8); }
        }
    }
    step.count
}
fn check(length: usize, steps: &[Step], expected: Result<(), Error>, filled: usize, calls: &[(usize, usize)]) {
    let mut output = vec![MaybeUninit::new(0xa5u8); length];
    *MODEL.lock().unwrap() = Some(Model { steps: steps.to_vec(), index: 0,
        base: output.as_mut_ptr() as usize, total: length, calls: Vec::new() });
    assert_eq!(backends::fill_inner(&mut output), expected);
    let state = MODEL.lock().unwrap().take().unwrap();
    assert_eq!(state.index, steps.len());
    assert_eq!(state.calls, calls);
    for (index, byte) in output.into_iter().enumerate() {
        let expected = if index < filled { index.wrapping_mul(17).wrapping_add(3) as u8 } else { 0xa5 };
        assert_eq!(unsafe { byte.assume_init() }, expected);
    }
}
fn main() {
    let interrupted = Step { count: -1, error: 4 };
    check(0, &[], Ok(()), 0, &[]);
    for length in [1usize, 32, 257, 4096] {
        check(length, &[Step { count: length as isize, error: 0 }], Ok(()), length, &[(0, length)]);
    }
    check(9, &[interrupted, Step { count: 2, error: 0 }, interrupted,
               Step { count: 3, error: 0 }, Step { count: 4, error: 0 }],
          Ok(()), 9, &[(0, 9), (0, 9), (2, 7), (2, 7), (5, 4)]);
    check(9, &[Step { count: 3, error: 0 }, Step { count: -1, error: 5 }],
          Err(Error(-5)), 3, &[(0, 9), (3, 6)]);
    for error in [5, 11, 38] {
        check(8, &[Step { count: -1, error }], Err(Error(-error)), 0, &[(0, 8)]);
    }
    for error in [0, -1, i32::MIN] {
        check(8, &[Step { count: -1, error }], Err(Error::ERRNO_NOT_POSITIVE), 0, &[(0, 8)]);
    }
    for count in [0, 9, isize::MAX] {
        check(8, &[Step { count, error: 0 }], Err(Error::UNEXPECTED), 0, &[(0, 8)]);
    }
    println!("native Alix getrandom backend partial reads, EINTR, errno and no-fallback contracts passed");
}
'''
    program = program.replace("UTIL_PATH", str(SOURCE / "util.rs")).replace("BACKEND_SOURCE", backend)
    compiler = os.environ.get("HOST_RUSTC") or shutil.which("rustc")
    if not compiler:
        raise RuntimeError("a host Rust compiler is required")
    with tempfile.TemporaryDirectory(prefix="alix-getrandom-test-") as directory:
        source = Path(directory) / "test.rs"
        binary = Path(directory) / "test"
        source.write_text(program)
        subprocess.run([compiler, "--edition=2021", "-C", "opt-level=2", str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
