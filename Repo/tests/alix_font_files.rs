use libz_rs_sys as _;
unsafe extern "C" { fn alix_font_files_test_main() -> i32; }
fn main() { std::process::exit(unsafe { alix_font_files_test_main() }); }
