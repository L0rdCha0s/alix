//! Cargo cannot discover objects passed to our external native link driver.
//! Track them so a rebuilt libc cannot leave the smoke ELF silently stale.
fn main() {
    println!("cargo:rerun-if-env-changed=ALIX_RUNTIME_LINK_INPUTS");
    let inputs = std::env::var("ALIX_RUNTIME_LINK_INPUTS")
        .expect("the Alix runtime builder must supply native linker dependencies");
    assert!(!inputs.is_empty(), "native linker dependencies must not be empty");
    for input in inputs.lines() {
        assert!(!input.is_empty(), "native linker dependency must not be empty");
        println!("cargo:rerun-if-changed={input}");
    }
}
