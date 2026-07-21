fn main() {
    let mut b = cc::Build::new();
    b.file("csrc/ctshim.c");
    // valgrind headers live wherever it was installed (e.g. ~/.local/include).
    if let Ok(inc) = std::env::var("VALGRIND_INCLUDE") {
        b.include(inc);
    }
    b.compile("ctshim");
    println!("cargo:rerun-if-changed=csrc/ctshim.c");
    println!("cargo:rerun-if-env-changed=VALGRIND_INCLUDE");
}
