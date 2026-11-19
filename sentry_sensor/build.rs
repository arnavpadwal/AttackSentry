use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut lib_path = PathBuf::from(manifest_dir);
    lib_path.push("..");
    lib_path.push("npcap-sdk");
    lib_path.push("Lib");
    lib_path.push("x64");

    println!("cargo:rustc-link-search=native={}", lib_path.display());
}
