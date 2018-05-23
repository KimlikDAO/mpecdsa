// build.rs for ecdsa signing application
// 
// need special build to handle avx2 impl of sha256 hashing.
//

use std::process::Command;
use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    Command::new("gcc").args(&["src/sha256_octa.c", "-c", "-mavx2", "-O3", "-fPIC", "-fopenmp", "-Wa,-q", "-o"])
                       .arg(&format!("{}/sha256_octa.o", out_dir))
                       .status().unwrap();
    Command::new("ar").args(&["-crus", "libsha256_octa.a", "sha256_octa.o"])
                      .current_dir(&Path::new(&out_dir))
                      .status().unwrap();

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=sha256_octa");
    println!("cargo:rustc-link-lib=gomp");
}