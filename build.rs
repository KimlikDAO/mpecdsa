// build.rs for ecdsa signing application
//
// need special build to handle avx2 impl of sha256 hashing.
//

use std::env;
use std::path::Path;
use std::process::Command;
use std::string::String;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}", out_dir);

    let mut extra_args = vec!["-O3", "-fPIC"];

    if std::env::var("TARGET").unwrap().contains("apple-darwin") {
        extra_args.push("-Wa,-q")
    }

    let omp_flag = env::var("DEP_OPENMP_FLAG").unwrap_or("".to_string());
    if cfg!(feature = "openmp") {
        extra_args.push(&omp_flag);
    }

    let cc = if std::env::var("CC").is_ok() {
        std::env::var("CC").unwrap()
    } else {
        String::from("gcc")
    };

    let ar = if std::env::var("AR").is_ok() {
        std::env::var("AR").unwrap()
    } else {
        String::from("ar")
    };

    if std::env::var("TARGET").unwrap().contains("x86_64") {
        Command::new(&cc)
            .args(&["src/sha256_octa.c", "-c", "-mavx2", "-o"])
            .arg(&format!("{}/sha256_multi.o", out_dir))
            .args(&extra_args)
            .status()
            .unwrap();
        Command::new(&ar)
            .args(&["-crus", "libsha256_multi.a", "sha256_multi.o"])
            .current_dir(&Path::new(&out_dir))
            .status()
            .unwrap();
        println!("cargo:rustc-link-lib=static=sha256_multi");
    }

    for file in ["blake2s", "blake2sp"].iter() {
        if std::env::var("TARGET").unwrap().contains("x86_64") {
            Command::new(&cc)
                .args(&[&format!("blake2/sse/{}.c", file), "-c", "-mavx2", "-o"])
                .arg(&format!("{}/{}.o", out_dir, file))
                .args(&extra_args)
                .status()
                .unwrap();
        } else if cfg!(feature = "rpi3") {
            Command::new(&cc)
                .args(&[
                    &format!("blake2/neon/{}.c", file),
                    "-c",
                    "-mcpu=cortex-a53",
                    "-mfpu=neon-fp-armv8",
                    "-mneon-for-64bits",
                    "-mfloat-abi=hard",
                    "-o",
                ])
                .arg(&format!("{}/{}.o", out_dir, file))
                .args(&extra_args)
                .status()
                .unwrap();
        } else if std::env::var("TARGET").unwrap().contains("aarch64") {
            Command::new(&cc)
                .args(&[
                    &format!("blake2/neon/{}.c", file),
                    "-c",
                    "-march=armv8-a",
                    "-mfpu=neon-fp-armv8",
                    "-mfloat-abi=hard",
                    "-o",
                ])
                .arg(&format!("{}/{}.o", out_dir, file))
                .args(&extra_args)
                .status()
                .unwrap();
        } else if std::env::var("TARGET").unwrap().contains("armv7") {
            Command::new(&cc)
                .args(&[
                    &format!("blake2/neon/{}.c", file),
                    "-c",
                    "-march=armv7-a",
                    "-mfpu=neon-vfpv4",
                    "-mfloat-abi=hard",
                    "-o",
                ])
                .arg(&format!("{}/{}.o", out_dir, file))
                .args(&extra_args)
                .status()
                .unwrap();
        } else {
            Command::new(&cc)
                .args(&[&format!("blake2/ref/{}-ref.c", file), "-c", "-o"])
                .arg(&format!("{}/{}.o", out_dir, file))
                .args(&extra_args)
                .status()
                .unwrap();
        }
    }

    Command::new(&cc)
        .args(&["src/blake2_multi.c", "-c", "-o"])
        .arg(&format!("{}/blake2_multi.o", out_dir))
        .args(&extra_args)
        .status()
        .unwrap();
    Command::new(&ar)
        .args(&[
            "-crus",
            "libblake2.a",
            "blake2s.o",
            "blake2sp.o",
            "blake2_multi.o",
        ])
        .current_dir(&Path::new(&out_dir))
        .status()
        .unwrap();
    println!("cargo:rustc-link-lib=static=blake2");
}
