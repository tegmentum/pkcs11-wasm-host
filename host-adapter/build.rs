use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let wit_dir = manifest_dir.join("..").join("wit");

    println!("cargo:rerun-if-changed={}", wit_dir.display());
    println!("cargo:rustc-env=PKCS11_WIT_ROOT={}", wit_dir.display());
}
