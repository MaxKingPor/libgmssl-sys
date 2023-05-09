fn main() {
    let path = cmake::Config::new("GmSSL")
        .define("ENABLE_SM2_EXTS", "ON")
        .define("BUILD_SHARED_LIBS", "OFF")
        .configure_arg("--no-warn-unused-cli") // 交叉编译时防止cmake 报错
        .build_target("gmssl")
        .build();
    println!("cargo:rerun-if-changed=GmSSL");
    println!(
        "cargo:rustc-link-search=native={}/build/bin",
        path.display()
    );
    println!("cargo:rustc-link-lib=static=gmssl");
    println!("cargo:rerun-if-changed=wrapper.h");

    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
}
