use std::{env, path::PathBuf};

fn main() {
    // 编译GmSSL
    let path = cmake::Config::new("GmSSL")
        .define("ENABLE_SM2_EXTS", "ON") // sm2 扩展
        .define("BUILD_SHARED_LIBS", "OFF") // 静态链接
        .configure_arg("--no-warn-unused-cli") // 交叉编译时防止cmake 报错
        .build_target("gmssl") // 仅仅编译库
        .build();
    println!("cargo:rerun-if-changed=GmSSL");
    println!(
        "cargo:rustc-link-search=native={}/build/bin",
        path.display()
    );
    println!("cargo:rustc-link-lib=static=gmssl"); // 链接

    // 生成绑定
    let bindings = bindgen::builder()
        .header("wrapper.h")
        .clang_arg("-IGmSSL/include")
        .allowlist_file(r".*?gmssl.*?")
        // .blocklist_type(r".*?FILE.*?")
        // .blocklist_function(r".*?print$")
        // .blocklist_function(r".*?pem$")
        // .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");
    // env::var("OUT_DIR").unwrap()
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=wrapper.h");

    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
}
