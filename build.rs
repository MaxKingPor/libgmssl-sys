use std::env;
use std::path::PathBuf;

fn main() {
    // 编译GmSSL
    let mut config = cmake::Config::new("GmSSL");
    config
        .define("BUILD_SHARED_LIBS", "OFF") // 静态链接
        // .configure_arg("--no-warn-unused-cli") // 交叉编译时防止cmake 报错
        .build_target("gmssl"); // 仅仅编译库

    env::vars()
        .filter_map(|(k, _)| {
            if k.starts_with("CARGO_FEATURE_ENABLE") && k != "CARGO_FEATURE_DEFAULT" {
                Some(k.replace("CARGO_FEATURE_", ""))
            } else {
                None
            }
        })
        .for_each(|arg| {
            println!("CARGO_FEATURE {}", arg);
            config.define(arg, "ON");
        });

    if cfg!(target_env = "msvc") {
        config.cflag("/utf-8"); // msvc 有编码问题统一使用UTF-8
        if cfg!(target_family = "windows") {
            config.cflag("/DWIN32 /D_WINDOWS");
        }
    };
    let path = config.build();
    println!(
        "cargo:rustc-link-search=native={}/build/bin",
        path.display()
    );
    if cfg!(target_env = "msvc") {
        println!(
            "cargo:rustc-link-search=native={}/build/bin/Debug",
            path.display()
        );
        println!(
            "cargo:rustc-link-search=native={}/build/bin/Release",
            path.display()
        );
        println!(
            "cargo:rustc-link-search=native={}/build/bin/MinSizeRel",
            path.display()
        );
        println!(
            "cargo:rustc-link-search=native={}/build/bin/RelWithDebInfo",
            path.display()
        );
    }

    println!("cargo:rerun-if-changed=GmSSL");

    println!("cargo:rustc-link-lib=static=gmssl"); // 链接

    // 生成绑定
    let bindings = bindgen::builder()
        .header("wrapper.h")
        .clang_arg("-IGmSSL/include")
        .allowlist_file(r".*?gmssl.*?")
        // .blocklist_type(r".*?FILE.*?")
        // .blocklist_function(r".*?print$")
        // .blocklist_function(r"^format.*$")
        // .blocklist_function(r".*?pem$")
        // .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=wrapper.h");
}
